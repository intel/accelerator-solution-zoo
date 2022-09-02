#include "ccp.h"
#include "serialize.h"
#include "ccp_priv.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#define MAX_NUM_CONNECTIONS 4096
#define CREATE_TIMEOUT_US 100000 // 100 ms
#define MAX_NUM_PROGRAMS 10

int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
);

// array of active connections
struct ccp_connection* ccp_active_connections;
// datapath implementation
struct ccp_datapath* datapath;
// datapath programs available to all flows
struct DatapathProgram* datapath_programs;

int ccp_init(struct ccp_datapath *dp) {
    // check that dp is properly filled in.
    if (
        dp                ==  NULL  ||
        dp->set_cwnd      ==  NULL  ||
        dp->set_rate_abs  ==  NULL  ||
        dp->set_rate_rel  ==  NULL  ||
        dp->send_msg      ==  NULL  ||
        dp->now           ==  NULL  ||
        dp->since_usecs   ==  NULL  ||
        dp->after_usecs   ==  NULL
    ) {
        return -1;
    }

    datapath = (struct ccp_datapath*)__MALLOC__(sizeof(struct ccp_datapath));
    if (!datapath) {
        return -1;
    }

    // copy function pointers into datapath
    datapath->set_cwnd           = dp->set_cwnd;
    datapath->set_rate_abs       = dp->set_rate_abs;
    datapath->set_rate_rel       = dp->set_rate_rel;
    datapath->send_msg           = dp->send_msg;
    datapath->now                = dp->now;
    datapath->since_usecs        = dp->since_usecs;
    datapath->after_usecs        = dp->after_usecs;
    datapath->impl               = dp->impl;

    datapath->time_zero = datapath->now();

    ccp_active_connections = (struct ccp_connection*)__MALLOC__(MAX_NUM_CONNECTIONS * sizeof(struct ccp_connection));
    if (!ccp_active_connections) {
        __FREE__(datapath);
        return -1;
    }

    memset(ccp_active_connections, 0, MAX_NUM_CONNECTIONS * sizeof(struct ccp_connection));

    datapath_programs = (struct DatapathProgram*)__MALLOC__(MAX_NUM_PROGRAMS * sizeof(struct DatapathProgram));
    if (!datapath_programs) {
        __FREE__(datapath);
        __FREE__(ccp_active_connections);
        return -1;
    }

    memset(datapath_programs, 0, MAX_NUM_PROGRAMS * sizeof(struct DatapathProgram));

    return 0;
}

void ccp_free(void) {
    __FREE__(ccp_active_connections);
    __FREE__(datapath);
    __FREE__(datapath_programs);
    ccp_active_connections = NULL;
    datapath = NULL;
    datapath_programs = NULL;
}

void ccp_conn_create_success(struct ccp_priv_state *state) {
    state->sent_create = true;
}

struct ccp_connection *ccp_connection_start(void *impl, struct ccp_datapath_info *flow_info) {
    int ok;
    u16 sid;
    struct ccp_connection *conn;

    // scan to find empty place
    // index = 0 means free/unused
    for (sid = 0; sid < MAX_NUM_CONNECTIONS; sid++) {
        conn = &ccp_active_connections[sid];
        if (conn->index == 0) {
            // found a free slot
            conn->index = sid + 1;
            sid = sid + 1;
            break;
        }
    }
    
    if (sid >= MAX_NUM_CONNECTIONS) {
        return NULL;
    }

    conn->impl = impl;
    memcpy(&conn->flow_info, flow_info, sizeof(struct ccp_datapath_info));

    init_ccp_priv_state(conn);

    // send to CCP:
    // index of pointer back to this sock for IPC callback
    ok = send_conn_create(datapath, conn);
    if (ok < 0) {
        PRINT("failed to send create message: %d\n", ok);
        return conn;
    }
    
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    ccp_conn_create_success(state);

    return conn;
}

__INLINE__ void *ccp_get_global_impl(void) {
    return datapath->impl;
}

__INLINE__ int ccp_set_global_impl(void *ptr) {
    datapath->impl = ptr;
    return 0;
}

__INLINE__ void *ccp_get_impl(struct ccp_connection *conn) {
    return conn->impl;
}

__INLINE__ int ccp_set_impl(struct ccp_connection *conn, void *ptr) {
    conn->impl = ptr;
    return 0;
}

int ccp_invoke(struct ccp_connection *conn) {
    int i;
    int ok = 0;
    struct ccp_priv_state *state;

		if (conn == NULL) {
			return -1;
		}

		state = get_ccp_priv_state(conn);
    if (!(state->sent_create)) {
        // try contacting the CCP again
        // index of pointer back to this sock for IPC callback
        DBG_PRINT("%s retx create message\n", __FUNCTION__);
        ok = send_conn_create(datapath, conn);
        if (ok < 0) {
            PRINT("failed to retx create message: %d\n", ok);
        } else {
            ccp_conn_create_success(state);
        }

        return 0;
    }

    // set cwnd and rate registers to what they are in the datapath
    DBG_PRINT("primitives (cwnd, rate): (%u, %u)\n", conn->prims.snd_cwnd, conn->prims.snd_rate);
    state->registers.impl_registers[CWND_REG] = (u64)conn->prims.snd_cwnd;
    state->registers.impl_registers[RATE_REG] = (u64)conn->prims.snd_rate;
    
    if (state->staged_program_index >= 0) {
        // change the program to this program, and reset the state
        DBG_PRINT("[sid=%d] Applying staged program change: %d -> %d\n", conn->index, state->program_index, state->staged_program_index); 
        state->program_index = state->staged_program_index;
        reset_state(state);
        init_register_state(state);
        reset_time(state);
        state->staged_program_index = -1;
    }

    for (i = 0; i < MAX_CONTROL_REG; i++) {
        if (state->pending_update.control_is_pending[i]) {
            DBG_PRINT("[sid=%d] Applying staged field update: control reg %u (%d->%d) \n", conn->index, i,
                state->registers.control_registers[i],
                state->pending_update.control_registers[i]
            );
            state->registers.control_registers[i] = state->pending_update.control_registers[i];
        }
    }

    if (state->pending_update.impl_is_pending[CWND_REG]) {
        DBG_PRINT("[sid=%d] Applying staged field update: cwnd reg <- %llu\n", conn->index, state->pending_update.impl_registers[CWND_REG]);
        state->registers.impl_registers[CWND_REG] = state->pending_update.impl_registers[CWND_REG];
        if (state->registers.impl_registers[CWND_REG] != 0) {
            datapath->set_cwnd(datapath, conn, state->registers.impl_registers[CWND_REG]);
        }
    }

    if (state->pending_update.impl_is_pending[RATE_REG]) {
        DBG_PRINT("[sid=%d] Applying staged field update: rate reg <- %llu\n", conn->index, state->pending_update.impl_registers[RATE_REG]);
        state->registers.impl_registers[RATE_REG] = state->pending_update.impl_registers[RATE_REG];
        if (state->registers.impl_registers[RATE_REG] != 0) {
            datapath->set_rate_abs(datapath, conn, state->registers.impl_registers[RATE_REG]);
        }
    }

    memset(&state->pending_update, 0, sizeof(struct staged_update));
    
    ok = state_machine(conn);
    if (!ok) {
        return ok;
    }

    return ok;
}

// lookup existing connection by its ccp socket id
// return NULL on error
struct ccp_connection *ccp_connection_lookup(u16 sid) {
    struct ccp_connection *conn;
    // bounds check
    if (sid == 0 || sid > MAX_NUM_CONNECTIONS) {
        PRINT("index out of bounds: %d", sid);
        return NULL;
    }

    conn = &ccp_active_connections[sid-1];
    if (conn->index != sid) {
        PRINT("index mismatch: sid %d, index %d", sid, conn->index);
        return NULL;
    }

    return conn;
}

// after connection ends, free its slot in the ccp table
// also free slot in ccp instruction table
void ccp_connection_free(u16 sid) {
    int msg_size, ok;
    struct ccp_connection *conn;
    char msg[REPORT_MSG_SIZE];

    DBG_PRINT("Entering %s\n", __FUNCTION__);
    // bounds check
    if (sid == 0 || sid > MAX_NUM_CONNECTIONS) {
        PRINT("index out of bounds: %d", sid);
        return;
    }

    conn = &ccp_active_connections[sid-1];
    if (conn->index != sid) {
        PRINT("index mismatch: sid %d, index %d", sid, conn->index);
        return;
    }

    free_ccp_priv_state(conn);

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, sid, 0, 0, 0);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    if (ok < 0) {
        PRINT("error sending close message: %d", ok);
    }
    
    // ccp_connection_start will look for an array entry with index 0
    // to indicate that it's available for a new flow's information.
    // So, we set index to 0 here to reuse the memory.
    conn->index = 0;
    return;
}

// lookup datapath program using program ID
// returns  NULL on error
struct DatapathProgram* datapath_program_lookup(u16 pid) {
    struct DatapathProgram *prog;
    // bounds check
    if (pid == 0) {
        DBG_PRINT("no datapath program set\n");
        return NULL;
    } else if (pid > MAX_NUM_PROGRAMS) {
        PRINT("program index out of bounds: %d\n", pid);
        return NULL;
    }

    prog = &datapath_programs[pid-1];
    if (prog->index != pid) {
        PRINT("index mismatch: pid %d, index %d", pid, prog->index);
        return NULL;
    }

    return prog;

}

// scan through datapath program table for the program with this UID
int datapath_program_lookup_uid(u32 program_uid) {
    struct DatapathProgram *prog;
    int i;
    for (i=0; i < MAX_NUM_PROGRAMS; i++) {
        prog = &datapath_programs[i];
        if (prog->index == 0) {
            continue;
        }
        if (prog->program_uid == program_uid) {
            return (int)(prog->index);
        }
    }
    return -1;
}

// saves a new datapath program into the array of datapath programs
// returns index into datapath program array where this program is stored
// if there is no more space, returns -1
int datapath_program_install(struct InstallExpressionMsgHdr* install_expr_msg, char* buf) {
    u16 pid;
    int ok;
    int i;
    struct DatapathProgram* program;
    struct InstructionMsg* current_instr;
    char* msg_ptr; // for reading from char* buf
    msg_ptr = buf;
    for (pid = 0; pid < MAX_NUM_PROGRAMS; pid++) {
        program = &datapath_programs[pid];
        if (program->index == 0) {
            // found a free slot
            program->index = pid + 1;
            pid = pid + 1;
            break;
        }
    }
    if (pid >= MAX_NUM_PROGRAMS) {
        return -1;
    }

    // copy into the program
    program->index = pid;
    program->program_uid = install_expr_msg->program_uid;
    program->num_expressions = install_expr_msg->num_expressions;
    program->num_instructions = install_expr_msg->num_instructions;
    DBG_PRINT("Trying to install new program with (uid=%d) with %d expressions and %d instructions\n", program->program_uid, program->num_expressions, program->num_instructions);

    memcpy(program->expressions, msg_ptr, program->num_expressions * sizeof(struct ExpressionMsg));
    msg_ptr += program->num_expressions * sizeof(struct ExpressionMsg);

    // parse individual instructions
    for (i=0; i < (int)(program->num_instructions); i++) {
        current_instr = (struct InstructionMsg*)(msg_ptr);
        ok = read_instruction(&(program->fold_instructions[i]), current_instr);
        if (ok < 0) {
            PRINT("Could not read instruction # %d: %d in program with uid %u\n", i, ok, program->program_uid);
            return ok;
        }
        msg_ptr += sizeof(struct InstructionMsg);
    }

    DBG_PRINT("installed new program (uid=%d) with %d expressions and %d instructions\n", program->program_uid, program->num_expressions, program->num_instructions);

    return 0;

}

// frees datapath program
void datapath_program_free(u16 pid) {
    struct DatapathProgram *program;

    DBG_PRINT("Entering %s\n", __FUNCTION__);
    // bounds check
    if (pid == 0 || pid > MAX_NUM_PROGRAMS) {
        PRINT("index out of bounds: %d", pid);
        return;
    }

    program = &datapath_programs[pid-1];
    if (program->index != pid) {
        PRINT("index mismatch: pid %d, index %d", pid, program->index);
        return;
    }

    memset(program, 0, sizeof(struct DatapathProgram));
    program->index = 0;
    return;
}

int stage_update(struct staged_update *pending_update, struct UpdateField *update_field) {
    // update the value for these registers
    // for cwnd, rate; update field in datapath
    switch(update_field->reg_type) {
        case CONTROL_REG:
            // set new value
            DBG_PRINT("%s: control %u <- %llu\n", __FUNCTION__, update_field->reg_index, update_field->new_value);
            pending_update->control_registers[update_field->reg_index] = update_field->new_value;
            pending_update->control_is_pending[update_field->reg_index] = true;
            return 0;
        case IMPLICIT_REG:
            if (update_field->reg_index == CWND_REG) {
                DBG_PRINT("%s: cwnd <- %llu\n", __FUNCTION__, update_field->new_value);
                pending_update->impl_registers[CWND_REG] = update_field->new_value;
                pending_update->impl_is_pending[CWND_REG] = true;
            } else if (update_field->reg_index == RATE_REG) {
                DBG_PRINT("%s: rate <- %llu\n", __FUNCTION__, update_field->new_value);
                pending_update->impl_registers[RATE_REG] = update_field->new_value;
                pending_update->impl_is_pending[RATE_REG] = true;
            }
            return 0;
        default:
            return -1; // allowed only for CONTROL and CWND and RATE reg within CONTROL_REG
    }
}

int stage_multiple_updates(struct staged_update *pending_update, size_t num_updates, struct UpdateField *msg_ptr) {
    int ok;
    for (size_t i = 0; i < num_updates; i++) {
        ok = stage_update(pending_update, msg_ptr);
        if (ok < 0) {
            return ok;
        }

        msg_ptr++;
    }

    return 0;
}

int ccp_read_msg(
    char *buf,
    int bufsize
) {
    int ok;
    u32 num_updates;
    struct ccp_connection *conn;
    struct ccp_priv_state *state;
    struct CcpMsgHeader hdr;
    struct InstallExpressionMsgHdr expr_msg_info;
    int msg_program_index;
    struct ChangeProgMsg change_program;
    char* msg_ptr;

    ok = read_header(&hdr, buf);  
    if (ok < 0) {
        PRINT("read header failed: %d", ok);
        return -1;
    }

    if (bufsize < 0) {
        PRINT("negative bufsize: %d", bufsize);
        return -2;
    }
    if (hdr.Len > ((u32) bufsize)) {
        PRINT("message size wrong: %u > %d\n", hdr.Len, bufsize);
        return -3;
    }

    if (hdr.Len > BIGGEST_MSG_SIZE) {
        PRINT("message too long: %u > %d\n", hdr.Len, BIGGEST_MSG_SIZE);
        return -4;
    }
    msg_ptr = buf + ok;

    // INSTALL_EXPR message is for all flows, not a specific connection
    // sock_id in this message should be disregarded (could be before any flows begin)
    if (hdr.Type == INSTALL_EXPR) {
        DBG_PRINT("Received install message\n");
        memset(&expr_msg_info, 0, sizeof(struct InstallExpressionMsgHdr));
        ok = read_install_expr_msg_hdr(&hdr, &expr_msg_info, msg_ptr);
        if (ok < 0) {
            PRINT("could not read install expression msg header: %d\n", ok);
            return -5;
        }
        // clear the datapath programs
        // TODO: implement a system for which each ccp process has an ID corresponding to its programs
        // as all programs are sent down separately, right now we check if its a new portus starting
        // by checking if the ID of the program is 0
        // TODO: remove this hack
        if (expr_msg_info.program_uid == 0) {
            memset(datapath_programs, 0, MAX_NUM_PROGRAMS * sizeof(struct DatapathProgram));
        }

        msg_ptr += ok;
        ok = datapath_program_install(&expr_msg_info, msg_ptr);
        if ( ok < 0 ) {
            PRINT("could not install datapath program: %d\n", ok);
            return -6;
        }
        return 0; // installed program successfully
    }

    // rest of the messages must be for a specific flow
    conn = ccp_connection_lookup(hdr.SocketId);
    state = get_ccp_priv_state(conn);
    if (conn == NULL) {
        PRINT("unknown connection: %u\n", hdr.SocketId);
        return -7;
    }

    if (hdr.Type == UPDATE_FIELDS) {
        DBG_PRINT("[sid=%d] Received update_fields message\n", conn->index);
        ok = check_update_fields_msg(&hdr, &num_updates, msg_ptr);
        msg_ptr += ok;
        if (ok < 0) {
            PRINT("Update fields message failed: %d\n", ok);
            return -8;
        }

        ok = stage_multiple_updates(&state->pending_update, num_updates, (struct UpdateField*) msg_ptr);
        if (ok < 0) {
            PRINT("Failed to stage updates: %d\n", ok);
            return -11;
        }

        DBG_PRINT("Staged %u updates\n", num_updates);
    } else if (hdr.Type == CHANGE_PROG) {
        DBG_PRINT("[sid=%d] Received change_prog message\n", conn->index);
        // check if the program is in the program_table
        ok = read_change_prog_msg(&hdr, &change_program, msg_ptr);
        if (ok < 0) {
            PRINT("Change program message deserialization failed: %d\n", ok);
            return -9;
        }
        msg_ptr += ok;

        msg_program_index = datapath_program_lookup_uid(change_program.program_uid);
        if (msg_program_index < 0) {
            // TODO: is it possible there is not enough time between when the message is installed and when a flow asks to use the program?
            PRINT("Could not find datapath program with program uid: %u\n", msg_program_index);
            return -10;
        }

        state->staged_program_index = (u16)msg_program_index; // index into program array for further lookup of instructions

        // clear any staged but not applied updates, as they are now irrelevant
        memset(&state->pending_update, 0, sizeof(struct staged_update));
        // stage any possible update fields to the initialized registers
        // corresponding to the new program
        ok = stage_multiple_updates(&state->pending_update, change_program.num_updates, (struct UpdateField*)(msg_ptr));
        if (ok < 0) {
            PRINT("Failed to stage updates: %d\n", ok);
            return -8;
        }

        DBG_PRINT("Staged switch to program %d\n", change_program.program_uid);
    }

    return ok;
}

// send create msg
int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
) {
    int ok;
    char msg[REPORT_MSG_SIZE];
    int msg_size;
    struct CreateMsg cr = {
        .init_cwnd = conn->flow_info.init_cwnd,
        .mss = conn->flow_info.mss,
        .src_ip = conn->flow_info.src_ip,
        .src_port = conn->flow_info.src_port,
        .dst_ip = conn->flow_info.dst_ip,
        .dst_port = conn->flow_info.dst_port,
    };

    if (
        conn->last_create_msg_sent != 0 &&
        datapath->since_usecs(conn->last_create_msg_sent) < CREATE_TIMEOUT_US
    ) {
        DBG_PRINT("%s: %llu < %u\n", 
            __FUNCTION__, 
            datapath->since_usecs(conn->last_create_msg_sent), 
            CREATE_TIMEOUT_US
        );
        return -1;
    }

    if (conn->index < 1) {
        return -2;
    }

    conn->last_create_msg_sent = datapath->now();
    msg_size = write_create_msg(msg, REPORT_MSG_SIZE, conn->index, cr);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    return ok;
}

// send datapath measurements
// acks, rtt, rin, rout
int send_measurement(
    struct ccp_connection *conn,
    u32 program_uid,
    u64 *fields,
    u8 num_fields
) {
    int ok;
    char msg[REPORT_MSG_SIZE];
    int msg_size;
    if (conn->index < 1) {
        ok = -1;
        return ok;
    }

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, conn->index, program_uid, fields, num_fields);
    DBG_PRINT("[sid=%d] In %s\n", conn->index, __FUNCTION__);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    return ok;
}
