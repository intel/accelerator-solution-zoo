#ifndef CCP_PRIV_H
#define CCP_PRIV_H

#include "ccp.h"
#include "serialize.h"

/*
 * CCP Send State Machine
 * 
 * Userspace CCP algorithms specify "expressions", e.g.:
 * (def (Report.loss 0) (Control.bottle_rate 1000))
 * (when (> Micros 0)
 *      (bind Rate (* Control.bottle_rate 3))
 *      (fallthrough)
 *  )
 * (when (> Micros 2000)
 *       (report)
 *       (bind Rate (* Control.bottle_rate 2))
 *       (fallthrough)
 *  )
 * (when (> Micros 8000)
 *       (report)
 *       (reset)
 *       (fallthrough)
 * )
 * (when true
 *       (bind Report.loss (+ Flow.loss Pkt.lost_pkts_sample))
 *       (bind Rate (max Rate (min Pkt.rate_outgoing Pkt.rate_incoming)))
 * )
 * Expressions are conditions (a series of instructions that evaluate to a boolean expression)
 * followed by a set of instructions to execute if that event is true
 */
#ifdef __CPLUSPLUS__
extern "C" {
#endif

/* Triggers the state machine that goes through the expressions and evaluates conditions if true.
 * Should be called on each tick of the ACK clock; i.e. every packet.
 */
int state_machine(
    struct ccp_connection *conn
);

struct Register {
    u8 type;
    int index;
    u64 value;
};

struct Instruction64 {
    u8 op;
    struct Register rRet;
    struct Register rLeft;
    struct Register rRight;
};

/*  Expression contains reference to:
 *  instructions for condition
 *  instructions for body of expression
 */
struct Expression {
    u32 cond_start_idx;
    u32 num_cond_instrs;
    u32 event_start_idx;
    u32 num_event_instrs;
};

/*  Entire datapath program
 *  a set of expressions (conditions)
 *  a set of instructions
 */
struct DatapathProgram {
    u8 num_to_return;
    u16 index; // index in array
    u32 program_uid; // program uid assigned by CCP agent
    u32 num_expressions;
    u32 num_instructions;
    struct Expression expressions[MAX_EXPRESSIONS];
    struct Instruction64 fold_instructions[MAX_INSTRUCTIONS];
};

int read_expression(
    struct Expression *ret,
    struct ExpressionMsg *msg
);

int read_instruction(
    struct Instruction64 *ret,
    struct InstructionMsg *msg
);

void print_register(struct Register* reg);

struct register_file {
    // report and control registers - users send a DEF for these
    u64 report_registers[MAX_REPORT_REG]; // reported variables, reset to DEF value upon report
    u64 control_registers[MAX_CONTROL_REG]; // extra user defined variables, not reset on report

    // tmp, local and implicit registers
    u64 impl_registers[MAX_IMPLICIT_REG]; // stores special flags and variables
    u64 tmp_registers[MAX_TMP_REG]; // used for temporary calculation in instructions
    u64 local_registers[MAX_LOCAL_REG]; // for local variables within a program - created in a bind in a when clause
};

struct staged_update {
    bool control_is_pending[MAX_CONTROL_REG];
    u64 control_registers[MAX_CONTROL_REG];
    bool impl_is_pending[MAX_IMPLICIT_REG];
    u64 impl_registers[MAX_IMPLICIT_REG];
};

/* libccp Private State
 * struct ccp_connection has a void* state to store libccp's state
 * libccp internally casts this to a struct ccp_priv_state*.
 */
struct ccp_priv_state {
    bool sent_create;
    u64 implicit_time_zero; // can be reset

    u16 program_index; // index into program array
    int staged_program_index;

    struct register_file registers;
    struct staged_update pending_update;
};

/*
 * Resets a specific register's value in response to an update field message.
 * Needs pointer to ccp_connection in case message is for updating the cwnd or rate.
 */
int update_register(
    struct ccp_connection* conn,
    struct ccp_priv_state *state,
    struct UpdateField *update_field
);

/* Reset the output state registers to their default values
 * according to the DEF instruction preamble.
 */
void reset_state(struct ccp_priv_state *state);

/* Initializes the control registers to their default values
 * according to the DEF instruction preamble.
 */
void init_register_state(struct ccp_priv_state *state);

/* Reset the implicit time registers to count from datapath->now()
 */
void reset_time(struct ccp_priv_state *state);

/* Initialize send machine and measurement machine state in ccp_connection.
 * Called from ccp_connection_start()
 */
int init_ccp_priv_state(struct ccp_connection *conn);
/* Free the allocated flow memory.
 * Call when the flow has ended.
 */
void free_ccp_priv_state(struct ccp_connection *conn);

/* Retrieve the private state from ccp_connection.
 */
__INLINE__ struct ccp_priv_state *get_ccp_priv_state(struct ccp_connection *conn);

/*
 * Reserved Implicit Registers
 */
#define EXPR_FLAG_REG             0
#define SHOULD_FALLTHROUGH_REG    1
#define SHOULD_REPORT_REG         2
#define US_ELAPSED_REG            3
#define CWND_REG                  4
#define RATE_REG                  5

/*
 * Primitive registers
 */
#define  ACK_BYTES_ACKED          0
#define  ACK_BYTES_MISORDERED     1
#define  ACK_ECN_BYTES            2
#define  ACK_ECN_PACKETS          3
#define  ACK_LOST_PKTS_SAMPLE     4
#define  ACK_NOW                  5
#define  ACK_PACKETS_ACKED        6
#define  ACK_PACKETS_MISORDERED   7
#define  FLOW_BYTES_IN_FLIGHT     8
#define  FLOW_BYTES_PENDING       9
#define  FLOW_PACKETS_IN_FLIGHT   10
#define  FLOW_RATE_INCOMING       11
#define  FLOW_RATE_OUTGOING       12
#define  FLOW_RTT_SAMPLE_US       13
#define  FLOW_WAS_TIMEOUT         14

/*
 * Operations
 */
#define    ADD        0
#define    BIND       1
#define    DEF        2
#define    DIV        3
#define    EQUIV      4
#define    EWMA       5
#define    GT         6
#define    IF         7
#define    LT         8
#define    MAX        9
#define    MAXWRAP    10
#define    MIN        11
#define    MUL        12
#define    NOTIF      13
#define    SUB        14
#define    MAX_OP     15

// types of registers
#define CONTROL_REG            0
#define IMMEDIATE_REG          1
#define IMPLICIT_REG           2
#define LOCAL_REG              3
#define PRIMITIVE_REG          4
#define VOLATILE_REPORT_REG    5
#define NONVOLATILE_REPORT_REG 6
#define TMP_REG                7

#ifdef __CPLUSPLUS__
} // extern "C"
#endif

#endif
