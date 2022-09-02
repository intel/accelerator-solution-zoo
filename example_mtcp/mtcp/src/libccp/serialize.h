/* 
 * CCP Datapath Message Serialization 
 * 
 * Serializes and deserializes messages for communication with userspace CCP.
 */
#ifndef CCP_SERIALIZE_H
#define CCP_SERIALIZE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifdef __CPLUSPLUS__
extern "C" {
#endif

struct __attribute__((packed, aligned(4))) CcpMsgHeader {
    u16 Type;
    u16 Len;
    u32 SocketId;
};

/* return: sizeof(struct CcpMsgHeader) on success, -1 otherwise.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf);

/* return: sizeof(struct CcpMsgHeader) on success, -1 otherwise.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr);

/* There are 4 message types (Type field in header)
 * CREATE and MEASURE are written from datapath to CCP
 * PATTERN and INSTALL_FOLD are received in datapath from CCP
 * 
 * Messages start with the header, then 
 * 1. fixed number of u32
 * 2. fixed number of u64
 * 3. bytes blob, flexible length
 */
#define  CREATE        0
#define  MEASURE       1
#define  INSTALL_EXPR  2
#define  UPDATE_FIELDS 3
#define  CHANGE_PROG   4

// Some messages contain strings.
#define  BIGGEST_MSG_SIZE  32678

// for create messages, we know they are smaller when we send them up
#define CREATE_MSG_SIZE     512
// size of report msg is approx MAX_REPORT_REG * 8 + 4 + 4
#define REPORT_MSG_SIZE     900

// Some messages contain serialized fold instructions.
#define MAX_EXPRESSIONS    256 // arbitrary TODO: make configurable
#define MAX_INSTRUCTIONS   256 // arbitrary, TODO: make configurable
#define MAX_IMPLICIT_REG   6  // fixed number of implicit registers
#define MAX_REPORT_REG     110 // measure msg 110 * 8 + 4 + 4
#define MAX_CONTROL_REG    110 // arbitrary
#define MAX_TMP_REG        8
#define MAX_LOCAL_REG      8
#define MAX_MUTABLE_REG    222 // # report + # control + cwnd, rate registers

/* CREATE
 * str: the datapath's requested congestion control algorithm (could be overridden)
 * TODO(eventually): convey relevant sockopts to CCP
 */
struct __attribute__((packed, aligned(4))) CreateMsg {
    u32 init_cwnd;
    u32 mss;
    u32 src_ip;
    u32 src_port;
    u32 dst_ip;
    u32 dst_port;
};

/* Write cr: CreateMsg into buf with socketid sid.
 * buf should be preallocated, and bufsize should be its size.
 */
int write_create_msg(
    char *buf,
    int bufsize,
    u32 sid,
    struct CreateMsg cr
);

/* MEASURE
 * program_uid: unique id for the datapath program that generated this report,
 *              so that the ccp can use the corresponding scope
 * num_fields: number of returned fields,
 * bytes: the return registers of the installed fold function ([]uint64).
 *        there will be at most MAX_PERM_REG returned registers
 */
struct __attribute__((packed, aligned(4))) MeasureMsg {
    u32 program_uid;
    u32 num_fields;
    u64 fields[MAX_REPORT_REG];
};

/* Write ms: MeasureMsg into buf with socketid sid.
 * buf should be preallocated, and bufsize should be its size.
 */
int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid,
    u32 program_uid,
    u64 *msg_fields,
    u8 num_fields
);

/* INSTRUCTION
 * 1 u8 for opcode
 * 3 sets of {u8, u32} for each of the result register, left register and right register
 */
struct __attribute__((packed, aligned(4))) InstructionMsg {
    u8 opcode;
    u8 result_reg_type;
    u32 result_register;
    u8 left_reg_type;
    u32 left_register;
    u8 right_reg_type;
    u32 right_register;
};


/* ExpressionMsg: 4 u32s
 * start of expression condition instr ID
 * number of expression condition instrs
 * start of event body instr ID
 * number of event body instrs
 */
struct __attribute__((packed, aligned(4))) ExpressionMsg {
    u32 cond_start_idx;
    u32 num_cond_instrs;
    u32 event_start_idx;
    u32 num_event_instrs;
};

struct __attribute__((packed, aligned(4))) InstallExpressionMsgHdr {
    u32 program_uid;
    u32 num_expressions;
    u32 num_instructions;
};

/* return: size of InstallExpressionMsgHeader
 * copies from buffer into InstallExpressionMsgHdr struct.
 * also checks whether the number of instructions or expressions is too large.
 * InstallExprMessage:
 * {
 *  struct InstallExpressionMsgHeader (3 u32s)
 *  ExpressionMsg[num_expressions]
 *  InstructionMsg[num_instructions]
 * }
 */
int read_install_expr_msg_hdr(
    struct CcpMsgHeader *hdr,
    struct InstallExpressionMsgHdr *expr_msg_info,
    char *buf
);

struct __attribute__((packed, aligned(1))) UpdateField {
    u8 reg_type;
    u32 reg_index;
    u64 new_value;
};

/* Fills in number of updates.
 * Check whether number of updates is too large.
 * Returns size of update field header: 1 u32
 * UpdateFieldsMsg:
 * {
 *  1 u32: num_updates
 *  UpdateField[num_updates]
 * }
 */
int check_update_fields_msg(
    struct CcpMsgHeader *hdr,
    u32 *num_updates,
    char *buf
);

struct __attribute__((packed, aligned(1))) ChangeProgMsg {
    u32 program_uid;
    u32 num_updates;
};

int read_change_prog_msg(
    struct CcpMsgHeader *hdr,
    struct ChangeProgMsg *change_prog,
    char *buf
);

#ifdef __CPLUSPLUS__
} // extern "C"
#endif

#endif
