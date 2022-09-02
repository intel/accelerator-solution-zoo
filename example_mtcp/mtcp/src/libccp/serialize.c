#include "serialize.h"
#include "ccp.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#else
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

/* (type, len, socket_id) header
 * -----------------------------------
 * | Msg Type | Len (2B) | Uint32    |
 * | (2 B)    | (2 B)    | (32 bits) |
 * -----------------------------------
 * total: 6 Bytes
 */

/* We only read Install Expr messages.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf) {
    memcpy(hdr, buf, sizeof(struct CcpMsgHeader));

    switch (hdr->Type) {
    case INSTALL_EXPR:
        return sizeof(struct CcpMsgHeader);
    case UPDATE_FIELDS:
        return sizeof(struct CcpMsgHeader);
    case CHANGE_PROG:
        return sizeof(struct CcpMsgHeader);
    default:
        return -hdr->Type;
    }
}

/* We only write Create, and Measure messages.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr) {
    switch (hdr->Type) {
    case CREATE:
    case MEASURE:
        break;
    default:
        return -1;
    }

    if (bufsize < ((int)sizeof(struct CcpMsgHeader))) {
        return -2;
    }

    memcpy(buf, hdr, sizeof(struct CcpMsgHeader));
    return sizeof(struct CcpMsgHeader);
}

int write_create_msg(
    char *buf, 
    int bufsize,
    u32 sid, 
    struct CreateMsg cr
) {
    struct CcpMsgHeader hdr;
    int ok;
    u16 msg_len = sizeof(struct CcpMsgHeader) + sizeof(struct CreateMsg);
    
    hdr = (struct CcpMsgHeader){
        .Type = CREATE, 
        .Len = msg_len,
        .SocketId = sid,
    };

    if (bufsize < 0) {
        return -1;
    }
    
    if (((u32) bufsize) < hdr.Len) {
        return -2;
    }
    
    ok = serialize_header(buf, bufsize, &hdr);
    if (ok < 0) {
        return ok;
    }

    buf += ok;
    memcpy(buf, &cr, hdr.Len - sizeof(struct CcpMsgHeader));
    return hdr.Len;
}

int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid, 
    u32 program_uid,
    u64 *msg_fields,
    u8 num_fields
) {
    int ok;
    struct MeasureMsg ms = {
        .program_uid = program_uid,
        .num_fields = num_fields,
    };
    
    // 4 bytes for num_fields (u32) and 4 for program_uid = 8
    u16 msg_len = sizeof(struct CcpMsgHeader) + 8 + ms.num_fields * sizeof(u64);
    struct CcpMsgHeader hdr = {
        .Type = MEASURE, 
        .Len = msg_len,
        .SocketId = sid,
    };
    
    // copy message fields into MeasureMsg struct
    memcpy(ms.fields, msg_fields, ms.num_fields * sizeof(u64));
    
    if (bufsize < 0) {
        return -1;
    }

    if (((u32) bufsize) < hdr.Len) {
        return -2;
    }

    ok = serialize_header(buf, bufsize, &hdr);
    if (ok < 0) {
        return ok;
    }

    buf += ok;
    memcpy(buf, &ms, hdr.Len - sizeof(struct CcpMsgHeader));
    return hdr.Len;
}

int read_install_expr_msg_hdr(
    struct CcpMsgHeader *hdr,
    struct InstallExpressionMsgHdr *expr_msg_info,
    char *buf
) {
    if (hdr->Type != INSTALL_EXPR) {
        return -1;
    } 

    if (expr_msg_info->num_expressions > MAX_EXPRESSIONS) {
        PRINT("Program to install has too many expressions: %u\n", expr_msg_info->num_expressions);
        return -2;
    }

    if (expr_msg_info->num_instructions > MAX_INSTRUCTIONS) {
        PRINT("Program to install has too many instructions: %u\n", expr_msg_info->num_instructions);
        return -2;
    }
    memcpy(expr_msg_info, buf, sizeof(struct InstallExpressionMsgHdr));
    return sizeof(struct InstallExpressionMsgHdr);

}

int check_update_fields_msg(
    struct CcpMsgHeader *hdr,
    u32 *num_updates,
    char *buf
) {
    if (hdr->Type != UPDATE_FIELDS) {
        return -1;
    }

    *num_updates = (u32)*buf;
    if (*num_updates > MAX_MUTABLE_REG) {
        PRINT("Too many updates!: %u\n", *num_updates);
        return -2;
    }
    return sizeof(u32);
}

int read_change_prog_msg(
    struct CcpMsgHeader *hdr,
    struct ChangeProgMsg *change_prog,
    char *buf
) {
    if (hdr->Type != CHANGE_PROG) {
        return -1;
    }

    memcpy(change_prog, buf, sizeof(struct ChangeProgMsg));
    if (change_prog->num_updates > MAX_MUTABLE_REG) {
        PRINT("Too many updates sent with change prog: %u\n", change_prog->num_updates);
        return -2;
    }
    return sizeof(struct ChangeProgMsg);
}
