#include "bytecode.h"

#include <stdlib.h>
#include <string.h>

static int bc_grow(Bytecode *bc, size_t add)
{
    if (bc->len + add <= bc->cap) return 1;
    size_t new_cap = bc->cap == 0 ? 64 : bc->cap;
    while (new_cap < bc->len + add) {
        new_cap *= 2;
    }
    unsigned char *next = (unsigned char*)realloc(bc->data, new_cap);
    if (!next) return 0;
    bc->data = next;
    bc->cap = new_cap;
    return 1;
}

void bc_init(Bytecode *bc)
{
    bc->data = NULL;
    bc->len = 0;
    bc->cap = 0;
}

void bc_free(Bytecode *bc)
{
    free(bc->data);
    bc->data = NULL;
    bc->len = 0;
    bc->cap = 0;
}

int bc_emit_u8(Bytecode *bc, uint8_t v)
{
    if (!bc_grow(bc, 1)) return 0;
    bc->data[bc->len++] = (unsigned char)v;
    return 1;
}

int bc_emit_u32(Bytecode *bc, uint32_t v)
{
    if (!bc_grow(bc, 4)) return 0;
    bc->data[bc->len++] = (unsigned char)(v & 0xFF);
    bc->data[bc->len++] = (unsigned char)((v >> 8) & 0xFF);
    bc->data[bc->len++] = (unsigned char)((v >> 16) & 0xFF);
    bc->data[bc->len++] = (unsigned char)((v >> 24) & 0xFF);
    return 1;
}

int bc_emit_i64(Bytecode *bc, int64_t v)
{
    if (!bc_grow(bc, 8)) return 0;
    uint64_t u = (uint64_t)v;
    for (int i = 0; i < 8; i++) {
        bc->data[bc->len++] = (unsigned char)((u >> (i * 8)) & 0xFF);
    }
    return 1;
}

int bc_emit_f64(Bytecode *bc, double v)
{
    if (!bc_grow(bc, 8)) return 0;
    union {
        double d;
        unsigned char b[8];
    } u;
    u.d = v;
    for (int i = 0; i < 8; i++) {
        bc->data[bc->len++] = u.b[i];
    }
    return 1;
}

int bc_emit_bytes(Bytecode *bc, const unsigned char *bytes, size_t len)
{
    if (!bc_grow(bc, len)) return 0;
    if (len) {
        memcpy(bc->data + bc->len, bytes, len);
        bc->len += len;
    }
    return 1;
}

int bc_emit_string(Bytecode *bc, const char *s, size_t len)
{
    if (len > 0xFFFFFFFFu) return 0;
    if (!bc_emit_u32(bc, (uint32_t)len)) return 0;
    return bc_emit_bytes(bc, (const unsigned char*)s, len);
}

const char *bc_opcode_name(uint8_t op)
{
    switch (op) {
    case BC_PUSH_INT: return "PUSH_INT";
    case BC_PUSH_FLOAT: return "PUSH_FLOAT";
    case BC_PUSH_CHAR: return "PUSH_CHAR";
    case BC_PUSH_STRING: return "PUSH_STRING";
    case BC_BUILD_INT: return "BUILD_INT";
    case BC_BUILD_FLOAT: return "BUILD_FLOAT";
    case BC_BUILD_OBJECT: return "BUILD_OBJECT";
    case BC_BUILD_FUNCTION: return "BUILD_FUNCTION";
    case BC_INDEX: return "INDEX";
    case BC_STORE_INDEX: return "STORE_INDEX";
    case BC_LOAD_ROOT: return "LOAD_ROOT";
    case BC_LOAD_GLOBAL: return "LOAD_GLOBAL";
    case BC_LOAD_THIS: return "LOAD_THIS";
    case BC_STORE_GLOBAL: return "STORE_GLOBAL";
    case BC_SET_THIS: return "SET_THIS";
    case BC_CALL: return "CALL";
    case BC_CALL_EX: return "CALL_EX";
    case BC_STRICT: return "STRICT";
    case BC_JMP: return "JMP";
    case BC_JMP_IF_FALSE: return "JMP_IF_FALSE";
    case BC_RETURN: return "RETURN";
    case BC_POP: return "POP";
    case BC_DUP: return "DUP";
    case BC_GC: return "GC";
    case BC_DUMP: return "DUMP";
    case BC_BUILD_INT_LIT: return "BUILD_INT_LIT";
    case BC_BUILD_FLOAT_LIT: return "BUILD_FLOAT_LIT";
    case BC_ADD: return "ADD";
    case BC_SUB: return "SUB";
    case BC_MUL: return "MUL";
    case BC_DIV: return "DIV";
    case BC_MOD: return "MOD";
    case BC_NEG: return "NEG";
    case BC_NOT: return "NOT";
    case BC_EQ: return "EQ";
    case BC_NEQ: return "NEQ";
    case BC_LT: return "LT";
    case BC_LTE: return "LTE";
    case BC_GT: return "GT";
    case BC_GTE: return "GTE";
    case BC_AND: return "AND";
    case BC_OR: return "OR";
    default: return "UNKNOWN";
    }
}
