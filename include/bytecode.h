#ifndef BYTECODE_H
#define BYTECODE_H 1

#include <stddef.h>
#include <stdint.h>

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} Bytecode;

enum {
    BC_PUSH_NUM = 1,
    BC_PUSH_CHAR,
    BC_PUSH_STRING,
    BC_PUSH_BYTE,
    BC_BUILD_NUMBER,
    BC_BUILD_BYTE,
    BC_BUILD_OBJECT,
    BC_BUILD_FUNCTION,
    BC_INDEX,
    BC_STORE_INDEX,
    BC_LOAD_ROOT,
    BC_LOAD_GLOBAL,
    BC_LOAD_THIS,
    BC_STORE_GLOBAL,
    BC_SET_THIS,
    BC_CALL,
    BC_JMP,
    BC_JMP_IF_FALSE,
    BC_RETURN,
    BC_POP,
    BC_DUP,
    BC_GC,
    BC_DUMP,
    BC_BUILD_NUMBER_LIT,
    BC_ADD,
    BC_SUB,
    BC_MUL,
    BC_DIV,
    BC_MOD,
    BC_NEG,
    BC_NOT,
    BC_EQ,
    BC_NEQ,
    BC_LT,
    BC_LTE,
    BC_GT,
    BC_GTE,
    BC_AND,
    BC_OR
};

void bc_init(Bytecode *bc);
void bc_free(Bytecode *bc);
int bc_emit_u8(Bytecode *bc, uint8_t v);
int bc_emit_u32(Bytecode *bc, uint32_t v);
int bc_emit_f64(Bytecode *bc, double v);
int bc_emit_bytes(Bytecode *bc, const unsigned char *bytes, size_t len);
int bc_emit_string(Bytecode *bc, const char *s, size_t len);

const char *bc_opcode_name(uint8_t op);

#endif
