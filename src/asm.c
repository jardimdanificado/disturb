#include "asm.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static void err_set(char *buf, size_t cap, const char *msg)
{
    if (!buf || cap == 0) return;
    snprintf(buf, cap, "%s", msg);
}

static const char *skip_ws(const char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

static int parse_ident(const char **p, char *out, size_t cap)
{
    const char *s = *p;
    if (!isalpha((unsigned char)*s) && *s != '_') return 0;
    size_t len = 0;
    while (*s && (isalnum((unsigned char)*s) || *s == '_')) {
        if (len + 1 < cap) out[len] = *s;
        len++;
        s++;
    }
    if (cap > 0) {
        out[len < cap ? len : cap - 1] = 0;
    }
    *p = s;
    return 1;
}

static int parse_string_lit(const char **p, unsigned char **out, size_t *len_out, char *err, size_t err_cap)
{
    const char *s = *p;
    if (*s != '"' && *s != '\'') return 0;
    char quote = *s++;
    size_t cap = 16;
    size_t len = 0;
    unsigned char *buf = (unsigned char*)malloc(cap);
    if (!buf) {
        err_set(err, err_cap, "out of memory");
        return 0;
    }

    while (*s && *s != quote) {
        unsigned char c = (unsigned char)*s++;
        if (c == '\\') {
            if (!*s) {
                free(buf);
                err_set(err, err_cap, "unterminated escape");
                return 0;
            }
            char esc = *s++;
            switch (esc) {
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case '\\': c = '\\'; break;
            case '"': c = '"'; break;
            case '\'': c = '\''; break;
            default:
                free(buf);
                err_set(err, err_cap, "unknown escape");
                return 0;
            }
        }
        if (len + 1 > cap) {
            cap *= 2;
            unsigned char *next = (unsigned char*)realloc(buf, cap);
            if (!next) {
                free(buf);
                err_set(err, err_cap, "out of memory");
                return 0;
            }
            buf = next;
        }
        buf[len++] = c;
    }
    if (*s != quote) {
        free(buf);
        err_set(err, err_cap, "unterminated string");
        return 0;
    }
    s++;
    *p = s;
    *out = buf;
    *len_out = len;
    return 1;
}

static int parse_u32(const char **p, uint32_t *out)
{
    char *end = NULL;
    unsigned long v = strtoul(*p, &end, 10);
    if (!end || end == *p) return 0;
    if (v > 0xFFFFFFFFu) return 0;
    *out = (uint32_t)v;
    *p = end;
    return 1;
}

static int parse_double(const char **p, double *out)
{
    char *end = NULL;
    double v = strtod(*p, &end);
    if (!end || end == *p) return 0;
    *out = v;
    *p = end;
    return 1;
}

int urb_assemble(const char *source, Bytecode *out, char *err_buf, size_t err_cap)
{
    bc_init(out);
    const char *s = source;
    char ident[128];

    while (*s) {
        s = skip_ws(s);
        if (!*s) break;

        if (!parse_ident(&s, ident, sizeof(ident))) {
            err_set(err_buf, err_cap, "expected opcode");
            bc_free(out);
            return 0;
        }
        s = skip_ws(s);

        if (strcmp(ident, "PUSH_NUM") == 0) {
            double v = 0.0;
            if (!parse_double(&s, &v)) {
                err_set(err_buf, err_cap, "PUSH_NUM expects a number");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_PUSH_NUM) || !bc_emit_f64(out, v)) {
                err_set(err_buf, err_cap, "failed to emit PUSH_NUM");
                bc_free(out);
                return 0;
            }
        } else if (strcmp(ident, "PUSH_CHAR") == 0 || strcmp(ident, "PUSH_STRING") == 0) {
            unsigned char *buf = NULL;
            size_t len = 0;
            if (!parse_string_lit(&s, &buf, &len, err_buf, err_cap)) {
                bc_free(out);
                return 0;
            }
            if (strcmp(ident, "PUSH_CHAR") == 0 && len != 1) {
                free(buf);
                err_set(err_buf, err_cap, "PUSH_CHAR expects a single character");
                bc_free(out);
                return 0;
            }
            uint8_t op = strcmp(ident, "PUSH_CHAR") == 0 ? BC_PUSH_CHAR : BC_PUSH_STRING;
            int ok = bc_emit_u8(out, op) && bc_emit_string(out, (const char*)buf, len);
            free(buf);
            if (!ok) {
                err_set(err_buf, err_cap, "failed to emit string");
                bc_free(out);
                return 0;
            }
        } else if (strcmp(ident, "PUSH_BYTE") == 0) {
            uint32_t v = 0;
            if (!parse_u32(&s, &v) || v > 255) {
                err_set(err_buf, err_cap, "PUSH_BYTE expects 0-255");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_PUSH_BYTE) || !bc_emit_u8(out, (uint8_t)v)) {
                err_set(err_buf, err_cap, "failed to emit PUSH_BYTE");
                bc_free(out);
                return 0;
            }
        } else if (strcmp(ident, "BUILD_NUMBER_LIT") == 0) {
            uint32_t count = 0;
            if (!parse_u32(&s, &count)) {
                err_set(err_buf, err_cap, "BUILD_NUMBER_LIT expects a count");
                bc_free(out);
                return 0;
            }
            if (!bc_emit_u8(out, BC_BUILD_NUMBER_LIT) || !bc_emit_u32(out, count)) {
                err_set(err_buf, err_cap, "failed to emit BUILD_NUMBER_LIT");
                bc_free(out);
                return 0;
            }
            for (uint32_t i = 0; i < count; i++) {
                double v = 0.0;
                s = skip_ws(s);
                if (!parse_double(&s, &v)) {
                    err_set(err_buf, err_cap, "BUILD_NUMBER_LIT expects values");
                    bc_free(out);
                    return 0;
                }
                if (!bc_emit_f64(out, v)) {
                    err_set(err_buf, err_cap, "failed to emit BUILD_NUMBER_LIT value");
                    bc_free(out);
                    return 0;
                }
            }
        } else if (strcmp(ident, "BUILD_NUMBER") == 0 || strcmp(ident, "BUILD_BYTE") == 0 ||
                   strcmp(ident, "BUILD_OBJECT") == 0 || strcmp(ident, "BUILD_FUNCTION") == 0) {
            uint32_t count = 0;
            if (!parse_u32(&s, &count)) {
                err_set(err_buf, err_cap, "BUILD_* expects a count");
                bc_free(out);
                return 0;
            }
            if (strcmp(ident, "BUILD_FUNCTION") == 0) {
                err_set(err_buf, err_cap, "BUILD_FUNCTION not supported in asm yet");
                bc_free(out);
                return 0;
            }
            uint8_t op = strcmp(ident, "BUILD_NUMBER") == 0 ? BC_BUILD_NUMBER :
                         strcmp(ident, "BUILD_BYTE") == 0 ? BC_BUILD_BYTE : BC_BUILD_OBJECT;
            if (!bc_emit_u8(out, op) || !bc_emit_u32(out, count)) {
                err_set(err_buf, err_cap, "failed to emit BUILD_*");
                bc_free(out);
                return 0;
            }
        } else if (strcmp(ident, "LOAD_ROOT") == 0 || strcmp(ident, "LOAD_GLOBAL") == 0 ||
                   strcmp(ident, "STORE_GLOBAL") == 0 || strcmp(ident, "CALL") == 0) {
            if (strcmp(ident, "LOAD_ROOT") == 0) {
                if (!bc_emit_u8(out, BC_LOAD_ROOT)) {
                    err_set(err_buf, err_cap, "failed to emit LOAD_ROOT");
                    bc_free(out);
                    return 0;
                }
                goto line_done;
            }
            char name[256];
            if (!parse_ident(&s, name, sizeof(name))) {
                err_set(err_buf, err_cap, "expected identifier name");
                bc_free(out);
                return 0;
            }
            if (strcmp(ident, "CALL") == 0) {
                uint32_t argc = 0;
                if (!parse_u32(&s, &argc)) {
                    err_set(err_buf, err_cap, "CALL expects arg count");
                    bc_free(out);
                    return 0;
                }
                if (!bc_emit_u8(out, BC_CALL) ||
                    !bc_emit_string(out, name, strlen(name)) ||
                    !bc_emit_u32(out, argc)) {
                    err_set(err_buf, err_cap, "failed to emit CALL");
                    bc_free(out);
                    return 0;
                }
            } else {
                uint8_t op = strcmp(ident, "LOAD_GLOBAL") == 0 ? BC_LOAD_GLOBAL : BC_STORE_GLOBAL;
                if (!bc_emit_u8(out, op) || !bc_emit_string(out, name, strlen(name))) {
                    err_set(err_buf, err_cap, "failed to emit name");
                    bc_free(out);
                    return 0;
                }
            }
        } else if (strcmp(ident, "INDEX") == 0 || strcmp(ident, "STORE_INDEX") == 0 ||
                   strcmp(ident, "POP") == 0 || strcmp(ident, "DUP") == 0 ||
                   strcmp(ident, "GC") == 0 || strcmp(ident, "DUMP") == 0 ||
                   strcmp(ident, "LOAD_THIS") == 0 || strcmp(ident, "SET_THIS") == 0 ||
                   strcmp(ident, "ADD") == 0 || strcmp(ident, "SUB") == 0 ||
                   strcmp(ident, "MUL") == 0 || strcmp(ident, "DIV") == 0 ||
                   strcmp(ident, "MOD") == 0 || strcmp(ident, "NEG") == 0 ||
                   strcmp(ident, "NOT") == 0 || strcmp(ident, "EQ") == 0 ||
                   strcmp(ident, "NEQ") == 0 || strcmp(ident, "LT") == 0 ||
                   strcmp(ident, "LTE") == 0 || strcmp(ident, "GT") == 0 ||
                   strcmp(ident, "GTE") == 0 || strcmp(ident, "AND") == 0 ||
                   strcmp(ident, "OR") == 0) {
            uint8_t op = BC_INDEX;
            if (strcmp(ident, "STORE_INDEX") == 0) op = BC_STORE_INDEX;
            else if (strcmp(ident, "POP") == 0) op = BC_POP;
            else if (strcmp(ident, "DUP") == 0) op = BC_DUP;
            else if (strcmp(ident, "GC") == 0) op = BC_GC;
            else if (strcmp(ident, "DUMP") == 0) op = BC_DUMP;
            else if (strcmp(ident, "LOAD_THIS") == 0) op = BC_LOAD_THIS;
            else if (strcmp(ident, "SET_THIS") == 0) op = BC_SET_THIS;
            else if (strcmp(ident, "ADD") == 0) op = BC_ADD;
            else if (strcmp(ident, "SUB") == 0) op = BC_SUB;
            else if (strcmp(ident, "MUL") == 0) op = BC_MUL;
            else if (strcmp(ident, "DIV") == 0) op = BC_DIV;
            else if (strcmp(ident, "MOD") == 0) op = BC_MOD;
            else if (strcmp(ident, "NEG") == 0) op = BC_NEG;
            else if (strcmp(ident, "NOT") == 0) op = BC_NOT;
            else if (strcmp(ident, "EQ") == 0) op = BC_EQ;
            else if (strcmp(ident, "NEQ") == 0) op = BC_NEQ;
            else if (strcmp(ident, "LT") == 0) op = BC_LT;
            else if (strcmp(ident, "LTE") == 0) op = BC_LTE;
            else if (strcmp(ident, "GT") == 0) op = BC_GT;
            else if (strcmp(ident, "GTE") == 0) op = BC_GTE;
            else if (strcmp(ident, "AND") == 0) op = BC_AND;
            else if (strcmp(ident, "OR") == 0) op = BC_OR;
            if (!bc_emit_u8(out, op)) {
                err_set(err_buf, err_cap, "failed to emit opcode");
                bc_free(out);
                return 0;
            }
        } else {
            err_set(err_buf, err_cap, "unknown opcode");
            bc_free(out);
            return 0;
        }

line_done:
        while (*s && *s != '\n' && *s != '\r') s++;
        while (*s == '\n' || *s == '\r') s++;
    }

    return 1;
}

static int read_u8(const unsigned char *data, size_t len, size_t *pc, uint8_t *out)
{
    if (*pc + 1 > len) return 0;
    *out = data[(*pc)++];
    return 1;
}

static int read_u32(const unsigned char *data, size_t len, size_t *pc, uint32_t *out)
{
    if (*pc + 4 > len) return 0;
    uint32_t v = 0;
    v |= (uint32_t)data[(*pc)++];
    v |= (uint32_t)data[(*pc)++] << 8;
    v |= (uint32_t)data[(*pc)++] << 16;
    v |= (uint32_t)data[(*pc)++] << 24;
    *out = v;
    return 1;
}

static int read_f64(const unsigned char *data, size_t len, size_t *pc, double *out)
{
    if (*pc + 8 > len) return 0;
    union {
        double d;
        unsigned char b[8];
    } u;
    for (int i = 0; i < 8; i++) {
        u.b[i] = data[(*pc)++];
    }
    *out = u.d;
    return 1;
}

static int read_string(const unsigned char *data, size_t len, size_t *pc, unsigned char **out, size_t *out_len)
{
    uint32_t slen = 0;
    if (!read_u32(data, len, pc, &slen)) return 0;
    if (*pc + slen > len) return 0;
    unsigned char *buf = (unsigned char*)malloc(slen + 1);
    if (!buf) return 0;
    memcpy(buf, data + *pc, slen);
    buf[slen] = 0;
    *pc += slen;
    *out = buf;
    *out_len = slen;
    return 1;
}

static void fprint_escaped(FILE *out, const unsigned char *s, size_t len, char quote)
{
    fputc(quote, out);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = s[i];
        switch (c) {
        case '\n': fputs("\\n", out); break;
        case '\r': fputs("\\r", out); break;
        case '\t': fputs("\\t", out); break;
        case '\\': fputs("\\\\", out); break;
        case '"': fputs("\\\"", out); break;
        case '\'': fputs("\\'", out); break;
        default: fputc((char)c, out); break;
        }
    }
    fputc(quote, out);
}

int urb_disassemble(const unsigned char *data, size_t len, FILE *out)
{
    size_t pc = 0;
    while (pc < len) {
        uint8_t op = 0;
        if (!read_u8(data, len, &pc, &op)) return 0;
        switch (op) {
        case BC_PUSH_NUM: {
            double v = 0.0;
            if (!read_f64(data, len, &pc, &v)) return 0;
            fprintf(out, "PUSH_NUM %.17g\n", v);
            break;
        }
        case BC_PUSH_CHAR:
        case BC_PUSH_STRING: {
            unsigned char *buf = NULL;
            size_t slen = 0;
            if (!read_string(data, len, &pc, &buf, &slen)) return 0;
            fputs(op == BC_PUSH_CHAR ? "PUSH_CHAR " : "PUSH_STRING ", out);
            fprint_escaped(out, buf, slen, op == BC_PUSH_CHAR ? '\'' : '"');
            fputc('\n', out);
            free(buf);
            break;
        }
        case BC_PUSH_BYTE: {
            uint8_t v = 0;
            if (!read_u8(data, len, &pc, &v)) return 0;
            fprintf(out, "PUSH_BYTE %u\n", (unsigned)v);
            break;
        }
        case BC_BUILD_NUMBER:
        case BC_BUILD_BYTE:
        case BC_BUILD_OBJECT: {
            uint32_t count = 0;
            if (!read_u32(data, len, &pc, &count)) return 0;
            const char *name = op == BC_BUILD_NUMBER ? "BUILD_NUMBER" :
                               op == BC_BUILD_BYTE ? "BUILD_BYTE" : "BUILD_OBJECT";
            fprintf(out, "%s %u\n", name, (unsigned)count);
            break;
        }
        case BC_BUILD_FUNCTION: {
            uint32_t argc = 0;
            uint32_t vararg = 0;
            uint32_t code_len = 0;
            if (!read_u32(data, len, &pc, &argc)) return 0;
            if (!read_u32(data, len, &pc, &vararg)) return 0;
            if (!read_u32(data, len, &pc, &code_len)) return 0;
            if (pc + code_len > len) return 0;
            pc += code_len;
            fprintf(out, "BUILD_FUNCTION %u %u %u", (unsigned)argc, (unsigned)vararg, (unsigned)code_len);
            for (uint32_t i = 0; i < argc; i++) {
                unsigned char *buf = NULL;
                size_t slen = 0;
                if (!read_string(data, len, &pc, &buf, &slen)) return 0;
                fprintf(out, " %s", buf);
                free(buf);
            }
            fputc('\n', out);
            break;
        }
        case BC_BUILD_NUMBER_LIT: {
            uint32_t count = 0;
            if (!read_u32(data, len, &pc, &count)) return 0;
            fprintf(out, "BUILD_NUMBER_LIT %u", (unsigned)count);
            for (uint32_t i = 0; i < count; i++) {
                double v = 0.0;
                if (!read_f64(data, len, &pc, &v)) return 0;
                fprintf(out, " %.17g", v);
            }
            fputc('\n', out);
            break;
        }
        case BC_LOAD_GLOBAL:
        case BC_STORE_GLOBAL:
        case BC_CALL: {
            unsigned char *buf = NULL;
            size_t slen = 0;
            if (!read_string(data, len, &pc, &buf, &slen)) return 0;
            const char *name = op == BC_LOAD_GLOBAL ? "LOAD_GLOBAL" :
                               op == BC_STORE_GLOBAL ? "STORE_GLOBAL" : "CALL";
            if (op == BC_CALL) {
                uint32_t argc = 0;
                if (!read_u32(data, len, &pc, &argc)) {
                    free(buf);
                    return 0;
                }
                fprintf(out, "%s %s %u\n", name, buf, (unsigned)argc);
            } else {
                fprintf(out, "%s %s\n", name, buf);
            }
            free(buf);
            break;
        }
        case BC_LOAD_ROOT:
            fputs("LOAD_ROOT\n", out);
            break;
        case BC_LOAD_THIS:
            fputs("LOAD_THIS\n", out);
            break;
        case BC_INDEX:
            fputs("INDEX\n", out);
            break;
        case BC_STORE_INDEX:
            fputs("STORE_INDEX\n", out);
            break;
        case BC_SET_THIS:
            fputs("SET_THIS\n", out);
            break;
        case BC_POP:
            fputs("POP\n", out);
            break;
        case BC_DUP:
            fputs("DUP\n", out);
            break;
        case BC_GC:
            fputs("GC\n", out);
            break;
        case BC_DUMP:
            fputs("DUMP\n", out);
            break;
        case BC_ADD:
            fputs("ADD\n", out);
            break;
        case BC_SUB:
            fputs("SUB\n", out);
            break;
        case BC_MUL:
            fputs("MUL\n", out);
            break;
        case BC_DIV:
            fputs("DIV\n", out);
            break;
        case BC_MOD:
            fputs("MOD\n", out);
            break;
        case BC_NEG:
            fputs("NEG\n", out);
            break;
        case BC_NOT:
            fputs("NOT\n", out);
            break;
        case BC_EQ:
            fputs("EQ\n", out);
            break;
        case BC_NEQ:
            fputs("NEQ\n", out);
            break;
        case BC_LT:
            fputs("LT\n", out);
            break;
        case BC_LTE:
            fputs("LTE\n", out);
            break;
        case BC_GT:
            fputs("GT\n", out);
            break;
        case BC_GTE:
            fputs("GTE\n", out);
            break;
        case BC_AND:
            fputs("AND\n", out);
            break;
        case BC_OR:
            fputs("OR\n", out);
            break;
        default:
            return 0;
        }
    }
    return 1;
}
