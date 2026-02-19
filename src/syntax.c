#include "vm.h"
#include "bytecode.h"
#include "papagaio.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__)
#define UNUSED_FN __attribute__((unused))
#else
#define UNUSED_FN
#endif

#define PAPAGAIO_ESCAPED_SIGIL '\x01'

typedef enum {
    TOK_EOF = 0,
    TOK_IDENT,
    TOK_IF,
    TOK_ELSE,
    TOK_FOR,
    TOK_WHILE,
    TOK_EACH,
    TOK_IN,
    TOK_RETURN,
    TOK_BREAK,
    TOK_CONTINUE,
    TOK_SWITCH,
    TOK_CASE,
    TOK_DEFAULT,
    TOK_GOTO,
    TOK_NUMBER,
    TOK_STRING,
    TOK_CHAR,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_LBRACKET,
    TOK_RBRACKET,
    TOK_DOT,
    TOK_COMMA,
    TOK_COLON,
    TOK_EQ,
    TOK_QEQ,
    TOK_PLUS,
    TOK_MINUS,
    TOK_STAR,
    TOK_SLASH,
    TOK_PERCENT,
    TOK_BANG,
    TOK_TILDE,
    TOK_EQEQ,
    TOK_EQEQEQ,
    TOK_NEQ,
    TOK_SNEQ,
    TOK_LT,
    TOK_LTE,
    TOK_GT,
    TOK_GTE,
    TOK_SHL,
    TOK_SHR,
    TOK_BITAND,
    TOK_BITOR,
    TOK_BITXOR,
    TOK_AND,
    TOK_OR,
    TOK_PLUSPLUS,
    TOK_MINUSMINUS,
    TOK_PLUS_EQ,
    TOK_MINUS_EQ,
    TOK_STAR_EQ,
    TOK_SLASH_EQ,
    TOK_PERCENT_EQ,
    TOK_BITAND_EQ,
    TOK_BITOR_EQ,
    TOK_BITXOR_EQ,
    TOK_SHL_EQ,
    TOK_SHR_EQ,
    TOK_ELLIPSIS
} TokenKind;

typedef struct {
    TokenKind kind;
    const char *start;
    size_t len;
    double number;
    char *str;
    size_t str_len;
    int is_float;
    int num_suffix;
    int line;
    int col;
} Token;

typedef struct Expr Expr;

typedef enum {
    EXPR_LITERAL_NUM,
    EXPR_LITERAL_STRING,
    EXPR_LITERAL_CHAR,
    EXPR_NAME,
    EXPR_MEMBER,
    EXPR_INDEX,
    EXPR_CAST_LIST,
    EXPR_LITERAL_NUMBER_LIST,
    EXPR_OBJECT_LITERAL,
    EXPR_UNARY,
    EXPR_BINARY,
    EXPR_CALL,
    EXPR_FUNC_LITERAL,
    EXPR_ASSIGN,
    EXPR_UPDATE
} ExprKind;

typedef struct {
    char *name;
    size_t name_len;
    Expr *value;
} ObjPair;

struct Expr {
    ExprKind kind;
    int line;
    int col;
    union {
        struct {
            double number;
            int is_float;
            int num_suffix;
        } lit_num;
        struct {
            char *data;
            size_t len;
        } lit_str;
        struct {
            char *name;
            size_t len;
        } name;
        struct {
            Expr *base;
            char *name;
            size_t len;
        } member;
        struct {
            Expr *base;
            Expr *index;
        } index;
        struct {
            Expr **items;
            int count;
        } cast_list;
        struct {
            double *items;
            int count;
            int is_float;
        } num_list;
        struct {
            ObjPair *pairs;
            int count;
        } obj;
        struct {
            TokenKind op;
            Expr *expr;
        } unary;
        struct {
            TokenKind op;
            Expr *left;
            Expr *right;
        } binary;
        struct {
            Expr *callee;
            Expr **args;
            int argc;
            int has_override;
            Int override_len;
        } call;
        struct {
            TokenKind op;
            Expr *left;
            Expr *right;
        } assign;
        struct {
            TokenKind op;
            Expr *target;
            int is_prefix;
        } update;
        struct {
            char **args;
            size_t *arg_lens;
            int argc;
            int has_vararg;
            Bytecode *defaults;
            uint8_t *has_default;
            Bytecode bc;
        } func;
    } as;
};

static int expr_is_lvalue(const Expr *e);

typedef struct ArenaBlock {
    struct ArenaBlock *next;
    size_t cap;
    size_t used;
    unsigned char data[];
} ArenaBlock;

typedef struct {
    void **items;
    size_t count;
    size_t cap;
    struct ArenaBlock *blocks;
    size_t block_size;
} Arena;

static char *arena_format_temp(Arena *a, const char *prefix, int id);

typedef struct LoopContext {
    size_t *breaks;
    int break_count;
    int break_cap;
    size_t *continues;
    int cont_count;
    int cont_cap;
    size_t continue_target;
    int has_continue_target;
    int allow_continue;
} LoopContext;

typedef struct LabelEntry {
    char *name;
    size_t name_len;
    size_t pos;
    int defined;
    size_t *patches;
    int patch_count;
    int patch_cap;
} LabelEntry;

typedef struct {
    const char *src;
    size_t pos;
    int line;
    int col;
    Token current;
    TokenKind prev_kind;
    int had_error;
    char err[256];
    Arena arena;
    int temp_id;
    struct LoopContext *loops;
    int loop_count;
    int loop_cap;
    LabelEntry *labels;
    int label_count;
    int label_cap;
} Parser;

static void arena_init(Arena *a)
{
    a->items = NULL;
    a->count = 0;
    a->cap = 0;
    a->blocks = NULL;
    a->block_size = 16384;
}

static void *arena_alloc(Arena *a, size_t size)
{
    if (!a || size == 0) return NULL;
    size_t aligned = (size + 7) & ~(size_t)7;
    ArenaBlock *block = a->blocks;
    if (!block || block->used + aligned > block->cap) {
        size_t cap = a->block_size;
        if (aligned > cap) cap = aligned;
        ArenaBlock *next = (ArenaBlock*)malloc(sizeof(ArenaBlock) + cap);
        if (!next) return NULL;
        next->next = block;
        next->cap = cap;
        next->used = 0;
        a->blocks = next;
        block = next;
    }
    unsigned char *ptr = block->data + block->used;
    memset(ptr, 0, size);
    block->used += aligned;
    return ptr;
}

static int arena_track(Arena *a, void *p)
{
    if (!p) return 0;
    if (a->count == a->cap) {
        size_t next = a->cap == 0 ? 16 : a->cap * 2;
        void **items = (void**)realloc(a->items, next * sizeof(void*));
        if (!items) return 0;
        a->items = items;
        a->cap = next;
    }
    a->items[a->count++] = p;
    return 1;
}

static char *arena_strndup(Arena *a, const char *s, size_t len)
{
    char *buf = (char*)arena_alloc(a, len + 1);
    if (!buf) return NULL;
    memcpy(buf, s, len);
    buf[len] = 0;
    return buf;
}

static void arena_free(Arena *a)
{
    for (size_t i = 0; i < a->count; i++) {
        free(a->items[i]);
    }
    free(a->items);
    a->items = NULL;
    a->count = 0;
    a->cap = 0;
    ArenaBlock *block = a->blocks;
    while (block) {
        ArenaBlock *next = block->next;
        free(block);
        block = next;
    }
    a->blocks = NULL;
    a->block_size = 0;
}

static void loop_free(Parser *p)
{
    for (int i = 0; i < p->loop_count; i++) {
        free(p->loops[i].breaks);
        free(p->loops[i].continues);
    }
    free(p->loops);
    p->loops = NULL;
    p->loop_count = 0;
    p->loop_cap = 0;
}

static LoopContext *loop_current(Parser *p)
{
    if (!p || p->loop_count <= 0) return NULL;
    return &p->loops[p->loop_count - 1];
}

static int loop_push(Parser *p, int allow_continue)
{
    if (p->loop_count == p->loop_cap) {
        int next = p->loop_cap == 0 ? 4 : p->loop_cap * 2;
        LoopContext *tmp = (LoopContext*)realloc(p->loops, (size_t)next * sizeof(LoopContext));
        if (!tmp) return 0;
        p->loops = tmp;
        p->loop_cap = next;
    }
    LoopContext *ctx = &p->loops[p->loop_count++];
    memset(ctx, 0, sizeof(*ctx));
    ctx->allow_continue = allow_continue;
    return 1;
}

static void loop_pop(Parser *p)
{
    if (!p || p->loop_count <= 0) return;
    LoopContext *ctx = &p->loops[p->loop_count - 1];
    free(ctx->breaks);
    free(ctx->continues);
    p->loop_count--;
}

static int loop_add_break(Parser *p, size_t pos)
{
    LoopContext *ctx = loop_current(p);
    if (!ctx) return 0;
    if (ctx->break_count == ctx->break_cap) {
        int next = ctx->break_cap == 0 ? 4 : ctx->break_cap * 2;
        size_t *tmp = (size_t*)realloc(ctx->breaks, (size_t)next * sizeof(size_t));
        if (!tmp) return 0;
        ctx->breaks = tmp;
        ctx->break_cap = next;
    }
    ctx->breaks[ctx->break_count++] = pos;
    return 1;
}

static int loop_add_continue(Parser *p, size_t pos)
{
    LoopContext *ctx = loop_current(p);
    if (!ctx) return 0;
    if (ctx->cont_count == ctx->cont_cap) {
        int next = ctx->cont_cap == 0 ? 4 : ctx->cont_cap * 2;
        size_t *tmp = (size_t*)realloc(ctx->continues, (size_t)next * sizeof(size_t));
        if (!tmp) return 0;
        ctx->continues = tmp;
        ctx->cont_cap = next;
    }
    ctx->continues[ctx->cont_count++] = pos;
    return 1;
}

static void parser_error(Parser *p, const char *fmt, ...)
{
    if (p->had_error) return;
    va_list args;
    va_start(args, fmt);
    char msg[200];
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    snprintf(p->err, sizeof(p->err), "parse error at line %d, col %d: %s", p->current.line, p->current.col, msg);
    p->had_error = 1;
}

static void label_free(Parser *p)
{
    if (!p || !p->labels) return;
    for (int i = 0; i < p->label_count; i++) {
        free(p->labels[i].patches);
    }
    free(p->labels);
    p->labels = NULL;
    p->label_count = 0;
    p->label_cap = 0;
}

static LabelEntry *label_find(Parser *p, const char *name, size_t len)
{
    if (!p || !p->labels) return NULL;
    for (int i = 0; i < p->label_count; i++) {
        if (p->labels[i].name_len == len &&
            strncmp(p->labels[i].name, name, len) == 0) {
            return &p->labels[i];
        }
    }
    return NULL;
}

static LabelEntry *label_ensure(Parser *p, const char *name, size_t len)
{
    if (!p) return NULL;
    LabelEntry *existing = label_find(p, name, len);
    if (existing) return existing;
    if (p->label_count == p->label_cap) {
        int next = p->label_cap == 0 ? 4 : p->label_cap * 2;
        LabelEntry *tmp = (LabelEntry*)realloc(p->labels, (size_t)next * sizeof(LabelEntry));
        if (!tmp) return NULL;
        p->labels = tmp;
        p->label_cap = next;
    }
    LabelEntry *lbl = &p->labels[p->label_count++];
    memset(lbl, 0, sizeof(*lbl));
    lbl->name = arena_strndup(&p->arena, name, len);
    if (!lbl->name) return NULL;
    lbl->name_len = len;
    lbl->defined = 0;
    return lbl;
}

static int patch_jump(Bytecode *bc, Parser *p, size_t pos, size_t target);

static int label_add_ref(Parser *p, Bytecode *bc, const char *name, size_t len, size_t pos)
{
    if (!p || !bc) return 0;
    LabelEntry *lbl = label_ensure(p, name, len);
    if (!lbl) return 0;
    if (lbl->defined) {
        return patch_jump(bc, p, pos, lbl->pos);
    }
    if (lbl->patch_count == lbl->patch_cap) {
        int next = lbl->patch_cap == 0 ? 4 : lbl->patch_cap * 2;
        size_t *tmp = (size_t*)realloc(lbl->patches, (size_t)next * sizeof(size_t));
        if (!tmp) return 0;
        lbl->patches = tmp;
        lbl->patch_cap = next;
    }
    lbl->patches[lbl->patch_count++] = pos;
    return 1;
}

static int label_define(Parser *p, Bytecode *bc, const char *name, size_t len)
{
    if (!p || !bc) return 0;
    LabelEntry *lbl = label_ensure(p, name, len);
    if (!lbl) return 0;
    if (lbl->defined) {
        parser_error(p, "label '%.*s' already defined", (int)len, name);
        return 0;
    }
    lbl->defined = 1;
    lbl->pos = bc->len;
    for (int i = 0; i < lbl->patch_count; i++) {
        if (!patch_jump(bc, p, lbl->patches[i], lbl->pos)) return 0;
    }
    lbl->patch_count = 0;
    return 1;
}

static int label_validate(Parser *p)
{
    if (!p) return 0;
    for (int i = 0; i < p->label_count; i++) {
        if (!p->labels[i].defined && p->labels[i].patch_count > 0) {
            parser_error(p, "undefined label '%.*s'", (int)p->labels[i].name_len, p->labels[i].name);
            return 0;
        }
    }
    return 1;
}
static void token_free(Token *t)
{
    free(t->str);
    t->str = NULL;
    t->str_len = 0;
}

static int peek_char(Parser *p)
{
    return p->src[p->pos];
}

static int next_char(Parser *p)
{
    int c = p->src[p->pos];
    if (c == 0) return 0;
    p->pos++;
    if (c == '\n') {
        p->line++;
        p->col = 1;
    } else {
        p->col++;
    }
    return c;
}

static void skip_ws(Parser *p)
{
    for (;;) {
        int c = peek_char(p);
        while (c && isspace((unsigned char)c)) {
            next_char(p);
            c = peek_char(p);
        }
        if (c == '/' && p->src[p->pos + 1] == '/') {
            while (c && c != '\n') {
                next_char(p);
                c = peek_char(p);
            }
            continue;
        }
        if (c == '/' && p->src[p->pos + 1] == '*') {
            next_char(p);
            next_char(p);
            c = peek_char(p);
            while (c) {
                if (c == '*' && p->src[p->pos + 1] == '/') {
                    next_char(p);
                    next_char(p);
                    break;
                }
                next_char(p);
                c = peek_char(p);
            }
            if (!c) {
                parser_error(p, "unterminated block comment");
                return;
            }
            continue;
        }
        break;
    }
}

static int parse_escape(Parser *p, int *out)
{
    int c = next_char(p);
    if (!c) return 0;
    switch (c) {
    case 'n': *out = '\n'; return 1;
    case 'r': *out = '\r'; return 1;
    case 't': *out = '\t'; return 1;
    case '\\': *out = '\\'; return 1;
    case '\'': *out = '\''; return 1;
    case '"': *out = '"'; return 1;
    case '$': *out = PAPAGAIO_ESCAPED_SIGIL; return 1;
    default: return 0;
    }
}

static Token next_token(Parser *p)
{
    Token t;
    memset(&t, 0, sizeof(t));

    skip_ws(p);
    t.start = p->src + p->pos;
    t.line = p->line;
    t.col = p->col;

    int c = peek_char(p);
    if (!c) {
        t.kind = TOK_EOF;
        return t;
    }

    if (isalpha((unsigned char)c) || c == '_') {
        next_char(p);
        while (isalnum((unsigned char)peek_char(p)) || peek_char(p) == '_') {
            next_char(p);
        }
        t.len = (size_t)(p->src + p->pos - t.start);
        if (t.len == 2 && strncmp(t.start, "if", 2) == 0) {
            t.kind = TOK_IF;
        } else if (t.len == 4 && strncmp(t.start, "else", 4) == 0) {
            t.kind = TOK_ELSE;
        } else if (t.len == 3 && strncmp(t.start, "for", 3) == 0) {
            t.kind = TOK_FOR;
        } else if (t.len == 5 && strncmp(t.start, "while", 5) == 0) {
            t.kind = TOK_WHILE;
        } else if (t.len == 4 && strncmp(t.start, "each", 4) == 0) {
            t.kind = TOK_EACH;
        } else if (t.len == 2 && strncmp(t.start, "in", 2) == 0) {
            t.kind = TOK_IN;
        } else if (t.len == 6 && strncmp(t.start, "return", 6) == 0) {
            t.kind = TOK_RETURN;
        } else if (t.len == 5 && strncmp(t.start, "break", 5) == 0) {
            t.kind = TOK_BREAK;
        } else if (t.len == 8 && strncmp(t.start, "continue", 8) == 0) {
            t.kind = TOK_CONTINUE;
        } else if (t.len == 6 && strncmp(t.start, "switch", 6) == 0) {
            t.kind = TOK_SWITCH;
        } else if (t.len == 4 && strncmp(t.start, "case", 4) == 0) {
            t.kind = TOK_CASE;
        } else if (t.len == 7 && strncmp(t.start, "default", 7) == 0) {
            t.kind = TOK_DEFAULT;
        } else if (t.len == 4 && strncmp(t.start, "goto", 4) == 0) {
            t.kind = TOK_GOTO;
        } else {
            t.kind = TOK_IDENT;
        }
        return t;
    }

    if (isdigit((unsigned char)c) || (c == '.' && isdigit((unsigned char)p->src[p->pos + 1]))) {
        char *end = NULL;
        double v = strtod(p->src + p->pos, &end);
        if (end == p->src + p->pos) {
            t.kind = TOK_EOF;
            return t;
        }
        size_t len = (size_t)(end - (p->src + p->pos));
        int is_float = 0;
        int num_suffix = 0;
        for (size_t i = 0; i < len; i++) {
            char ch = p->src[p->pos + i];
            if (ch == '.' || ch == 'e' || ch == 'E') {
                is_float = 1;
                break;
            }
        }
        char suffix = p->src[p->pos + len];
        char next = p->src[p->pos + len + 1];
        if ((suffix == 'i' || suffix == 'u' || suffix == 'f') &&
            !(isalnum((unsigned char)next) || next == '_')) {
            num_suffix = suffix;
            len += 1;
            if (suffix == 'f') {
                is_float = 1;
            } else {
                is_float = 0;
            }
        }
        for (size_t i = 0; i < len; i++) next_char(p);
        t.kind = TOK_NUMBER;
        t.number = v;
        t.len = len;
        t.is_float = is_float;
        t.num_suffix = num_suffix;
        return t;
    }

    if (c == '"' || c == '\'') {
        int quote = next_char(p);
        size_t cap = 16;
        size_t len = 0;
        char *buf = (char*)malloc(cap);
        if (!buf) {
            parser_error(p, "out of memory");
            t.kind = TOK_EOF;
            return t;
        }
        while ((c = peek_char(p)) && c != quote) {
            int out = 0;
            if (c == '\\') {
                next_char(p);
                if (!parse_escape(p, &out)) {
                    free(buf);
                    parser_error(p, "invalid escape sequence");
                    t.kind = TOK_EOF;
                    return t;
                }
            } else {
                out = next_char(p);
            }
            if (len + 1 > cap) {
                cap *= 2;
                char *next = (char*)realloc(buf, cap);
                if (!next) {
                    free(buf);
                    parser_error(p, "out of memory");
                    t.kind = TOK_EOF;
                    return t;
                }
                buf = next;
            }
            buf[len++] = (char)out;
        }
        if (peek_char(p) != quote) {
            free(buf);
            parser_error(p, "unterminated string");
            t.kind = TOK_EOF;
            return t;
        }
        next_char(p);
        t.kind = quote == '\'' ? TOK_CHAR : TOK_STRING;
        t.str = buf;
        t.str_len = len;
        return t;
    }

    next_char(p);
    switch (c) {
    case '(': t.kind = TOK_LPAREN; break;
    case ')': t.kind = TOK_RPAREN; break;
    case '{': t.kind = TOK_LBRACE; break;
    case '}': t.kind = TOK_RBRACE; break;
    case '[': t.kind = TOK_LBRACKET; break;
    case ']': t.kind = TOK_RBRACKET; break;
    case '.':
        if (peek_char(p) == '.' && p->src[p->pos + 1] == '.') {
            next_char(p);
            next_char(p);
            t.kind = TOK_ELLIPSIS;
        } else {
            t.kind = TOK_DOT;
        }
        break;
    case ',': t.kind = TOK_COMMA; break;
    case ':': t.kind = TOK_COLON; break;
    case ';':
        parser_error(p, "';' is no longer supported; use ',' to separate statements");
        t.kind = TOK_EOF;
        break;
    case '+':
        if (peek_char(p) == '+') {
            next_char(p);
            t.kind = TOK_PLUSPLUS;
        } else if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_PLUS_EQ;
        } else {
            t.kind = TOK_PLUS;
        }
        break;
    case '-':
        if (peek_char(p) == '-') {
            next_char(p);
            t.kind = TOK_MINUSMINUS;
        } else if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_MINUS_EQ;
        } else {
            t.kind = TOK_MINUS;
        }
        break;
    case '*':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_STAR_EQ;
        } else {
            t.kind = TOK_STAR;
        }
        break;
    case '/':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_SLASH_EQ;
        } else {
            t.kind = TOK_SLASH;
        }
        break;
    case '%':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_PERCENT_EQ;
        } else {
            t.kind = TOK_PERCENT;
        }
        break;
    case '!':
        if (peek_char(p) == '=') {
            next_char(p);
            if (peek_char(p) == '=') {
                next_char(p);
                t.kind = TOK_SNEQ;
            } else {
                t.kind = TOK_NEQ;
            }
        } else {
            t.kind = TOK_BANG;
        }
        break;
    case '~':
        t.kind = TOK_TILDE;
        break;
    case '=':
        if (peek_char(p) == '=') {
            next_char(p);
            if (peek_char(p) == '=') {
                next_char(p);
                t.kind = TOK_EQEQEQ;
            } else {
                t.kind = TOK_EQEQ;
            }
        } else {
            t.kind = TOK_EQ;
        }
        break;
    case '?':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_QEQ;
        } else {
            t.kind = TOK_EOF;
        }
        break;
    case '<':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_LTE;
        } else if (peek_char(p) == '<') {
            next_char(p);
            if (peek_char(p) == '=') {
                next_char(p);
                t.kind = TOK_SHL_EQ;
            } else {
                t.kind = TOK_SHL;
            }
        } else {
            t.kind = TOK_LT;
        }
        break;
    case '>':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_GTE;
        } else if (peek_char(p) == '>') {
            next_char(p);
            if (peek_char(p) == '=') {
                next_char(p);
                t.kind = TOK_SHR_EQ;
            } else {
                t.kind = TOK_SHR;
            }
        } else {
            t.kind = TOK_GT;
        }
        break;
    case '&':
        if (peek_char(p) == '&') {
            next_char(p);
            t.kind = TOK_AND;
        } else if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_BITAND_EQ;
        } else {
            t.kind = TOK_BITAND;
        }
        break;
    case '|':
        if (peek_char(p) == '|') {
            next_char(p);
            t.kind = TOK_OR;
        } else if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_BITOR_EQ;
        } else {
            t.kind = TOK_BITOR;
        }
        break;
    case '^':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_BITXOR_EQ;
        } else {
            t.kind = TOK_BITXOR;
        }
        break;
    default: t.kind = TOK_EOF; break;
    }
    return t;
}

static void advance(Parser *p)
{
    p->prev_kind = p->current.kind;
    token_free(&p->current);
    p->current = next_token(p);
}

static int match(Parser *p, TokenKind kind)
{
    if (p->current.kind != kind) return 0;
    advance(p);
    return 1;
}

static int expect(Parser *p, TokenKind kind, const char *msg)
{
    if (p->current.kind == kind) {
        advance(p);
        return 1;
    }
    parser_error(p, "%s", msg);
    return 0;
}

static TokenKind peek_kind(Parser *p, int n)
{
    Parser probe = *p;
    Token tok = {0};
    for (int i = 0; i < n; i++) {
        token_free(&tok);
        tok = next_token(&probe);
    }
    TokenKind kind = tok.kind;
    token_free(&tok);
    return kind;
}

static int peek_is_func_literal(Parser *p)
{
    Parser probe = *p;
    Token tok = {0};

    token_free(&tok);
    tok = next_token(&probe);
    if (tok.kind == TOK_RPAREN) {
        token_free(&tok);
        tok = next_token(&probe);
        token_free(&tok);
        return tok.kind == TOK_LBRACE;
    }

    for (;;) {
        int is_vararg = 0;
        if (tok.kind == TOK_ELLIPSIS) {
            is_vararg = 1;
            token_free(&tok);
            tok = next_token(&probe);
        }

        if (tok.kind != TOK_IDENT) {
            token_free(&tok);
            return 0;
        }

        token_free(&tok);
        tok = next_token(&probe);
        if (!is_vararg && tok.kind == TOK_ELLIPSIS) {
            token_free(&tok);
            tok = next_token(&probe);
            if (tok.kind != TOK_RPAREN) {
                token_free(&tok);
                return 0;
            }
            token_free(&tok);
            tok = next_token(&probe);
            token_free(&tok);
            return tok.kind == TOK_LBRACE;
        }
        if (is_vararg) {
            if (tok.kind != TOK_RPAREN) {
                token_free(&tok);
                return 0;
            }
            token_free(&tok);
            tok = next_token(&probe);
            token_free(&tok);
            return tok.kind == TOK_LBRACE;
        }

        if (tok.kind == TOK_EQ) {
            int depth = 0;
            for (;;) {
                token_free(&tok);
                tok = next_token(&probe);
                if (tok.kind == TOK_EOF) {
                    token_free(&tok);
                    return 0;
                }
                if (tok.kind == TOK_LPAREN || tok.kind == TOK_LBRACE || tok.kind == TOK_LBRACKET) {
                    depth++;
                    continue;
                }
                if (tok.kind == TOK_RPAREN) {
                    if (depth == 0) {
                        token_free(&tok);
                        tok = next_token(&probe);
                        token_free(&tok);
                        return tok.kind == TOK_LBRACE;
                    }
                    depth--;
                    continue;
                }
                if (tok.kind == TOK_RBRACE || tok.kind == TOK_RBRACKET) {
                    if (depth > 0) depth--;
                    continue;
                }
                if (tok.kind == TOK_COMMA && depth == 0) {
                    token_free(&tok);
                    tok = next_token(&probe);
                    break;
                }
            }
            continue;
        }

        if (tok.kind == TOK_RPAREN) {
            token_free(&tok);
            tok = next_token(&probe);
            token_free(&tok);
            return tok.kind == TOK_LBRACE;
        }

        if (tok.kind != TOK_COMMA) {
            token_free(&tok);
            return 0;
        }

        token_free(&tok);
        tok = next_token(&probe);
    }
}

static Expr *expr_new(Parser *p, ExprKind kind)
{
    Expr *e = (Expr*)arena_alloc(&p->arena, sizeof(Expr));
    if (!e) {
        parser_error(p, "out of memory");
        return NULL;
    }
    e->kind = kind;
    e->line = p->current.line;
    e->col = p->current.col;
    return e;
}

static Expr *parse_expr(Parser *p);
static int parse_statement(Parser *p, Bytecode *bc);
static int parse_switch_statement(Parser *p, Bytecode *bc);
static int parse_switch_case(Parser *p, Bytecode *bc, const char *tmp_name, size_t tmp_len);
static Expr *parse_func_literal(Parser *p);
UNUSED_FN static Expr *parse_func_literal_with_first_arg(Parser *p, char *name, size_t len);
static int emit_expr(Bytecode *bc, Parser *p, Expr *e);
static void parser_error(Parser *p, const char *fmt, ...);
static int patch_jump(Bytecode *bc, Parser *p, size_t pos, size_t target);

static Expr *parse_object_literal(Parser *p)
{
    if (!expect(p, TOK_LBRACE, "expected '{' to start object literal")) return NULL;
    Expr *e = expr_new(p, EXPR_OBJECT_LITERAL);
    if (!e) return NULL;
    ObjPair *pairs = NULL;
    int count = 0;
    int cap = 0;

    if (p->current.kind != TOK_RBRACE) {
        for (;;) {
            if (p->current.kind != TOK_IDENT) {
                parser_error(p, "object key must be an identifier");
                return NULL;
            }
            char *key = arena_strndup(&p->arena, p->current.start, p->current.len);
            size_t key_len = p->current.len;
            advance(p);
            if (!expect(p, TOK_EQ, "expected '=' after object key")) return NULL;
            Expr *value = parse_expr(p);
            if (!value) return NULL;

            if (count == cap) {
                int next = cap == 0 ? 4 : cap * 2;
                ObjPair *tmp = (ObjPair*)realloc(pairs, (size_t)next * sizeof(ObjPair));
                if (!tmp) {
                    parser_error(p, "out of memory");
                    return NULL;
                }
                pairs = tmp;
                cap = next;
            }
            pairs[count].name = key;
            pairs[count].name_len = key_len;
            pairs[count].value = value;
            count++;

            if (match(p, TOK_COMMA)) {
                /* allow trailing comma before closing brace */
                if (p->current.kind == TOK_RBRACE) break;
                continue;
            }
            break;
        }
    }

    if (!expect(p, TOK_RBRACE, "expected '}' to end object literal")) return NULL;
    if (pairs && !arena_track(&p->arena, pairs)) {
        parser_error(p, "out of memory");
        return NULL;
    }
    e->as.obj.pairs = pairs;
    e->as.obj.count = count;
    return e;
}

static Expr *parse_primary(Parser *p)
{
    if (p->current.kind == TOK_LBRACE) {
        return parse_object_literal(p);
    }

    if (p->current.kind == TOK_NUMBER) {
        /* Check if this is a space-separated number list like: 1 2 3 */
        Parser probe = *p;
        Token next = next_token(&probe);
        int is_number_list = (next.kind == TOK_NUMBER);
        token_free(&next);
        
        if (is_number_list) {
            /* Parse space-separated number list */
            double *vals = NULL;
            int count = 0;
            int cap = 0;
            int is_float = 0;
            
            for (;;) {
                if (p->current.kind != TOK_NUMBER) break;
                
                if (count == cap) {
                    int next_cap = cap == 0 ? 16 : cap * 2;
                    double *tmp = (double*)realloc(vals, (size_t)next_cap * sizeof(double));
                    if (!tmp) {
                        parser_error(p, "out of memory");
                        free(vals);
                        return NULL;
                    }
                    vals = tmp;
                    cap = next_cap;
                }
                
                vals[count++] = p->current.number;
                if (p->current.is_float) {
                    is_float = 1;
                }
                advance(p);
                
                /* Stop if next token is not a number */
                if (p->current.kind != TOK_NUMBER) break;
            }
            
            Expr *e = expr_new(p, EXPR_LITERAL_NUMBER_LIST);
            if (!e) {
                free(vals);
                return NULL;
            }
            if (vals && !arena_track(&p->arena, vals)) {
                parser_error(p, "out of memory");
                free(vals);
                return NULL;
            }
            e->as.num_list.items = vals;
            e->as.num_list.count = count;
            e->as.num_list.is_float = is_float;
            return e;
        } else {
            /* Single number literal */
            Expr *e = expr_new(p, EXPR_LITERAL_NUM);
            if (!e) return NULL;
            e->as.lit_num.number = p->current.number;
            e->as.lit_num.is_float = p->current.is_float;
            e->as.lit_num.num_suffix = p->current.num_suffix;
            advance(p);
            return e;
        }
    }

    if (p->current.kind == TOK_STRING || p->current.kind == TOK_CHAR) {
        if (p->current.kind == TOK_CHAR && p->current.str_len != 1) {
            parser_error(p, "char literal must be a single byte");
            return NULL;
        }
        Expr *e = expr_new(p, p->current.kind == TOK_CHAR ? EXPR_LITERAL_CHAR : EXPR_LITERAL_STRING);
        if (!e) return NULL;
        e->as.lit_str.data = arena_strndup(&p->arena, p->current.str, p->current.str_len);
        e->as.lit_str.len = p->current.str_len;
        advance(p);
        return e;
    }

    if (p->current.kind == TOK_IDENT) {
        Expr *e = expr_new(p, EXPR_NAME);
        if (!e) return NULL;
        e->as.name.name = arena_strndup(&p->arena, p->current.start, p->current.len);
        e->as.name.len = p->current.len;
        advance(p);
        return e;
    }

    if (p->current.kind == TOK_LBRACKET) {
        parser_error(p, "list literal with '[' is no longer supported; use space-separated numeric lists like: 1 2 3");
        return NULL;
    }

    if (p->current.kind == TOK_LPAREN) {
        int is_func = peek_is_func_literal(p);
        advance(p);
        if (is_func) {
            return parse_func_literal(p);
        }
        Expr *inner = parse_expr(p);
        if (!inner) return NULL;
        if (!expect(p, TOK_RPAREN, "expected ')' after expression")) return NULL;
        return inner;
    }

    parser_error(p, "unexpected token");
    return NULL;
}

static int parse_block(Parser *p, Bytecode *bc)
{
    if (!expect(p, TOK_LBRACE, "expected '{' to start block")) return 0;
    while (p->current.kind != TOK_RBRACE && p->current.kind != TOK_EOF) {
        if (!parse_statement(p, bc)) return 0;
    }
    if (!expect(p, TOK_RBRACE, "expected '}' after block")) return 0;
    return 1;
}

static Expr *parse_func_literal(Parser *p)
{
    Expr *e = expr_new(p, EXPR_FUNC_LITERAL);
    if (!e) return NULL;

    char **args = NULL;
    size_t *arg_lens = NULL;
    Bytecode *defaults = NULL;
    uint8_t *has_default = NULL;
    int argc = 0;
    int cap = 0;
    int has_vararg = 0;

    if (p->current.kind != TOK_RPAREN) {
        for (;;) {
            int is_vararg = 0;
            if (match(p, TOK_ELLIPSIS)) {
                is_vararg = 1;
                has_vararg = 1;
            }
            if (p->current.kind != TOK_IDENT) {
                if (is_vararg) parser_error(p, "expected parameter name after '...'");
                else parser_error(p, "expected parameter name");
                return NULL;
            }
            char *name = arena_strndup(&p->arena, p->current.start, p->current.len);
            size_t len = p->current.len;
            advance(p);
            if (!is_vararg && p->current.kind == TOK_ELLIPSIS) {
                parser_error(p, "invalid vararg syntax: use '...name'");
                return NULL;
            }

            if (argc == cap) {
                int next = cap == 0 ? 4 : cap * 2;
                char **tmp = (char**)realloc(args, (size_t)next * sizeof(char*));
                size_t *ltmp = (size_t*)realloc(arg_lens, (size_t)next * sizeof(size_t));
                Bytecode *dtmp = (Bytecode*)realloc(defaults, (size_t)next * sizeof(Bytecode));
                uint8_t *htmp = (uint8_t*)realloc(has_default, (size_t)next * sizeof(uint8_t));
                if (!tmp || !ltmp || !dtmp || !htmp) {
                    parser_error(p, "out of memory");
                    return NULL;
                }
                args = tmp;
                arg_lens = ltmp;
                defaults = dtmp;
                has_default = htmp;
                cap = next;
            }
            args[argc] = name;
            arg_lens[argc] = len;
            defaults[argc].data = NULL;
            defaults[argc].len = 0;
            defaults[argc].cap = 0;
            has_default[argc] = 0;
            argc++;

            if (is_vararg) {
                if (p->current.kind != TOK_RPAREN) {
                    parser_error(p, "varargs must be last");
                    return NULL;
                }
                break;
            }

            if (match(p, TOK_EQ)) {
                if (is_vararg) {
                    parser_error(p, "vararg cannot have default value");
                    return NULL;
                }
                Expr *def = parse_expr(p);
                if (!def) return NULL;
                Bytecode def_bc;
                bc_init(&def_bc);
                if (!emit_expr(&def_bc, p, def)) return NULL;
                defaults[argc - 1] = def_bc;
                has_default[argc - 1] = 1;
            }

            if (match(p, TOK_COMMA)) continue;
            break;
        }
    }

    if (!expect(p, TOK_RPAREN, "expected ')' after parameters")) return NULL;

    Bytecode *body = (Bytecode*)arena_alloc(&p->arena, sizeof(Bytecode));
    if (!body) {
        parser_error(p, "out of memory");
        return NULL;
    }
    bc_init(body);
    if (!parse_block(p, body)) return NULL;

    if (args && !arena_track(&p->arena, args)) {
        parser_error(p, "out of memory");
        return NULL;
    }
    if (arg_lens && !arena_track(&p->arena, arg_lens)) {
        parser_error(p, "out of memory");
        return NULL;
    }
    if (defaults && !arena_track(&p->arena, defaults)) {
        parser_error(p, "out of memory");
        return NULL;
    }
    if (has_default && !arena_track(&p->arena, has_default)) {
        parser_error(p, "out of memory");
        return NULL;
    }

    e->as.func.args = args;
    e->as.func.arg_lens = arg_lens;
    e->as.func.argc = argc;
    e->as.func.has_vararg = has_vararg;
    e->as.func.defaults = defaults;
    e->as.func.has_default = has_default;
    e->as.func.bc = *body;
    return e;
}

UNUSED_FN static Expr *parse_func_literal_with_first_arg(Parser *p, char *name, size_t len)
{
    Expr *e = expr_new(p, EXPR_FUNC_LITERAL);
    if (!e) return NULL;

    char **args = (char**)realloc(NULL, sizeof(char*));
    size_t *arg_lens = (size_t*)realloc(NULL, sizeof(size_t));
    Bytecode *defaults = (Bytecode*)realloc(NULL, sizeof(Bytecode));
    uint8_t *has_default = (uint8_t*)realloc(NULL, sizeof(uint8_t));
    if (!args || !arg_lens || !defaults || !has_default) {
        parser_error(p, "out of memory");
        return NULL;
    }
    args[0] = name;
    arg_lens[0] = len;
    defaults[0].data = NULL;
    defaults[0].len = 0;
    defaults[0].cap = 0;
    has_default[0] = 0;

    Bytecode *body = (Bytecode*)arena_alloc(&p->arena, sizeof(Bytecode));
    if (!body) {
        parser_error(p, "out of memory");
        return NULL;
    }
    bc_init(body);
    if (!parse_block(p, body)) return NULL;

    if (!arena_track(&p->arena, args) || !arena_track(&p->arena, arg_lens) ||
        !arena_track(&p->arena, defaults) || !arena_track(&p->arena, has_default)) {
        parser_error(p, "out of memory");
        return NULL;
    }

    e->as.func.args = args;
    e->as.func.arg_lens = arg_lens;
    e->as.func.argc = 1;
    e->as.func.has_vararg = 0;
    e->as.func.defaults = defaults;
    e->as.func.has_default = has_default;
    e->as.func.bc = *body;
    return e;
}

static Expr *parse_postfix(Parser *p)
{
    Expr *expr = parse_primary(p);
    if (!expr) return NULL;

    for (;;) {
        if (match(p, TOK_DOT)) {
            if (p->current.kind != TOK_IDENT) {
                parser_error(p, "expected identifier after '.'");
                return NULL;
            }
            Expr *e = expr_new(p, EXPR_MEMBER);
            if (!e) return NULL;
            e->as.member.base = expr;
            e->as.member.name = arena_strndup(&p->arena, p->current.start, p->current.len);
            e->as.member.len = p->current.len;
            advance(p);
            expr = e;
            continue;
        }
        if (match(p, TOK_LBRACKET)) {
            Expr *index = parse_expr(p);
            if (!index) return NULL;
            if (!expect(p, TOK_RBRACKET, "expected ']'")) return NULL;
            Expr *e = expr_new(p, EXPR_INDEX);
            if (!e) return NULL;
            e->as.index.base = expr;
            e->as.index.index = index;
            expr = e;
            continue;
        }
        if (p->current.kind == TOK_BANG &&
            peek_kind(p, 1) == TOK_NUMBER &&
            peek_kind(p, 2) == TOK_LPAREN) {
            if (expr->kind != EXPR_NAME && expr->kind != EXPR_MEMBER) {
                parser_error(p, "call target must be a name or member");
                return NULL;
            }
            advance(p);
            Token number_tok = p->current;
            if (!match(p, TOK_NUMBER)) {
                parser_error(p, "expected number after '!'");
                return NULL;
            }
            char tmp[64];
            size_t nlen = number_tok.len < sizeof(tmp) - 1 ? number_tok.len : sizeof(tmp) - 1;
            memcpy(tmp, number_tok.start, nlen);
            tmp[nlen] = 0;
            char *endptr = NULL;
            long long override = strtoll(tmp, &endptr, 10);
            if (!tmp[0] || (endptr && *endptr != 0) || override < 0) {
                parser_error(p, "invalid call override length");
                return NULL;
            }
            if (!expect(p, TOK_LPAREN, "expected '(' after call override")) return NULL;
            Expr **args = NULL;
            int argc = 0;
            int cap = 0;
            if (p->current.kind != TOK_RPAREN) {
                for (;;) {
                    Expr *arg = parse_expr(p);
                    if (!arg) return NULL;
                    if (argc == cap) {
                        int next = cap == 0 ? 4 : cap * 2;
                        Expr **tmp_args = (Expr**)realloc(args, (size_t)next * sizeof(Expr*));
                        if (!tmp_args) {
                            parser_error(p, "out of memory");
                            return NULL;
                        }
                        args = tmp_args;
                        cap = next;
                    }
                    args[argc++] = arg;
                    if (match(p, TOK_COMMA)) continue;
                    break;
                }
            }
            if (!expect(p, TOK_RPAREN, "expected ')' after arguments")) return NULL;
            if (args && !arena_track(&p->arena, args)) {
                parser_error(p, "out of memory");
                return NULL;
            }
            Expr *call = expr_new(p, EXPR_CALL);
            if (!call) return NULL;
            call->as.call.callee = expr;
            call->as.call.args = args;
            call->as.call.argc = argc;
            call->as.call.has_override = 1;
            call->as.call.override_len = (Int)override;
            expr = call;
            continue;
        }
        if (match(p, TOK_LPAREN)) {
            if (expr->kind != EXPR_NAME && expr->kind != EXPR_MEMBER) {
                parser_error(p, "call target must be a name or member");
                return NULL;
            }
            Expr **args = NULL;
            int argc = 0;
            int cap = 0;
            if (p->current.kind != TOK_RPAREN) {
                for (;;) {
                    Expr *arg = parse_expr(p);
                    if (!arg) return NULL;
                    if (argc == cap) {
                        int next = cap == 0 ? 4 : cap * 2;
                        Expr **tmp = (Expr**)realloc(args, (size_t)next * sizeof(Expr*));
                        if (!tmp) {
                            parser_error(p, "out of memory");
                            return NULL;
                        }
                        args = tmp;
                        cap = next;
                    }
                    args[argc++] = arg;
                    if (match(p, TOK_COMMA)) continue;
                    break;
                }
            }
            if (!expect(p, TOK_RPAREN, "expected ')' after arguments")) return NULL;
            if (args && !arena_track(&p->arena, args)) {
                parser_error(p, "out of memory");
                return NULL;
            }
            Expr *call = expr_new(p, EXPR_CALL);
            if (!call) return NULL;
            call->as.call.callee = expr;
            call->as.call.args = args;
            call->as.call.argc = argc;
            call->as.call.has_override = 0;
            call->as.call.override_len = 0;
            expr = call;
            continue;
        }
        break;
    }

    if (p->current.kind == TOK_PLUSPLUS || p->current.kind == TOK_MINUSMINUS) {
        TokenKind op = p->current.kind;
        advance(p);
        if (!expr_is_lvalue(expr)) {
            parser_error(p, "left side is not assignable");
            return NULL;
        }
        Expr *e = expr_new(p, EXPR_UPDATE);
        if (!e) return NULL;
        e->as.update.op = op;
        e->as.update.target = expr;
        e->as.update.is_prefix = 0;
        expr = e;
    }

    return expr;
}

static Expr *parse_unary(Parser *p)
{
    if (p->current.kind == TOK_PLUSPLUS || p->current.kind == TOK_MINUSMINUS) {
        TokenKind op = p->current.kind;
        advance(p);
        Expr *target = parse_postfix(p);
        if (!target) return NULL;
        if (!expr_is_lvalue(target)) {
            parser_error(p, "left side is not assignable");
            return NULL;
        }
        Expr *e = expr_new(p, EXPR_UPDATE);
        if (!e) return NULL;
        e->as.update.op = op;
        e->as.update.target = target;
        e->as.update.is_prefix = 1;
        return e;
    }
    if (p->current.kind == TOK_BANG || p->current.kind == TOK_MINUS ||
        p->current.kind == TOK_TILDE) {
        TokenKind op = p->current.kind;
        advance(p);
        Expr *e = expr_new(p, EXPR_UNARY);
        if (!e) return NULL;
        e->as.unary.op = op;
        e->as.unary.expr = parse_unary(p);
        if (!e->as.unary.expr) return NULL;
        return e;
    }
    return parse_postfix(p);
}

static Expr *parse_factor(Parser *p)
{
    Expr *expr = parse_unary(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_STAR || p->current.kind == TOK_SLASH ||
           p->current.kind == TOK_PERCENT) {
        TokenKind op = p->current.kind;
        advance(p);
        Expr *right = parse_unary(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = op;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_term(Parser *p)
{
    Expr *expr = parse_factor(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_PLUS || p->current.kind == TOK_MINUS) {
        TokenKind op = p->current.kind;
        advance(p);
        Expr *right = parse_factor(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = op;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_shift(Parser *p)
{
    Expr *expr = parse_term(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_SHL || p->current.kind == TOK_SHR) {
        TokenKind op = p->current.kind;
        advance(p);
        Expr *right = parse_term(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = op;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_compare(Parser *p)
{
    Expr *expr = parse_shift(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_LT || p->current.kind == TOK_LTE ||
           p->current.kind == TOK_GT || p->current.kind == TOK_GTE) {
        TokenKind op = p->current.kind;
        advance(p);
        Expr *right = parse_shift(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = op;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_equality(Parser *p)
{
    Expr *expr = parse_compare(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_EQEQ ||
           p->current.kind == TOK_EQEQEQ ||
           p->current.kind == TOK_NEQ ||
           p->current.kind == TOK_SNEQ) {
        TokenKind op = p->current.kind;
        advance(p);
        Expr *right = parse_compare(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = op;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_bitand(Parser *p)
{
    Expr *expr = parse_equality(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_BITAND) {
        advance(p);
        Expr *right = parse_equality(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = TOK_BITAND;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_bitxor(Parser *p)
{
    Expr *expr = parse_bitand(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_BITXOR) {
        advance(p);
        Expr *right = parse_bitand(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = TOK_BITXOR;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_bitor(Parser *p)
{
    Expr *expr = parse_bitxor(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_BITOR) {
        advance(p);
        Expr *right = parse_bitxor(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = TOK_BITOR;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_and(Parser *p)
{
    Expr *expr = parse_bitor(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_AND) {
        advance(p);
        Expr *right = parse_bitor(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = TOK_AND;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_or(Parser *p)
{
    Expr *expr = parse_and(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_OR) {
        advance(p);
        Expr *right = parse_and(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_BINARY);
        if (!e) return NULL;
        e->as.binary.op = TOK_OR;
        e->as.binary.left = expr;
        e->as.binary.right = right;
        expr = e;
    }
    return expr;
}

static Expr *parse_assignment(Parser *p)
{
    Expr *left = parse_or(p);
    if (!left) return NULL;

    TokenKind op = TOK_EOF;
    if (match(p, TOK_EQ)) op = TOK_EQ;
    else if (match(p, TOK_PLUS_EQ)) op = TOK_PLUS_EQ;
    else if (match(p, TOK_MINUS_EQ)) op = TOK_MINUS_EQ;
    else if (match(p, TOK_STAR_EQ)) op = TOK_STAR_EQ;
    else if (match(p, TOK_SLASH_EQ)) op = TOK_SLASH_EQ;
    else if (match(p, TOK_PERCENT_EQ)) op = TOK_PERCENT_EQ;
    else if (match(p, TOK_BITAND_EQ)) op = TOK_BITAND_EQ;
    else if (match(p, TOK_BITOR_EQ)) op = TOK_BITOR_EQ;
    else if (match(p, TOK_BITXOR_EQ)) op = TOK_BITXOR_EQ;
    else if (match(p, TOK_SHL_EQ)) op = TOK_SHL_EQ;
    else if (match(p, TOK_SHR_EQ)) op = TOK_SHR_EQ;
    else if (match(p, TOK_QEQ)) op = TOK_QEQ;

    if (op != TOK_EOF) {
        if (!expr_is_lvalue(left)) {
            parser_error(p, "left side is not assignable");
            return NULL;
        }
        Expr *right = parse_assignment(p);
        if (!right) return NULL;
        Expr *e = expr_new(p, EXPR_ASSIGN);
        if (!e) return NULL;
        e->as.assign.op = op;
        e->as.assign.left = left;
        e->as.assign.right = right;
        return e;
    }
    return left;
}

static Expr *parse_expr(Parser *p)
{
    return parse_assignment(p);
}

static int expr_is_lvalue(const Expr *e)
{
    if (!e) return 0;
    if (e->kind == EXPR_NAME) return 1;
    if (e->kind == EXPR_MEMBER || e->kind == EXPR_INDEX) return 1;
    return 0;
}

static int emit_expr(Bytecode *bc, Parser *p, Expr *e);

static int emit_key(Bytecode *bc, Parser *p, const char *name, size_t len)
{
    if (!bc_emit_u8(bc, BC_PUSH_STRING) || !bc_emit_string(bc, name, len)) {
        parser_error(p, "failed to emit key string");
        return 0;
    }
    return 1;
}

static int emit_load_global_name(Bytecode *bc, Parser *p, const char *name, size_t len)
{
    if (!bc_emit_u8(bc, BC_LOAD_GLOBAL) || !bc_emit_string(bc, name, len)) {
        parser_error(p, "failed to emit LOAD_GLOBAL");
        return 0;
    }
    return 1;
}

static int emit_store_global_name(Bytecode *bc, Parser *p, const char *name, size_t len)
{
    if (!bc_emit_u8(bc, BC_STORE_GLOBAL) || !bc_emit_string(bc, name, len)) {
        parser_error(p, "failed to emit STORE_GLOBAL");
        return 0;
    }
    return 1;
}

static int is_global_name(const Expr *e);

static int emit_binary_op(Bytecode *bc, Parser *p, TokenKind op)
{
    uint8_t out = 0;
    switch (op) {
    case TOK_PLUS: out = BC_ADD; break;
    case TOK_MINUS: out = BC_SUB; break;
    case TOK_STAR: out = BC_MUL; break;
    case TOK_SLASH: out = BC_DIV; break;
    case TOK_PERCENT: out = BC_MOD; break;
    case TOK_BITAND: out = BC_BITAND; break;
    case TOK_BITOR: out = BC_BITOR; break;
    case TOK_BITXOR: out = BC_BITXOR; break;
    case TOK_SHL: out = BC_SHL; break;
    case TOK_SHR: out = BC_SHR; break;
    case TOK_EQEQ: out = BC_EQ; break;
    case TOK_EQEQEQ: out = BC_SEQ; break;
    case TOK_SNEQ: out = BC_SNEQ; break;
    case TOK_NEQ: out = BC_NEQ; break;
    case TOK_LT: out = BC_LT; break;
    case TOK_LTE: out = BC_LTE; break;
    case TOK_GT: out = BC_GT; break;
    case TOK_GTE: out = BC_GTE; break;
    case TOK_AND: out = BC_AND; break;
    case TOK_OR: out = BC_OR; break;
    default:
        parser_error(p, "unsupported binary operator");
        return 0;
    }
    if (!bc_emit_u8(bc, out)) {
        parser_error(p, "failed to emit binary op");
        return 0;
    }
    return 1;
}

static size_t emit_jump(Bytecode *bc, Parser *p, uint8_t op)
{
    if (!bc_emit_u8(bc, op)) {
        parser_error(p, "failed to emit jump");
        return 0;
    }
    size_t pos = bc->len;
    if (!bc_emit_u32(bc, 0)) {
        parser_error(p, "failed to emit jump target");
        return 0;
    }
    return pos;
}

static int patch_jump(Bytecode *bc, Parser *p, size_t pos, size_t target)
{
    if (target > 0xFFFFFFFFu) {
        parser_error(p, "jump target too large");
        return 0;
    }
    if (pos + 4 > bc->len) {
        parser_error(p, "invalid jump patch");
        return 0;
    }
    uint32_t v = (uint32_t)target;
    bc->data[pos] = (unsigned char)(v & 0xFF);
    bc->data[pos + 1] = (unsigned char)((v >> 8) & 0xFF);
    bc->data[pos + 2] = (unsigned char)((v >> 16) & 0xFF);
    bc->data[pos + 3] = (unsigned char)((v >> 24) & 0xFF);
    return 1;
}

static int is_global_member(const Expr *lhs, const char **name, size_t *len)
{
    if (!lhs || lhs->kind != EXPR_MEMBER) return 0;
    if (!is_global_name(lhs->as.member.base)) return 0;
    if (name) *name = lhs->as.member.name;
    if (len) *len = lhs->as.member.len;
    return 1;
}

static int emit_assign_expr(Bytecode *bc, Parser *p, Expr *lhs, TokenKind op, Expr *rhs)
{
    if (!lhs || !rhs) return 0;

    const char *name = NULL;
    size_t name_len = 0;
    if (lhs->kind == EXPR_NAME && !is_global_name(lhs)) {
        name = lhs->as.name.name;
        name_len = lhs->as.name.len;
    } else if (is_global_member(lhs, &name, &name_len)) {
        /* ok */
    }

    if (name) {
        TokenKind bin_op = TOK_EOF;
        if (op == TOK_PLUS_EQ) bin_op = TOK_PLUS;
        else if (op == TOK_MINUS_EQ) bin_op = TOK_MINUS;
        else if (op == TOK_STAR_EQ) bin_op = TOK_STAR;
        else if (op == TOK_SLASH_EQ) bin_op = TOK_SLASH;
        else if (op == TOK_PERCENT_EQ) bin_op = TOK_PERCENT;
        else if (op == TOK_BITAND_EQ) bin_op = TOK_BITAND;
        else if (op == TOK_BITOR_EQ) bin_op = TOK_BITOR;
        else if (op == TOK_BITXOR_EQ) bin_op = TOK_BITXOR;
        else if (op == TOK_SHL_EQ) bin_op = TOK_SHL;
        else if (op == TOK_SHR_EQ) bin_op = TOK_SHR;

        if (op == TOK_QEQ) {
            if (!emit_load_global_name(bc, p, name, name_len)) return 0;
            if (!emit_load_global_name(bc, p, "null", 4)) return 0;
            if (!bc_emit_u8(bc, BC_EQ)) {
                parser_error(p, "failed to emit default compare");
                return 0;
            }
            size_t jmp_skip = emit_jump(bc, p, BC_JMP_IF_FALSE);
            if (!jmp_skip) return 0;
            if (!emit_expr(bc, p, rhs)) return 0;
            if (!emit_store_global_name(bc, p, name, name_len)) return 0;
            if (!emit_load_global_name(bc, p, name, name_len)) return 0;
            size_t jmp_end = emit_jump(bc, p, BC_JMP);
            if (!jmp_end) return 0;
            if (!patch_jump(bc, p, jmp_skip, bc->len)) return 0;
            if (!emit_load_global_name(bc, p, name, name_len)) return 0;
            if (!patch_jump(bc, p, jmp_end, bc->len)) return 0;
            return 1;
        }

        if (op == TOK_EQ) {
            if (!emit_expr(bc, p, rhs)) return 0;
            if (!emit_store_global_name(bc, p, name, name_len)) return 0;
            if (!emit_load_global_name(bc, p, name, name_len)) return 0;
            return 1;
        }

        if (bin_op == TOK_EOF) {
            parser_error(p, "unsupported assignment operator");
            return 0;
        }
        if (!emit_load_global_name(bc, p, name, name_len)) return 0;
        if (!emit_expr(bc, p, rhs)) return 0;
        if (!emit_binary_op(bc, p, bin_op)) return 0;
        if (!emit_store_global_name(bc, p, name, name_len)) return 0;
        if (!emit_load_global_name(bc, p, name, name_len)) return 0;
        return 1;
    }

    if (lhs->kind != EXPR_MEMBER && lhs->kind != EXPR_INDEX) {
        parser_error(p, "invalid assignment target");
        return 0;
    }

    int id = p->temp_id++;
    char *value_name = arena_format_temp(&p->arena, "__assign_value_", id);
    if (!value_name) {
        parser_error(p, "out of memory");
        return 0;
    }

    TokenKind bin_op = TOK_EOF;
    if (op == TOK_PLUS_EQ) bin_op = TOK_PLUS;
    else if (op == TOK_MINUS_EQ) bin_op = TOK_MINUS;
    else if (op == TOK_STAR_EQ) bin_op = TOK_STAR;
    else if (op == TOK_SLASH_EQ) bin_op = TOK_SLASH;
    else if (op == TOK_PERCENT_EQ) bin_op = TOK_PERCENT;
    else if (op == TOK_BITAND_EQ) bin_op = TOK_BITAND;
    else if (op == TOK_BITOR_EQ) bin_op = TOK_BITOR;
    else if (op == TOK_BITXOR_EQ) bin_op = TOK_BITXOR;
    else if (op == TOK_SHL_EQ) bin_op = TOK_SHL;
    else if (op == TOK_SHR_EQ) bin_op = TOK_SHR;

    if (op == TOK_QEQ) {
        if (!emit_expr(bc, p, lhs->kind == EXPR_MEMBER ? lhs->as.member.base : lhs->as.index.base)) return 0;
        if (lhs->kind == EXPR_MEMBER) {
            if (!emit_key(bc, p, lhs->as.member.name, lhs->as.member.len)) return 0;
        } else {
            if (!emit_expr(bc, p, lhs->as.index.index)) return 0;
        }
        if (!bc_emit_u8(bc, BC_INDEX)) {
            parser_error(p, "failed to emit INDEX");
            return 0;
        }
        if (!emit_load_global_name(bc, p, "null", 4)) return 0;
        if (!bc_emit_u8(bc, BC_EQ)) {
            parser_error(p, "failed to emit default compare");
            return 0;
        }
        size_t jmp_skip = emit_jump(bc, p, BC_JMP_IF_FALSE);
        if (!jmp_skip) return 0;
        if (!emit_expr(bc, p, rhs)) return 0;
        if (!emit_store_global_name(bc, p, value_name, strlen(value_name))) return 0;
        if (!emit_expr(bc, p, lhs->kind == EXPR_MEMBER ? lhs->as.member.base : lhs->as.index.base)) return 0;
        if (lhs->kind == EXPR_MEMBER) {
            if (!emit_key(bc, p, lhs->as.member.name, lhs->as.member.len)) return 0;
        } else {
            if (!emit_expr(bc, p, lhs->as.index.index)) return 0;
        }
        if (!emit_load_global_name(bc, p, value_name, strlen(value_name))) return 0;
        if (!bc_emit_u8(bc, BC_STORE_INDEX)) {
            parser_error(p, "failed to emit STORE_INDEX");
            return 0;
        }
        if (!emit_load_global_name(bc, p, value_name, strlen(value_name))) return 0;
        size_t jmp_end = emit_jump(bc, p, BC_JMP);
        if (!jmp_end) return 0;
        if (!patch_jump(bc, p, jmp_skip, bc->len)) return 0;
        if (!emit_expr(bc, p, lhs->kind == EXPR_MEMBER ? lhs->as.member.base : lhs->as.index.base)) return 0;
        if (lhs->kind == EXPR_MEMBER) {
            if (!emit_key(bc, p, lhs->as.member.name, lhs->as.member.len)) return 0;
        } else {
            if (!emit_expr(bc, p, lhs->as.index.index)) return 0;
        }
        if (!bc_emit_u8(bc, BC_INDEX)) {
            parser_error(p, "failed to emit INDEX");
            return 0;
        }
        if (!patch_jump(bc, p, jmp_end, bc->len)) return 0;
        return 1;
    }

    if (op == TOK_EQ) {
        if (!emit_expr(bc, p, rhs)) return 0;
        if (!emit_store_global_name(bc, p, value_name, strlen(value_name))) return 0;
        if (!emit_expr(bc, p, lhs->kind == EXPR_MEMBER ? lhs->as.member.base : lhs->as.index.base)) return 0;
        if (lhs->kind == EXPR_MEMBER) {
            if (!emit_key(bc, p, lhs->as.member.name, lhs->as.member.len)) return 0;
        } else {
            if (!emit_expr(bc, p, lhs->as.index.index)) return 0;
        }
        if (!emit_load_global_name(bc, p, value_name, strlen(value_name))) return 0;
        if (!bc_emit_u8(bc, BC_STORE_INDEX)) {
            parser_error(p, "failed to emit STORE_INDEX");
            return 0;
        }
        if (!emit_load_global_name(bc, p, value_name, strlen(value_name))) return 0;
        return 1;
    }

    if (bin_op == TOK_EOF) {
        parser_error(p, "unsupported assignment operator");
        return 0;
    }
    if (!emit_expr(bc, p, lhs->kind == EXPR_MEMBER ? lhs->as.member.base : lhs->as.index.base)) return 0;
    if (lhs->kind == EXPR_MEMBER) {
        if (!emit_key(bc, p, lhs->as.member.name, lhs->as.member.len)) return 0;
    } else {
        if (!emit_expr(bc, p, lhs->as.index.index)) return 0;
    }
    if (!bc_emit_u8(bc, BC_INDEX)) {
        parser_error(p, "failed to emit INDEX");
        return 0;
    }
    if (!emit_expr(bc, p, rhs)) return 0;
    if (!emit_binary_op(bc, p, bin_op)) return 0;
    if (!emit_store_global_name(bc, p, value_name, strlen(value_name))) return 0;
    if (!emit_expr(bc, p, lhs->kind == EXPR_MEMBER ? lhs->as.member.base : lhs->as.index.base)) return 0;
    if (lhs->kind == EXPR_MEMBER) {
        if (!emit_key(bc, p, lhs->as.member.name, lhs->as.member.len)) return 0;
    } else {
        if (!emit_expr(bc, p, lhs->as.index.index)) return 0;
    }
    if (!emit_load_global_name(bc, p, value_name, strlen(value_name))) return 0;
    if (!bc_emit_u8(bc, BC_STORE_INDEX)) {
        parser_error(p, "failed to emit STORE_INDEX");
        return 0;
    }
    if (!emit_load_global_name(bc, p, value_name, strlen(value_name))) return 0;
    return 1;
}

static int emit_update_expr(Bytecode *bc, Parser *p, Expr *target, TokenKind op, int is_prefix)
{
    if (!target) return 0;

    const char *name = NULL;
    size_t name_len = 0;
    if (target->kind == EXPR_NAME && !is_global_name(target)) {
        name = target->as.name.name;
        name_len = target->as.name.len;
    } else if (is_global_member(target, &name, &name_len)) {
        /* ok */
    }

    TokenKind bin_op = op == TOK_PLUSPLUS ? TOK_PLUS : TOK_MINUS;

    if (name) {
        if (!emit_load_global_name(bc, p, name, name_len)) return 0;
        if (is_prefix) {
            if (!bc_emit_u8(bc, BC_PUSH_INT) || !bc_emit_i64(bc, 1)) {
                parser_error(p, "failed to emit number literal");
                return 0;
            }
            if (!emit_binary_op(bc, p, bin_op)) return 0;
            if (!emit_store_global_name(bc, p, name, name_len)) return 0;
            if (!emit_load_global_name(bc, p, name, name_len)) return 0;
            return 1;
        }
        int id = p->temp_id++;
        char *old_name = arena_format_temp(&p->arena, "__update_old_", id);
        if (!old_name) {
            parser_error(p, "out of memory");
            return 0;
        }
        if (!bc_emit_u8(bc, BC_DUP)) {
            parser_error(p, "failed to emit DUP");
            return 0;
        }
        if (!emit_store_global_name(bc, p, old_name, strlen(old_name))) return 0;
        if (!bc_emit_u8(bc, BC_PUSH_INT) || !bc_emit_i64(bc, 1)) {
            parser_error(p, "failed to emit number literal");
            return 0;
        }
        if (!emit_binary_op(bc, p, bin_op)) return 0;
        if (!emit_store_global_name(bc, p, name, name_len)) return 0;
        if (!emit_load_global_name(bc, p, old_name, strlen(old_name))) return 0;
        return 1;
    }

    if (target->kind != EXPR_MEMBER && target->kind != EXPR_INDEX) {
        parser_error(p, "invalid assignment target");
        return 0;
    }

    int id = p->temp_id++;
    char *value_name = arena_format_temp(&p->arena, "__update_value_", id);
    char *old_name = arena_format_temp(&p->arena, "__update_old_", id);
    if (!value_name || !old_name) {
        parser_error(p, "out of memory");
        return 0;
    }

    Expr *base = target->kind == EXPR_MEMBER ? target->as.member.base : target->as.index.base;
    if (!emit_expr(bc, p, base)) return 0;
    if (target->kind == EXPR_MEMBER) {
        if (!emit_key(bc, p, target->as.member.name, target->as.member.len)) return 0;
    } else {
        if (!emit_expr(bc, p, target->as.index.index)) return 0;
    }
    if (!bc_emit_u8(bc, BC_INDEX)) {
        parser_error(p, "failed to emit INDEX");
        return 0;
    }

    if (!bc_emit_u8(bc, BC_DUP)) {
        parser_error(p, "failed to emit DUP");
        return 0;
    }
    if (!emit_store_global_name(bc, p, old_name, strlen(old_name))) return 0;
    if (!emit_load_global_name(bc, p, old_name, strlen(old_name))) return 0;
    if (!bc_emit_u8(bc, BC_PUSH_INT) || !bc_emit_i64(bc, 1)) {
        parser_error(p, "failed to emit int literal");
        return 0;
    }
    if (!emit_binary_op(bc, p, bin_op)) return 0;
    if (!emit_store_global_name(bc, p, value_name, strlen(value_name))) return 0;
    if (!emit_expr(bc, p, base)) return 0;
    if (target->kind == EXPR_MEMBER) {
        if (!emit_key(bc, p, target->as.member.name, target->as.member.len)) return 0;
    } else {
        if (!emit_expr(bc, p, target->as.index.index)) return 0;
    }
    if (!emit_load_global_name(bc, p, value_name, strlen(value_name))) return 0;
    if (!bc_emit_u8(bc, BC_STORE_INDEX)) {
        parser_error(p, "failed to emit STORE_INDEX");
        return 0;
    }

    if (is_prefix) {
        if (!emit_load_global_name(bc, p, value_name, strlen(value_name))) return 0;
    } else {
        if (!emit_load_global_name(bc, p, old_name, strlen(old_name))) return 0;
    }
    return 1;
}

static char *arena_format_temp(Arena *a, const char *prefix, int id)
{
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%s%d", prefix, id);
    if (len < 0) return NULL;
    char *out = (char*)arena_alloc(a, (size_t)len + 1);
    if (!out) return NULL;
    memcpy(out, buf, (size_t)len + 1);
    return out;
}

static int literal_needs_papagaio(const char *s, size_t len)
{
    if (!s || len == 0) return 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '$' || s[i] == PAPAGAIO_ESCAPED_SIGIL) return 1;
    }
    return 0;
}

static int emit_expr(Bytecode *bc, Parser *p, Expr *e)
{
    if (!e) return 0;
    switch (e->kind) {
    case EXPR_LITERAL_NUM:
        if (e->as.lit_num.is_float) {
            if (!bc_emit_u8(bc, BC_PUSH_FLOAT) || !bc_emit_f64(bc, e->as.lit_num.number)) {
                parser_error(p, "failed to emit float literal");
                return 0;
            }
        } else {
            if (!bc_emit_u8(bc, BC_PUSH_INT) || !bc_emit_i64(bc, (int64_t)e->as.lit_num.number)) {
                parser_error(p, "failed to emit int literal");
                return 0;
            }
        }
        return 1;
    case EXPR_LITERAL_STRING:
        {
            uint8_t op = literal_needs_papagaio(e->as.lit_str.data, e->as.lit_str.len)
                ? BC_PUSH_STRING
                : BC_PUSH_STRING_RAW;
            if (!bc_emit_u8(bc, op) ||
                !bc_emit_string(bc, e->as.lit_str.data, e->as.lit_str.len)) {
                parser_error(p, "failed to emit string literal");
                return 0;
            }
        }
        return 1;
    case EXPR_LITERAL_CHAR:
        {
            uint8_t op = literal_needs_papagaio(e->as.lit_str.data, e->as.lit_str.len)
                ? BC_PUSH_CHAR
                : BC_PUSH_CHAR_RAW;
            if (!bc_emit_u8(bc, op) ||
                !bc_emit_string(bc, e->as.lit_str.data, e->as.lit_str.len)) {
                parser_error(p, "failed to emit char literal");
                return 0;
            }
        }
        return 1;
    case EXPR_NAME:
        if (e->as.name.len == 4 && strncmp(e->as.name.name, "this", 4) == 0) {
            if (!bc_emit_u8(bc, BC_LOAD_THIS)) {
                parser_error(p, "failed to emit LOAD_THIS");
                return 0;
            }
            return 1;
        }
        if (e->as.name.len == 6 && strncmp(e->as.name.name, "global", 6) == 0) {
            if (!bc_emit_u8(bc, BC_LOAD_ROOT)) {
                parser_error(p, "failed to emit LOAD_ROOT");
                return 0;
            }
            return 1;
        }
        if (!bc_emit_u8(bc, BC_LOAD_GLOBAL) || !bc_emit_string(bc, e->as.name.name, e->as.name.len)) {
            parser_error(p, "failed to emit LOAD_GLOBAL");
            return 0;
        }
        return 1;
    case EXPR_MEMBER:
        if (!emit_expr(bc, p, e->as.member.base)) return 0;
        if (!emit_key(bc, p, e->as.member.name, e->as.member.len)) return 0;
        if (!bc_emit_u8(bc, BC_INDEX)) {
            parser_error(p, "failed to emit INDEX");
            return 0;
        }
        return 1;
    case EXPR_INDEX:
        if (!emit_expr(bc, p, e->as.index.base)) return 0;
        if (!emit_expr(bc, p, e->as.index.index)) return 0;
        if (!bc_emit_u8(bc, BC_INDEX)) {
            parser_error(p, "failed to emit INDEX");
            return 0;
        }
        return 1;
    case EXPR_CAST_LIST: {
        int count = e->as.cast_list.count;
        int all_literal = 1;
        for (int i = 0; i < count; i++) {
            if (e->as.cast_list.items[i]->kind != EXPR_LITERAL_NUM) {
                all_literal = 0;
                break;
            }
        }
        if (all_literal) {
            uint8_t op = e->as.cast_list.items[0]->as.lit_num.is_float ? BC_BUILD_FLOAT_LIT : BC_BUILD_INT_LIT;
            for (int i = 1; i < count; i++) {
                if (e->as.cast_list.items[i]->as.lit_num.is_float) {
                    op = BC_BUILD_FLOAT_LIT;
                    break;
                }
            }
            if (!bc_emit_u8(bc, op) || !bc_emit_u32(bc, (uint32_t)count)) {
                parser_error(p, "failed to emit BUILD_*_LIT");
                return 0;
            }
            for (int i = 0; i < count; i++) {
                double v = e->as.cast_list.items[i]->as.lit_num.number;
                if (op == BC_BUILD_FLOAT_LIT) {
                    if (!bc_emit_f64(bc, v)) {
                        parser_error(p, "failed to emit BUILD_FLOAT_LIT value");
                        return 0;
                    }
                } else {
                    if (!bc_emit_i64(bc, (int64_t)v)) {
                        parser_error(p, "failed to emit BUILD_INT_LIT value");
                        return 0;
                    }
                }
            }
            return 1;
        }

        for (int i = 0; i < count; i++) {
            if (!emit_expr(bc, p, e->as.cast_list.items[i])) return 0;
        }
        uint8_t op = BC_BUILD_INT;
        for (int i = 0; i < count; i++) {
            if (e->as.cast_list.items[i]->kind == EXPR_LITERAL_NUM &&
                e->as.cast_list.items[i]->as.lit_num.is_float) {
                op = BC_BUILD_FLOAT;
                break;
            }
        }
        if (!bc_emit_u8(bc, op) || !bc_emit_u32(bc, (uint32_t)count)) {
            parser_error(p, "failed to emit BUILD_*");
            return 0;
        }
        return 1;
    }
    case EXPR_LITERAL_NUMBER_LIST: {
        int count = e->as.num_list.count;
        uint8_t op = e->as.num_list.is_float ? BC_BUILD_FLOAT_LIT : BC_BUILD_INT_LIT;
        if (!bc_emit_u8(bc, op) || !bc_emit_u32(bc, (uint32_t)count)) {
            parser_error(p, "failed to emit BUILD_*_LIT");
            return 0;
        }
        for (int i = 0; i < count; i++) {
            if (op == BC_BUILD_FLOAT_LIT) {
                if (!bc_emit_f64(bc, e->as.num_list.items[i])) {
                    parser_error(p, "failed to emit BUILD_FLOAT_LIT value");
                    return 0;
                }
            } else {
                if (!bc_emit_i64(bc, (int64_t)e->as.num_list.items[i])) {
                    parser_error(p, "failed to emit BUILD_INT_LIT value");
                    return 0;
                }
            }
        }
        return 1;
    }
    case EXPR_OBJECT_LITERAL: {
        int count = e->as.obj.count;
        for (int i = 0; i < count; i++) {
            if (!emit_key(bc, p, e->as.obj.pairs[i].name, e->as.obj.pairs[i].name_len)) return 0;
            if (!emit_expr(bc, p, e->as.obj.pairs[i].value)) return 0;
        }
        if (!bc_emit_u8(bc, BC_BUILD_OBJECT) || !bc_emit_u32(bc, (uint32_t)count)) {
            parser_error(p, "failed to emit BUILD_OBJECT");
            return 0;
        }
        return 1;
    }
    case EXPR_UNARY: {
        if (!emit_expr(bc, p, e->as.unary.expr)) return 0;
        uint8_t op = BC_NOT;
        if (e->as.unary.op == TOK_MINUS) op = BC_NEG;
        else if (e->as.unary.op == TOK_TILDE) op = BC_BNOT;
        if (!bc_emit_u8(bc, op)) {
            parser_error(p, "failed to emit unary op");
            return 0;
        }
        return 1;
    }
    case EXPR_BINARY: {
        if (!emit_expr(bc, p, e->as.binary.left)) return 0;
        if (!emit_expr(bc, p, e->as.binary.right)) return 0;
        return emit_binary_op(bc, p, e->as.binary.op);
    }
    case EXPR_ASSIGN:
        return emit_assign_expr(bc, p, e->as.assign.left, e->as.assign.op, e->as.assign.right);
    case EXPR_UPDATE:
        return emit_update_expr(bc, p, e->as.update.target, e->as.update.op, e->as.update.is_prefix);
    case EXPR_CALL: {
        uint32_t argc = 0;
        for (int i = 0; i < e->as.call.argc; i++) {
            if (!emit_expr(bc, p, e->as.call.args[i])) return 0;
            argc++;
        }
        Expr *callee = e->as.call.callee;
        if (callee->kind == EXPR_NAME) {
            if (!bc_emit_u8(bc, BC_LOAD_GLOBAL) ||
                !bc_emit_string(bc, callee->as.name.name, callee->as.name.len)) {
                parser_error(p, "failed to load call target");
                return 0;
            }
            if (!bc_emit_u8(bc, BC_SET_THIS)) {
                parser_error(p, "failed to set this");
                return 0;
            }
        } else if (callee->kind == EXPR_MEMBER) {
            if (!emit_expr(bc, p, callee->as.member.base)) return 0;
            if (!bc_emit_u8(bc, BC_SET_THIS)) {
                parser_error(p, "failed to set this");
                return 0;
            }
        } else {
            parser_error(p, "call target must be a name or member");
            return 0;
        }
        const char *name = callee->kind == EXPR_NAME ? callee->as.name.name : callee->as.member.name;
        size_t len = callee->kind == EXPR_NAME ? callee->as.name.len : callee->as.member.len;
        if (e->as.call.has_override) {
            if (!bc_emit_u8(bc, BC_CALL_EX) ||
                !bc_emit_string(bc, name, len) ||
                !bc_emit_u32(bc, argc) ||
                !bc_emit_u32(bc, (uint32_t)e->as.call.override_len)) {
                parser_error(p, "failed to emit CALL_EX");
                return 0;
            }
        } else {
            if (!bc_emit_u8(bc, BC_CALL) ||
                !bc_emit_string(bc, name, len) ||
                !bc_emit_u32(bc, argc)) {
                parser_error(p, "failed to emit CALL");
                return 0;
            }
        }
        return 1;
    }
    case EXPR_FUNC_LITERAL: {
        Bytecode *body = &e->as.func.bc;
        if (body->len > 0xFFFFFFFFu) {
            parser_error(p, "function bytecode too large");
            return 0;
        }
        if (!bc_emit_u8(bc, BC_BUILD_FUNCTION) ||
            !bc_emit_u32(bc, (uint32_t)e->as.func.argc) ||
            !bc_emit_u32(bc, (uint32_t)(e->as.func.has_vararg ? 1 : 0)) ||
            !bc_emit_u32(bc, (uint32_t)body->len) ||
            !bc_emit_bytes(bc, body->data, body->len)) {
            parser_error(p, "failed to emit BUILD_FUNCTION");
            return 0;
        }
        for (int i = 0; i < e->as.func.argc; i++) {
            if (!bc_emit_string(bc, e->as.func.args[i], e->as.func.arg_lens[i])) {
                parser_error(p, "failed to emit function arg name");
                return 0;
            }
            uint32_t def_len = 0;
            if (e->as.func.has_default && e->as.func.has_default[i]) {
                Bytecode *def_bc = &e->as.func.defaults[i];
                if (def_bc->len > 0xFFFFFFFFu) {
                    parser_error(p, "default bytecode too large");
                    return 0;
                }
                def_len = (uint32_t)def_bc->len;
            }
            if (!bc_emit_u32(bc, def_len)) {
                parser_error(p, "failed to emit default length");
                return 0;
            }
            if (def_len) {
                Bytecode *def_bc = &e->as.func.defaults[i];
                if (!bc_emit_bytes(bc, def_bc->data, def_bc->len)) {
                    parser_error(p, "failed to emit default bytecode");
                    return 0;
                }
            }
        }
        bc_free(body);
        body->data = NULL;
        body->len = 0;
        body->cap = 0;
        if (e->as.func.has_default && e->as.func.defaults) {
            for (int i = 0; i < e->as.func.argc; i++) {
                if (e->as.func.has_default[i]) {
                    bc_free(&e->as.func.defaults[i]);
                }
                e->as.func.defaults[i].data = NULL;
                e->as.func.defaults[i].len = 0;
                e->as.func.defaults[i].cap = 0;
            }
        }
        return 1;
    }
    default:
        parser_error(p, "unsupported expression");
        return 0;
    }
}

static int is_global_name(const Expr *e)
{
    return e && e->kind == EXPR_NAME && e->as.name.len == 6 && strncmp(e->as.name.name, "global", 6) == 0;
}

static int emit_loop_break(Parser *p, Bytecode *bc)
{
    if (!loop_current(p)) {
        parser_error(p, "break outside loop");
        return 0;
    }
    size_t pos = emit_jump(bc, p, BC_JMP);
    if (!pos) return 0;
    if (!loop_add_break(p, pos)) {
        parser_error(p, "out of memory");
        return 0;
    }
    return 1;
}

static int emit_loop_continue(Parser *p, Bytecode *bc)
{
    LoopContext *ctx = loop_current(p);
    if (!ctx || !ctx->allow_continue) {
        parser_error(p, "continue outside loop");
        return 0;
    }
    size_t pos = emit_jump(bc, p, BC_JMP);
    if (!pos) return 0;
    if (!loop_add_continue(p, pos)) {
        parser_error(p, "out of memory");
        return 0;
    }
    return 1;
}

static int parse_simple_statement(Parser *p, Bytecode *bc, int require_sep)
{
    Expr *expr = parse_expr(p);
    if (!expr) return 0;
    if (require_sep) {
        /* comma normally terminates a statement; but if we're at the end of a
           block or end-of-file, the final comma is optional. */
        if (p->current.kind == TOK_COMMA) {
            advance(p);
        } else if (p->current.kind != TOK_RBRACE && p->current.kind != TOK_EOF) {
            parser_error(p, "expected ',' after statement");
            return 0;
        }
    }
    if (!emit_expr(bc, p, expr)) return 0;
    if (!bc_emit_u8(bc, BC_POP)) {
        parser_error(p, "failed to emit POP");
        return 0;
    }
    return 1;
}

static int parse_switch_case(Parser *p, Bytecode *bc, const char *tmp_name, size_t tmp_len)
{
    Expr *case_expr = parse_expr(p);
    if (!case_expr) return 0;
    if (!expect(p, TOK_COLON, "expected ':' after case")) return 0;

    if (!emit_load_global_name(bc, p, tmp_name, tmp_len)) return 0;
    if (!emit_expr(bc, p, case_expr)) return 0;
    if (!bc_emit_u8(bc, BC_EQ)) {
        parser_error(p, "failed to emit EQ for switch case");
        return 0;
    }
    size_t skip_case = emit_jump(bc, p, BC_JMP_IF_FALSE);
    if (!skip_case) return 0;

    while (p->current.kind != TOK_CASE && p->current.kind != TOK_DEFAULT &&
           p->current.kind != TOK_RBRACE) {
        if (!parse_statement(p, bc)) return 0;
    }

    if (!emit_loop_break(p, bc)) return 0;
    if (!patch_jump(bc, p, skip_case, bc->len)) return 0;
    return 1;
}

static int parse_switch_statement(Parser *p, Bytecode *bc)
{
    int has_parens = (p->current.kind == TOK_LPAREN);
    if (has_parens && !expect(p, TOK_LPAREN, "expected '(' after switch")) return 0;
    Expr *selector = parse_expr(p);
    if (!selector) return 0;
    if (has_parens && !expect(p, TOK_RPAREN, "expected ')' after switch expression")) return 0;
    if (!expect(p, TOK_LBRACE, "expected '{' to start switch")) return 0;

    int id = p->temp_id++;
    char *tmp_name = arena_format_temp(&p->arena, "__switch_val_", id);
    if (!tmp_name) {
        parser_error(p, "out of memory");
        return 0;
    }
    size_t tmp_len = strlen(tmp_name);

    if (!emit_expr(bc, p, selector)) return 0;
    if (!emit_store_global_name(bc, p, tmp_name, tmp_len)) return 0;

    if (!loop_push(p, 0)) {
        parser_error(p, "out of memory");
        return 0;
    }

    int seen_default = 0;
    while (p->current.kind != TOK_RBRACE) {
        if (match(p, TOK_CASE)) {
            if (seen_default) {
                parser_error(p, "case after default in switch");
                return 0;
            }
            if (!parse_switch_case(p, bc, tmp_name, tmp_len)) return 0;
            continue;
        }
        if (match(p, TOK_DEFAULT)) {
            if (seen_default) {
                parser_error(p, "multiple default cases in switch");
                return 0;
            }
            seen_default = 1;
            if (!expect(p, TOK_COLON, "expected ':' after default")) return 0;
            while (p->current.kind != TOK_RBRACE) {
                if (!parse_statement(p, bc)) return 0;
            }
            if (!emit_loop_break(p, bc)) return 0;
            continue;
        }
        parser_error(p, "expected case or default in switch");
        return 0;
    }

    if (!expect(p, TOK_RBRACE, "expected '}' after switch")) return 0;

    LoopContext *ctx = loop_current(p);
    size_t cleanup_pos = bc->len;
    if (ctx) {
        for (int i = 0; i < ctx->break_count; i++) {
            if (!patch_jump(bc, p, ctx->breaks[i], cleanup_pos)) { loop_pop(p); return 0; }
        }
    }
    loop_pop(p);

    if (!emit_load_global_name(bc, p, "null", 4)) return 0;
    if (!emit_store_global_name(bc, p, tmp_name, tmp_len)) return 0;
    return 1;
}

static int parse_if_statement(Parser *p, Bytecode *bc)
{
    int has_parens = (p->current.kind == TOK_LPAREN);
    if (has_parens && !expect(p, TOK_LPAREN, "expected '(' after if")) return 0;
    Expr *cond = parse_expr(p);
    if (!cond) return 0;
    if (has_parens && !expect(p, TOK_RPAREN, "expected ')' after condition")) return 0;
    if (!emit_expr(bc, p, cond)) return 0;

    size_t jmp_false = emit_jump(bc, p, BC_JMP_IF_FALSE);
    if (!jmp_false) return 0;
    if (!parse_block(p, bc)) return 0;

    if (match(p, TOK_ELSE)) {
        size_t jmp_end = emit_jump(bc, p, BC_JMP);
        if (!jmp_end) return 0;
        if (!patch_jump(bc, p, jmp_false, bc->len)) return 0;
        if (match(p, TOK_IF)) {
            if (!parse_if_statement(p, bc)) return 0;
        } else {
            if (!parse_block(p, bc)) return 0;
        }
        if (!patch_jump(bc, p, jmp_end, bc->len)) return 0;
    } else {
        if (!patch_jump(bc, p, jmp_false, bc->len)) return 0;
    }

    return 1;
}

static int parse_while_statement(Parser *p, Bytecode *bc)
{
    int has_parens = (p->current.kind == TOK_LPAREN);
    if (has_parens && !expect(p, TOK_LPAREN, "expected '(' after while")) return 0;
    if (!loop_push(p, 1)) {
        parser_error(p, "out of memory");
        return 0;
    }
    size_t loop_start = bc->len;
    Expr *cond = parse_expr(p);
    if (!cond) { loop_pop(p); return 0; }
    if (has_parens && !expect(p, TOK_RPAREN, "expected ')' after condition")) { loop_pop(p); return 0; }
    if (!emit_expr(bc, p, cond)) { loop_pop(p); return 0; }
    size_t jmp_out = emit_jump(bc, p, BC_JMP_IF_FALSE);
    if (!jmp_out) { loop_pop(p); return 0; }
    LoopContext *ctx = loop_current(p);
    if (ctx) {
        ctx->continue_target = loop_start;
        ctx->has_continue_target = 1;
    }
    if (!parse_block(p, bc)) { loop_pop(p); return 0; }
    if (ctx && ctx->has_continue_target) {
        for (int i = 0; i < ctx->cont_count; i++) {
            if (!patch_jump(bc, p, ctx->continues[i], ctx->continue_target)) { loop_pop(p); return 0; }
        }
    }
    if (!bc_emit_u8(bc, BC_JMP) || !bc_emit_u32(bc, (uint32_t)loop_start)) {
        parser_error(p, "failed to emit loop jump");
        loop_pop(p);
        return 0;
    }
    if (!patch_jump(bc, p, jmp_out, bc->len)) { loop_pop(p); return 0; }
    if (ctx) {
        size_t break_target = bc->len;
        for (int i = 0; i < ctx->break_count; i++) {
            if (!patch_jump(bc, p, ctx->breaks[i], break_target)) { loop_pop(p); return 0; }
        }
    }
    loop_pop(p);
    return 1;
}

static int parse_for_statement(Parser *p, Bytecode *bc)
{
    int has_parens = (p->current.kind == TOK_LPAREN);
    if (has_parens && !expect(p, TOK_LPAREN, "expected '(' after for")) return 0;
    if (!loop_push(p, 1)) {
        parser_error(p, "out of memory");
        return 0;
    }

    if (p->current.kind != TOK_COMMA) {
        if (!parse_simple_statement(p, bc, 0)) { loop_pop(p); return 0; }
    }
    if (!expect(p, TOK_COMMA, "expected ',' after for init")) { loop_pop(p); return 0; }

    size_t loop_start = bc->len;
    int has_cond = 0;
    size_t jmp_out = 0;
    if (p->current.kind != TOK_COMMA) {
        Expr *cond = parse_expr(p);
        if (!cond) { loop_pop(p); return 0; }
        if (!emit_expr(bc, p, cond)) { loop_pop(p); return 0; }
        jmp_out = emit_jump(bc, p, BC_JMP_IF_FALSE);
        if (!jmp_out) { loop_pop(p); return 0; }
        has_cond = 1;
    }
    if (!expect(p, TOK_COMMA, "expected ',' after for condition")) { loop_pop(p); return 0; }

    Bytecode step;
    bc_init(&step);
    if (p->current.kind != (has_parens ? TOK_RPAREN : TOK_LBRACE)) {
        if (!parse_simple_statement(p, &step, 0)) {
            bc_free(&step);
            loop_pop(p);
            return 0;
        }
    }
    if (has_parens && !expect(p, TOK_RPAREN, "expected ')' after for clauses")) {
        bc_free(&step);
        loop_pop(p);
        return 0;
    }

    if (!parse_block(p, bc)) {
        bc_free(&step);
        loop_pop(p);
        return 0;
    }

    LoopContext *ctx = loop_current(p);
    size_t step_start = bc->len;
    if (ctx) {
        ctx->continue_target = step_start;
        ctx->has_continue_target = 1;
        for (int i = 0; i < ctx->cont_count; i++) {
            if (!patch_jump(bc, p, ctx->continues[i], ctx->continue_target)) { loop_pop(p); return 0; }
        }
    }
    if (step.len > 0 && !bc_emit_bytes(bc, step.data, step.len)) {
        parser_error(p, "failed to emit for step");
        bc_free(&step);
        loop_pop(p);
        return 0;
    }
    bc_free(&step);

    if (!bc_emit_u8(bc, BC_JMP) || !bc_emit_u32(bc, (uint32_t)loop_start)) {
        parser_error(p, "failed to emit for loop jump");
        loop_pop(p);
        return 0;
    }
    if (has_cond && !patch_jump(bc, p, jmp_out, bc->len)) { loop_pop(p); return 0; }
    if (ctx) {
        size_t break_target = bc->len;
        for (int i = 0; i < ctx->break_count; i++) {
            if (!patch_jump(bc, p, ctx->breaks[i], break_target)) { loop_pop(p); return 0; }
        }
    }
    loop_pop(p);
    return 1;
}

static int parse_each_statement(Parser *p, Bytecode *bc)
{
    int has_parens = (p->current.kind == TOK_LPAREN);
    if (has_parens && !expect(p, TOK_LPAREN, "expected '(' after each")) return 0;
    if (!loop_push(p, 1)) {
        parser_error(p, "out of memory");
        return 0;
    }
    if (p->current.kind != TOK_IDENT) {
        parser_error(p, "expected identifier after each(");
        loop_pop(p);
        return 0;
    }
    char *value_name = arena_strndup(&p->arena, p->current.start, p->current.len);
    size_t value_len = p->current.len;
    advance(p);
    if (!expect(p, TOK_IN, "expected 'in' after each value")) { loop_pop(p); return 0; }

    Expr *iter = parse_expr(p);
    if (!iter) { loop_pop(p); return 0; }
    if (has_parens && !expect(p, TOK_RPAREN, "expected ')' after each expression")) { loop_pop(p); return 0; }

    int id = p->temp_id++;
    char *iter_name = arena_format_temp(&p->arena, "__each_iter_", id);
    char *len_name = arena_format_temp(&p->arena, "__each_len_", id);
    char *idx_name = arena_format_temp(&p->arena, "__each_idx_", id);
    if (!iter_name || !len_name || !idx_name) {
        parser_error(p, "out of memory");
        return 0;
    }
    size_t iter_len = strlen(iter_name);
    size_t len_len = strlen(len_name);
    size_t idx_len = strlen(idx_name);

    if (!emit_expr(bc, p, iter)) { loop_pop(p); return 0; }
    if (!emit_store_global_name(bc, p, iter_name, iter_len)) { loop_pop(p); return 0; }

    if (!bc_emit_u8(bc, BC_PUSH_INT) || !bc_emit_i64(bc, 0)) {
        parser_error(p, "failed to emit each index");
        loop_pop(p);
        return 0;
    }
    if (!emit_store_global_name(bc, p, idx_name, idx_len)) { loop_pop(p); return 0; }

    if (!emit_load_global_name(bc, p, iter_name, iter_len)) { loop_pop(p); return 0; }
    if (!bc_emit_u8(bc, BC_SET_THIS)) {
        parser_error(p, "failed to set each this");
        loop_pop(p);
        return 0;
    }
    if (!bc_emit_u8(bc, BC_CALL) ||
        !bc_emit_string(bc, "len", 3) ||
        !bc_emit_u32(bc, 0)) {
        parser_error(p, "failed to emit each len call");
        loop_pop(p);
        return 0;
    }
    if (!emit_store_global_name(bc, p, len_name, len_len)) { loop_pop(p); return 0; }

    size_t loop_start = bc->len;
    if (!emit_load_global_name(bc, p, idx_name, idx_len)) { loop_pop(p); return 0; }
    if (!emit_load_global_name(bc, p, len_name, len_len)) { loop_pop(p); return 0; }
    if (!bc_emit_u8(bc, BC_LT)) {
        parser_error(p, "failed to emit each compare");
        loop_pop(p);
        return 0;
    }
    size_t jmp_out = emit_jump(bc, p, BC_JMP_IF_FALSE);
    if (!jmp_out) { loop_pop(p); return 0; }

    if (!emit_load_global_name(bc, p, iter_name, iter_len)) { loop_pop(p); return 0; }
    if (!emit_load_global_name(bc, p, idx_name, idx_len)) { loop_pop(p); return 0; }
    if (!bc_emit_u8(bc, BC_INDEX)) {
        parser_error(p, "failed to emit each index");
        loop_pop(p);
        return 0;
    }
    if (!emit_store_global_name(bc, p, value_name, value_len)) { loop_pop(p); return 0; }

    if (!parse_block(p, bc)) { loop_pop(p); return 0; }

    LoopContext *ctx = loop_current(p);
    size_t continue_target = bc->len;
    if (ctx) {
        ctx->continue_target = continue_target;
        ctx->has_continue_target = 1;
        for (int i = 0; i < ctx->cont_count; i++) {
            if (!patch_jump(bc, p, ctx->continues[i], ctx->continue_target)) { loop_pop(p); return 0; }
        }
    }
    if (!emit_load_global_name(bc, p, idx_name, idx_len)) { loop_pop(p); return 0; }
    if (!bc_emit_u8(bc, BC_PUSH_INT) || !bc_emit_i64(bc, 1)) {
        parser_error(p, "failed to emit each increment");
        loop_pop(p);
        return 0;
    }
    if (!bc_emit_u8(bc, BC_ADD)) {
        parser_error(p, "failed to emit each increment add");
        loop_pop(p);
        return 0;
    }
    if (!emit_store_global_name(bc, p, idx_name, idx_len)) { loop_pop(p); return 0; }

    if (!bc_emit_u8(bc, BC_JMP) || !bc_emit_u32(bc, (uint32_t)loop_start)) {
        parser_error(p, "failed to emit each loop jump");
        loop_pop(p);
        return 0;
    }
    if (!patch_jump(bc, p, jmp_out, bc->len)) { loop_pop(p); return 0; }
    if (ctx) {
        size_t break_target = bc->len;
        for (int i = 0; i < ctx->break_count; i++) {
            if (!patch_jump(bc, p, ctx->breaks[i], break_target)) { loop_pop(p); return 0; }
        }
    }
    loop_pop(p);

    if (!emit_load_global_name(bc, p, "null", 4)) return 0;
    if (!emit_store_global_name(bc, p, iter_name, iter_len)) return 0;
    if (!emit_load_global_name(bc, p, "null", 4)) return 0;
    if (!emit_store_global_name(bc, p, len_name, len_len)) return 0;
    if (!emit_load_global_name(bc, p, "null", 4)) return 0;
    if (!emit_store_global_name(bc, p, idx_name, idx_len)) return 0;

    return 1;
}

static int parse_statement(Parser *p, Bytecode *bc)
{
    if (p->current.kind == TOK_IDENT &&
        p->current.len == 3 && strncmp(p->current.start, "use", 3) == 0) {
        Parser probe = *p;
        Token next = next_token(&probe);
        Token after = next_token(&probe);
        int mode = 0;
        if (after.kind == TOK_COMMA) {
            if (next.kind == TOK_STRING) {
                if (next.str_len == 6 && memcmp(next.str, "strict", 6) == 0) mode = 1;
                else if (next.str_len == 8 && memcmp(next.str, "nostrict", 8) == 0) mode = -1;
            } else if (next.kind == TOK_IDENT) {
                if (next.len == 6 && memcmp(next.start, "strict", 6) == 0) mode = 1;
                else if (next.len == 8 && memcmp(next.start, "nostrict", 8) == 0) mode = -1;
            }
        }
        token_free(&next);
        token_free(&after);
        if (mode != 0) {
            advance(p);
            if (p->current.kind == TOK_STRING) {
                if ((mode > 0 && (p->current.str_len != 6 ||
                                  memcmp(p->current.str, "strict", 6) != 0)) ||
                    (mode < 0 && (p->current.str_len != 8 ||
                                  memcmp(p->current.str, "nostrict", 8) != 0))) {
                    parser_error(p, mode > 0 ? "expected \"strict\" after use"
                                             : "expected \"nostrict\" after use");
                    return 0;
                }
            } else if (p->current.kind == TOK_IDENT) {
                if ((mode > 0 && (p->current.len != 6 ||
                                  memcmp(p->current.start, "strict", 6) != 0)) ||
                    (mode < 0 && (p->current.len != 8 ||
                                  memcmp(p->current.start, "nostrict", 8) != 0))) {
                    parser_error(p, mode > 0 ? "expected strict after use"
                                             : "expected nostrict after use");
                    return 0;
                }
            } else {
                parser_error(p, mode > 0 ? "expected strict after use"
                                         : "expected nostrict after use");
                return 0;
            }
            advance(p);
            if (!expect(p, TOK_COMMA, mode > 0 ? "expected ',' after use strict"
                                              : "expected ',' after use nostrict")) {
                return 0;
            }
            /* strict/nostrict kept only for backwards compatibility (no-op). */
            return 1;
        }
    }
    if (p->current.kind == TOK_IDENT && peek_kind(p, 1) == TOK_COLON) {
        const char *name = p->current.start;
        size_t len = p->current.len;
        advance(p);
        advance(p);
        if (!label_define(p, bc, name, len)) return 0;
        return 1;
    }
    if (match(p, TOK_GOTO)) {
        if (p->current.kind != TOK_IDENT) {
            parser_error(p, "expected identifier after goto");
            return 0;
        }
        const char *name = p->current.start;
        size_t len = p->current.len;
        advance(p);
        size_t jmp_target = emit_jump(bc, p, BC_JMP);
        if (!jmp_target) return 0;
        if (!label_add_ref(p, bc, name, len, jmp_target)) return 0;
        if (!expect(p, TOK_COMMA, "expected ',' after goto")) return 0;
        return 1;
    }
    if (match(p, TOK_SWITCH)) {
        return parse_switch_statement(p, bc);
    }
    if (match(p, TOK_IF)) {
        return parse_if_statement(p, bc);
    }
    if (match(p, TOK_WHILE)) {
        return parse_while_statement(p, bc);
    }
    if (match(p, TOK_FOR)) {
        return parse_for_statement(p, bc);
    }
    if (match(p, TOK_EACH)) {
        return parse_each_statement(p, bc);
    }
    if (match(p, TOK_RETURN)) {
        if (p->current.kind == TOK_COMMA) {
            if (!emit_load_global_name(bc, p, "null", 4)) return 0;
            advance(p);
        } else {
            Expr *value = parse_expr(p);
            if (!value) return 0;
            if (!emit_expr(bc, p, value)) return 0;
            if (!expect(p, TOK_COMMA, "expected ',' after return")) return 0;
        }
        if (!bc_emit_u8(bc, BC_RETURN)) {
            parser_error(p, "failed to emit RETURN");
            return 0;
        }
        return 1;
    }
    if (match(p, TOK_BREAK)) {
        if (!emit_loop_break(p, bc)) return 0;
        if (!expect(p, TOK_COMMA, "expected ',' after break")) return 0;
        return 1;
    }
    if (match(p, TOK_CONTINUE)) {
        if (!emit_loop_continue(p, bc)) return 0;
        if (!expect(p, TOK_COMMA, "expected ',' after continue")) return 0;
        return 1;
    }
    if (p->current.kind == TOK_LBRACE) {
        return parse_block(p, bc);
    }
    return parse_simple_statement(p, bc, 1);
}

static int parse_program(Parser *p, Bytecode *bc)
{
    while (p->current.kind != TOK_EOF) {
        if (!parse_statement(p, bc)) return 0;
    }
    if (!label_validate(p)) return 0;
    return 1;
}

typedef struct {
    char *token;
    char *value;
} PreMaskEntry;

typedef struct {
    PreMaskEntry *items;
    size_t count;
    size_t cap;
} PreMaskList;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} PreStrBuf;

static char *dup_n(const char *s, size_t len)
{
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    if (len) memcpy(out, s, len);
    out[len] = 0;
    return out;
}

static int prebuf_init(PreStrBuf *b, size_t hint)
{
    size_t cap = hint ? hint + 32 : 128;
    b->data = (char*)malloc(cap);
    if (!b->data) return 0;
    b->len = 0;
    b->cap = cap;
    b->data[0] = 0;
    return 1;
}

static int prebuf_grow(PreStrBuf *b, size_t add)
{
    if (b->len + add + 1 <= b->cap) return 1;
    size_t next = b->cap;
    while (next < b->len + add + 1) next <<= 1;
    char *tmp = (char*)realloc(b->data, next);
    if (!tmp) return 0;
    b->data = tmp;
    b->cap = next;
    return 1;
}

static int prebuf_append_n(PreStrBuf *b, const char *s, size_t n)
{
    if (!prebuf_grow(b, n)) return 0;
    if (n) memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
    return 1;
}

static int prebuf_append_char(PreStrBuf *b, char c)
{
    if (!prebuf_grow(b, 1)) return 0;
    b->data[b->len++] = c;
    b->data[b->len] = 0;
    return 1;
}

static void prebuf_free(PreStrBuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static void premask_free(PreMaskList *masks)
{
    if (!masks) return;
    for (size_t i = 0; i < masks->count; i++) {
        free(masks->items[i].token);
        free(masks->items[i].value);
    }
    free(masks->items);
    masks->items = NULL;
    masks->count = 0;
    masks->cap = 0;
}

static int premask_add(PreMaskList *masks, const char *segment, size_t len, const char **out_token)
{
    if (masks->count == masks->cap) {
        size_t next_cap = masks->cap ? masks->cap * 2 : 32;
        PreMaskEntry *tmp = (PreMaskEntry*)realloc(masks->items, next_cap * sizeof(PreMaskEntry));
        if (!tmp) return 0;
        masks->items = tmp;
        masks->cap = next_cap;
    }

    char tok[64];
    int n = snprintf(tok, sizeof(tok), "__PAPAGAIO_MASK_%zu__", masks->count);
    if (n <= 0 || (size_t)n >= sizeof(tok)) return 0;

    PreMaskEntry *entry = &masks->items[masks->count];
    entry->token = dup_n(tok, (size_t)n);
    entry->value = dup_n(segment, len);
    if (!entry->token || !entry->value) {
        free(entry->token);
        free(entry->value);
        entry->token = NULL;
        entry->value = NULL;
        return 0;
    }
    if (out_token) *out_token = entry->token;
    masks->count++;
    return 1;
}

static char *replace_all_literal(const char *src, const char *needle, const char *replacement)
{
    size_t src_len = strlen(src);
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(replacement);
    if (needle_len == 0) return dup_n(src, src_len);

    size_t count = 0;
    const char *p = src;
    while ((p = strstr(p, needle)) != NULL) {
        count++;
        p += needle_len;
    }

    if (count == 0) return dup_n(src, src_len);

    size_t out_len = src_len;
    if (repl_len >= needle_len) {
        out_len += count * (repl_len - needle_len);
    } else {
        out_len -= count * (needle_len - repl_len);
    }
    char *out = (char*)malloc(out_len + 1);
    if (!out) return NULL;

    const char *cur = src;
    char *dst = out;
    while ((p = strstr(cur, needle)) != NULL) {
        size_t chunk = (size_t)(p - cur);
        if (chunk) memcpy(dst, cur, chunk);
        dst += chunk;
        if (repl_len) memcpy(dst, replacement, repl_len);
        dst += repl_len;
        cur = p + needle_len;
    }
    strcpy(dst, cur);
    return out;
}

static int source_has_compiletime_papagaio_decl(const char *masked_src)
{
    if (!masked_src) return 0;
    if (strstr(masked_src, "$pattern{")) return 1;
    if (strstr(masked_src, "$regex")) return 1;
    if (strstr(masked_src, "$eval{")) return 1;
    return 0;
}

static char *restore_masked_segments(const char *src, const PreMaskList *masks);

static int parse_brace_block_span(const char *src, size_t n, size_t start, size_t *out_end)
{
    if (start >= n || src[start] != '{') return 0;
    int depth = 1;
    size_t i = start + 1;
    while (i < n) {
        if (src[i] == '{') {
            depth++;
        } else if (src[i] == '}') {
            depth--;
            if (depth == 0) {
                if (out_end) *out_end = i + 1;
                return 1;
            }
        }
        i++;
    }
    return 0;
}

static int parse_decl_span(const char *src, size_t n, size_t pos, size_t *out_end)
{
    if (pos >= n || src[pos] != '$') return 0;

    size_t i = pos;
    if (i + 8 <= n && memcmp(src + i, "$pattern", 8) == 0) {
        i += 8;
        while (i < n && isspace((unsigned char)src[i])) i++;
        if (i >= n || src[i] != '{') return 0;
        if (!parse_brace_block_span(src, n, i, &i)) return 0;
        while (i < n && isspace((unsigned char)src[i])) i++;
        if (i >= n || src[i] != '{') return 0;
        if (!parse_brace_block_span(src, n, i, &i)) return 0;
        if (out_end) *out_end = i;
        return 1;
    }

    if (i + 5 <= n && memcmp(src + i, "$eval", 5) == 0) {
        i += 5;
        while (i < n && isspace((unsigned char)src[i])) i++;
        if (i >= n || src[i] != '{') return 0;
        if (!parse_brace_block_span(src, n, i, &i)) return 0;
        if (out_end) *out_end = i;
        return 1;
    }

    if (i + 6 <= n && memcmp(src + i, "$regex", 6) == 0) {
        i += 6;
        while (i < n && src[i] != '{' && src[i] != '\n') i++;
        if (i >= n || src[i] != '{') return 0;
        if (!parse_brace_block_span(src, n, i, &i)) return 0;
        if (out_end) *out_end = i;
        return 1;
    }

    return 0;
}

static char *unmask_decl_segments(const char *masked_src, const PreMaskList *masks)
{
    size_t n = strlen(masked_src);
    PreStrBuf out;
    if (!prebuf_init(&out, n)) return NULL;

    size_t i = 0;
    while (i < n) {
        size_t end = 0;
        if (masked_src[i] == '$' && parse_decl_span(masked_src, n, i, &end) && end > i) {
            char *seg = dup_n(masked_src + i, end - i);
            char *restored = seg ? restore_masked_segments(seg, masks) : NULL;
            free(seg);
            if (!restored || !prebuf_append_n(&out, restored, strlen(restored))) {
                free(restored);
                prebuf_free(&out);
                return NULL;
            }
            free(restored);
            i = end;
            continue;
        }
        if (!prebuf_append_char(&out, masked_src[i])) {
            prebuf_free(&out);
            return NULL;
        }
        i++;
    }
    return out.data;
}

static char *mask_strings_and_comments(const char *src, PreMaskList *masks)
{
    size_t n = strlen(src);
    PreStrBuf out;
    if (!prebuf_init(&out, n)) return NULL;

    size_t i = 0;
    while (i < n) {
        char c = src[i];
        if (c == '"' || c == '\'') {
            size_t start = i;
            char quote = c;
            i++;
            while (i < n) {
                if (src[i] == '\\' && i + 1 < n) {
                    i += 2;
                    continue;
                }
                if (src[i] == quote) {
                    i++;
                    break;
                }
                i++;
            }
            const char *token = NULL;
            if (!premask_add(masks, src + start, i - start, &token) ||
                !prebuf_append_n(&out, token, strlen(token))) {
                prebuf_free(&out);
                return NULL;
            }
            continue;
        }

        if (c == '/' && i + 1 < n && src[i + 1] == '/') {
            size_t start = i;
            i += 2;
            while (i < n && src[i] != '\n') i++;
            if (i < n && src[i] == '\n') i++;
            const char *token = NULL;
            if (!premask_add(masks, src + start, i - start, &token) ||
                !prebuf_append_n(&out, token, strlen(token))) {
                prebuf_free(&out);
                return NULL;
            }
            continue;
        }

        if (c == '/' && i + 1 < n && src[i + 1] == '*') {
            size_t start = i;
            i += 2;
            while (i + 1 < n) {
                if (src[i] == '*' && src[i + 1] == '/') {
                    i += 2;
                    break;
                }
                i++;
            }
            if (i == n - 1 && src[i] != '/') i = n;
            const char *token = NULL;
            if (!premask_add(masks, src + start, i - start, &token) ||
                !prebuf_append_n(&out, token, strlen(token))) {
                prebuf_free(&out);
                return NULL;
            }
            continue;
        }

        if (!prebuf_append_char(&out, c)) {
            prebuf_free(&out);
            return NULL;
        }
        i++;
    }
    return out.data;
}

static char *restore_masked_segments(const char *src, const PreMaskList *masks)
{
    char *current = dup_n(src, strlen(src));
    if (!current) return NULL;

    for (size_t i = 0; i < masks->count; i++) {
        char *next = replace_all_literal(current, masks->items[i].token, masks->items[i].value);
        free(current);
        if (!next) return NULL;
        current = next;
    }
    return current;
}

static int preprocess_compiletime_papagaio(VM *vm, const char *src, char **out, char *err, size_t err_cap)
{
    if (out) *out = NULL;
    if (!vm || !src || !strchr(src, '$')) return 1;

    PreMaskList masks;
    memset(&masks, 0, sizeof(masks));

    char *masked = mask_strings_and_comments(src, &masks);
    if (!masked) {
        premask_free(&masks);
        if (err && err_cap > 0) snprintf(err, err_cap, "papagaio preprocess out of memory");
        return 0;
    }

    if (!source_has_compiletime_papagaio_decl(masked)) {
        free(masked);
        premask_free(&masks);
        return 1;
    }

    char *prepared = unmask_decl_segments(masked, &masks);
    free(masked);
    if (!prepared) {
        premask_free(&masks);
        if (err && err_cap > 0) snprintf(err, err_cap, "papagaio preprocess out of memory");
        return 0;
    }

    char *processed = papagaio_process_text(vm, prepared, strlen(prepared));
    free(prepared);
    if (!processed) {
        premask_free(&masks);
        if (err && err_cap > 0) snprintf(err, err_cap, "papagaio preprocess error");
        return 0;
    }

    char *restored = restore_masked_segments(processed, &masks);
    free(processed);
    premask_free(&masks);
    if (!restored) {
        if (err && err_cap > 0) snprintf(err, err_cap, "papagaio preprocess out of memory");
        return 0;
    }
    if (out) *out = restored;
    else free(restored);
    return 1;
}

static int vm_compile_source_impl(VM *vm, const char *src, Bytecode *out, char *err, size_t err_cap)
{
    if (!src || !out) return 0;

    const char *effective_src = src;
    char *preprocessed = NULL;
    if (!preprocess_compiletime_papagaio(vm, src, &preprocessed, err, err_cap)) {
        return 0;
    }
    if (preprocessed) {
        effective_src = preprocessed;
    }

    Parser p;
    memset(&p, 0, sizeof(p));
    p.src = effective_src;
    p.pos = 0;
    p.line = 1;
    p.col = 1;
    p.temp_id = 0;
    p.loops = NULL;
    p.loop_count = 0;
    p.loop_cap = 0;
    arena_init(&p.arena);
    p.prev_kind = TOK_EOF;
    p.current = next_token(&p);

    bc_init(out);

    int ok = parse_program(&p, out);
    if (p.had_error || !ok) {
        if (err && err_cap > 0) {
            snprintf(err, err_cap, "%s", p.err[0] ? p.err : "parse error");
        }
        bc_free(out);
        loop_free(&p);
        label_free(&p);
        arena_free(&p.arena);
        token_free(&p.current);
        free(preprocessed);
        return 0;
    }

    loop_free(&p);
    label_free(&p);
    arena_free(&p.arena);
    token_free(&p.current);
    free(preprocessed);
    return 1;
}

int vm_compile_source_with_vm(VM *vm, const char *src, Bytecode *out, char *err, size_t err_cap)
{
    return vm_compile_source_impl(vm, src, out, err, err_cap);
}

int vm_compile_source(const char *src, Bytecode *out, char *err, size_t err_cap)
{
    return vm_compile_source_impl(NULL, src, out, err, err_cap);
}

void vm_exec_line(VM *vm, const char *line)
{
    Bytecode bc;
    char err[256];
    err[0] = 0;
    if (!vm_compile_source_with_vm(vm, line ? line : "", &bc, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "parse error");
        return;
    }
    if (!vm_exec_bytecode(vm, bc.data, bc.len)) {
        bc_free(&bc);
        return;
    }
    bc_free(&bc);
}
