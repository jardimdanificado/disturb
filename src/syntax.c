#include "vm.h"
#include "bytecode.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    TOK_EOF = 0,
    TOK_IDENT,
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
    TOK_SEMI,
    TOK_EQ,
    TOK_PLUS,
    TOK_MINUS,
    TOK_STAR,
    TOK_SLASH,
    TOK_PERCENT,
    TOK_BANG,
    TOK_EQEQ,
    TOK_NEQ,
    TOK_LT,
    TOK_LTE,
    TOK_GT,
    TOK_GTE,
    TOK_AND,
    TOK_OR,
    TOK_ELLIPSIS
} TokenKind;

typedef struct {
    TokenKind kind;
    const char *start;
    size_t len;
    double number;
    char *str;
    size_t str_len;
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
    EXPR_FUNC_LITERAL
} ExprKind;

typedef enum {
    CAST_NUMBER,
    CAST_BYTE,
    CAST_OBJECT
} CastKind;

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
            CastKind kind;
            Expr **items;
            int count;
        } cast_list;
        struct {
            double *items;
            int count;
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
            char **args;
            size_t *arg_lens;
            int argc;
            int has_vararg;
            Bytecode bc;
        } func;
    } as;
};

typedef struct {
    void **items;
    size_t count;
    size_t cap;
} Arena;

typedef struct {
    const char *src;
    size_t pos;
    int line;
    int col;
    Token current;
    int had_error;
    char err[256];
    Arena arena;
} Parser;

static void arena_init(Arena *a)
{
    a->items = NULL;
    a->count = 0;
    a->cap = 0;
}

static void *arena_alloc(Arena *a, size_t size)
{
    void *p = calloc(1, size);
    if (!p) return NULL;
    if (a->count == a->cap) {
        size_t next = a->cap == 0 ? 16 : a->cap * 2;
        void **items = (void**)realloc(a->items, next * sizeof(void*));
        if (!items) {
            free(p);
            return NULL;
        }
        a->items = items;
        a->cap = next;
    }
    a->items[a->count++] = p;
    return p;
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
    int c = peek_char(p);
    while (c && isspace((unsigned char)c)) {
        next_char(p);
        c = peek_char(p);
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
        t.kind = TOK_IDENT;
        t.len = (size_t)(p->src + p->pos - t.start);
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
        for (size_t i = 0; i < len; i++) next_char(p);
        t.kind = TOK_NUMBER;
        t.number = v;
        t.len = len;
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
    case ';': t.kind = TOK_SEMI; break;
    case '+': t.kind = TOK_PLUS; break;
    case '-': t.kind = TOK_MINUS; break;
    case '*': t.kind = TOK_STAR; break;
    case '/': t.kind = TOK_SLASH; break;
    case '%': t.kind = TOK_PERCENT; break;
    case '!':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_NEQ;
        } else {
            t.kind = TOK_BANG;
        }
        break;
    case '=':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_EQEQ;
        } else {
            t.kind = TOK_EQ;
        }
        break;
    case '<':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_LTE;
        } else {
            t.kind = TOK_LT;
        }
        break;
    case '>':
        if (peek_char(p) == '=') {
            next_char(p);
            t.kind = TOK_GTE;
        } else {
            t.kind = TOK_GT;
        }
        break;
    case '&':
        if (peek_char(p) == '&') {
            next_char(p);
            t.kind = TOK_AND;
        } else {
            t.kind = TOK_EOF;
        }
        break;
    case '|':
        if (peek_char(p) == '|') {
            next_char(p);
            t.kind = TOK_OR;
        } else {
            t.kind = TOK_EOF;
        }
        break;
    default: t.kind = TOK_EOF; break;
    }
    return t;
}

static void advance(Parser *p)
{
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

static int peek_ident_is_type(Parser *p)
{
    Parser probe = *p;
    Token tok = {0};
    token_free(&tok);
    tok = next_token(&probe);
    if (tok.kind != TOK_IDENT) {
        token_free(&tok);
        return 0;
    }
    int ok = (tok.len == 6 && strncmp(tok.start, "object", 6) == 0) ||
             (tok.len == 6 && strncmp(tok.start, "number", 6) == 0) ||
             (tok.len == 4 && strncmp(tok.start, "byte", 4) == 0);
    token_free(&tok);
    return ok;
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
        if (tok.kind != TOK_IDENT) {
            token_free(&tok);
            return 0;
        }

        token_free(&tok);
        tok = next_token(&probe);
        if (tok.kind == TOK_ELLIPSIS) {
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
static int parse_number_list_fast(Parser *p, double **out_vals, int *out_count);
static int parse_statement(Parser *p, Bytecode *bc);
static Expr *parse_func_literal(Parser *p);
static Expr *parse_func_literal_with_first_arg(Parser *p, char *name, size_t len);

static Expr *parse_primary(Parser *p)
{
    if (p->current.kind == TOK_NUMBER) {
        Expr *e = expr_new(p, EXPR_LITERAL_NUM);
        if (!e) return NULL;
        e->as.lit_num.number = p->current.number;
        advance(p);
        return e;
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

    if (p->current.kind == TOK_LPAREN) {
        int is_cast = peek_kind(p, 1) == TOK_IDENT && peek_ident_is_type(p) &&
                      peek_kind(p, 2) == TOK_RPAREN &&
                      peek_kind(p, 3) == TOK_LBRACE;
        int is_func = !is_cast && peek_is_func_literal(p);
        advance(p);
        if (is_func) {
            return parse_func_literal(p);
        }
        if (!is_cast) {
            Expr *inner = parse_expr(p);
            if (!inner) return NULL;
            if (!expect(p, TOK_RPAREN, "expected ')' after expression")) return NULL;
            return inner;
        }
        if (p->current.kind != TOK_IDENT) {
            parser_error(p, "expected type name after '('");
            return NULL;
        }
        char *type = arena_strndup(&p->arena, p->current.start, p->current.len);
        advance(p);
        if (!expect(p, TOK_RPAREN, "expected ')' after type")) return NULL;

        if (strcmp(type, "object") == 0) {
            if (!expect(p, TOK_LBRACE, "expected '{' to start literal")) return NULL;
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

                    if (match(p, TOK_COMMA)) continue;
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

        CastKind cast;
        if (strcmp(type, "number") == 0) {
            cast = CAST_NUMBER;
        } else if (strcmp(type, "byte") == 0) {
            cast = CAST_BYTE;
        } else {
            return parse_func_literal_with_first_arg(p, type, strlen(type));
        }

        if (!expect(p, TOK_LBRACE, "expected '{' to start literal")) return NULL;

        if (cast == CAST_NUMBER) {
            double *vals = NULL;
            int count = 0;
            if (parse_number_list_fast(p, &vals, &count)) {
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
                return e;
            }
        }

        Expr *e = expr_new(p, EXPR_CAST_LIST);
        if (!e) return NULL;
        e->as.cast_list.kind = cast;
        Expr **items = NULL;
        int count = 0;
        int cap = 0;

        if (p->current.kind != TOK_RBRACE) {
            for (;;) {
                Expr *item = parse_expr(p);
                if (!item) return NULL;
                if (count == cap) {
                    int next = cap == 0 ? 4 : cap * 2;
                    Expr **tmp = (Expr**)realloc(items, (size_t)next * sizeof(Expr*));
                    if (!tmp) {
                        parser_error(p, "out of memory");
                        return NULL;
                    }
                    items = tmp;
                    cap = next;
                }
                items[count++] = item;

                if (match(p, TOK_COMMA)) continue;
                break;
            }
        }

        if (!expect(p, TOK_RBRACE, "expected '}' to end list")) return NULL;
        if (items && !arena_track(&p->arena, items)) {
            parser_error(p, "out of memory");
            return NULL;
        }
        e->as.cast_list.items = items;
        e->as.cast_list.count = count;
        return e;
    }

    parser_error(p, "unexpected token");
    return NULL;
}

static int parse_number_list_fast(Parser *p, double **out_vals, int *out_count)
{
    Parser probe = *p;
    probe.current.str = NULL;
    probe.current.str_len = 0;

    double *vals = NULL;
    int count = 0;
    int cap = 0;
    Token tok = probe.current;

    if (tok.kind == TOK_RBRACE) {
        *out_vals = NULL;
        *out_count = 0;
        return 1;
    }

    for (;;) {
        if (tok.kind != TOK_NUMBER) {
            token_free(&probe.current);
            free(vals);
            return 0;
        }
        if (count == cap) {
            int next = cap == 0 ? 16 : cap * 2;
            double *tmp = (double*)realloc(vals, (size_t)next * sizeof(double));
            if (!tmp) {
                token_free(&probe.current);
                free(vals);
                return 0;
            }
            vals = tmp;
            cap = next;
        }
        vals[count++] = tok.number;
        advance(&probe);
        tok = probe.current;
        if (tok.kind == TOK_COMMA) {
            advance(&probe);
            tok = probe.current;
            continue;
        }
        if (tok.kind == TOK_RBRACE) break;
        token_free(&probe.current);
        free(vals);
        return 0;
    }

    if (p->current.kind == TOK_RBRACE) {
        if (!expect(p, TOK_RBRACE, "expected '}' to end list")) {
            free(vals);
            return 0;
        }
    } else {
        for (int i = 0; i < count; i++) {
            if (p->current.kind != TOK_NUMBER) {
                free(vals);
                return 0;
            }
            advance(p);
            if (i + 1 < count && !match(p, TOK_COMMA)) {
                parser_error(p, "expected ',' between list items");
                free(vals);
                return 0;
            }
        }
        if (!expect(p, TOK_RBRACE, "expected '}' to end list")) {
            free(vals);
            return 0;
        }
    }

    *out_vals = vals;
    *out_count = count;
    return 1;
}

static int parse_block(Parser *p, Bytecode *bc)
{
    if (!expect(p, TOK_LBRACE, "expected '{' to start function body")) return 0;
    while (p->current.kind != TOK_RBRACE && p->current.kind != TOK_EOF) {
        if (!parse_statement(p, bc)) return 0;
    }
    if (!expect(p, TOK_RBRACE, "expected '}' after function body")) return 0;
    return 1;
}

static Expr *parse_func_literal(Parser *p)
{
    Expr *e = expr_new(p, EXPR_FUNC_LITERAL);
    if (!e) return NULL;

    char **args = NULL;
    size_t *arg_lens = NULL;
    int argc = 0;
    int cap = 0;
    int has_vararg = 0;

    if (p->current.kind != TOK_RPAREN) {
        for (;;) {
            if (p->current.kind != TOK_IDENT) {
                parser_error(p, "expected parameter name");
                return NULL;
            }
            char *name = arena_strndup(&p->arena, p->current.start, p->current.len);
            size_t len = p->current.len;
            advance(p);

            int is_vararg = 0;
            if (match(p, TOK_ELLIPSIS)) {
                is_vararg = 1;
                has_vararg = 1;
            }

            if (argc == cap) {
                int next = cap == 0 ? 4 : cap * 2;
                char **tmp = (char**)realloc(args, (size_t)next * sizeof(char*));
                size_t *ltmp = (size_t*)realloc(arg_lens, (size_t)next * sizeof(size_t));
                if (!tmp || !ltmp) {
                    parser_error(p, "out of memory");
                    return NULL;
                }
                args = tmp;
                arg_lens = ltmp;
                cap = next;
            }
            args[argc] = name;
            arg_lens[argc] = len;
            argc++;

            if (is_vararg) {
                if (p->current.kind != TOK_RPAREN) {
                    parser_error(p, "varargs must be last");
                    return NULL;
                }
                break;
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

    e->as.func.args = args;
    e->as.func.arg_lens = arg_lens;
    e->as.func.argc = argc;
    e->as.func.has_vararg = has_vararg;
    e->as.func.bc = *body;
    return e;
}

static Expr *parse_func_literal_with_first_arg(Parser *p, char *name, size_t len)
{
    Expr *e = expr_new(p, EXPR_FUNC_LITERAL);
    if (!e) return NULL;

    char **args = (char**)realloc(NULL, sizeof(char*));
    size_t *arg_lens = (size_t*)realloc(NULL, sizeof(size_t));
    if (!args || !arg_lens) {
        parser_error(p, "out of memory");
        return NULL;
    }
    args[0] = name;
    arg_lens[0] = len;

    Bytecode *body = (Bytecode*)arena_alloc(&p->arena, sizeof(Bytecode));
    if (!body) {
        parser_error(p, "out of memory");
        return NULL;
    }
    bc_init(body);
    if (!parse_block(p, body)) return NULL;

    if (!arena_track(&p->arena, args) || !arena_track(&p->arena, arg_lens)) {
        parser_error(p, "out of memory");
        return NULL;
    }

    e->as.func.args = args;
    e->as.func.arg_lens = arg_lens;
    e->as.func.argc = 1;
    e->as.func.has_vararg = 0;
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
        break;
    }

    return expr;
}

static Expr *parse_unary(Parser *p)
{
    if (p->current.kind == TOK_BANG || p->current.kind == TOK_MINUS) {
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

static Expr *parse_compare(Parser *p)
{
    Expr *expr = parse_term(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_LT || p->current.kind == TOK_LTE ||
           p->current.kind == TOK_GT || p->current.kind == TOK_GTE) {
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

static Expr *parse_equality(Parser *p)
{
    Expr *expr = parse_compare(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_EQEQ || p->current.kind == TOK_NEQ) {
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

static Expr *parse_and(Parser *p)
{
    Expr *expr = parse_equality(p);
    if (!expr) return NULL;
    while (p->current.kind == TOK_AND) {
        advance(p);
        Expr *right = parse_equality(p);
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

static Expr *parse_expr(Parser *p)
{
    return parse_or(p);
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

static int emit_expr(Bytecode *bc, Parser *p, Expr *e)
{
    if (!e) return 0;
    switch (e->kind) {
    case EXPR_LITERAL_NUM:
        if (!bc_emit_u8(bc, BC_PUSH_NUM) || !bc_emit_f64(bc, e->as.lit_num.number)) {
            parser_error(p, "failed to emit number literal");
            return 0;
        }
        return 1;
    case EXPR_LITERAL_STRING:
        if (!bc_emit_u8(bc, BC_PUSH_STRING) ||
            !bc_emit_string(bc, e->as.lit_str.data, e->as.lit_str.len)) {
            parser_error(p, "failed to emit string literal");
            return 0;
        }
        return 1;
    case EXPR_LITERAL_CHAR:
        if (!bc_emit_u8(bc, BC_PUSH_CHAR) ||
            !bc_emit_string(bc, e->as.lit_str.data, e->as.lit_str.len)) {
            parser_error(p, "failed to emit char literal");
            return 0;
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
        if (e->as.cast_list.kind == CAST_BYTE) {
            for (int i = 0; i < count; i++) {
                Expr *item = e->as.cast_list.items[i];
                if (item->kind == EXPR_LITERAL_NUM) {
                    double v = item->as.lit_num.number;
                    if (v < 0 || v > 255 || (double)(int)v != v) {
                        parser_error(p, "byte literal out of range (0-255)");
                        return 0;
                    }
                    if (!bc_emit_u8(bc, BC_PUSH_BYTE) || !bc_emit_u8(bc, (uint8_t)v)) {
                        parser_error(p, "failed to emit byte literal");
                        return 0;
                    }
                    continue;
                }
                if (!emit_expr(bc, p, item)) return 0;
            }
            if (!bc_emit_u8(bc, BC_BUILD_BYTE) || !bc_emit_u32(bc, (uint32_t)count)) {
                parser_error(p, "failed to emit BUILD_BYTE");
                return 0;
            }
            return 1;
        }

        int all_literal = 1;
        for (int i = 0; i < count; i++) {
            if (e->as.cast_list.items[i]->kind != EXPR_LITERAL_NUM) {
                all_literal = 0;
                break;
            }
        }
        if (all_literal) {
            if (!bc_emit_u8(bc, BC_BUILD_NUMBER_LIT) || !bc_emit_u32(bc, (uint32_t)count)) {
                parser_error(p, "failed to emit BUILD_NUMBER_LIT");
                return 0;
            }
            for (int i = 0; i < count; i++) {
                double v = e->as.cast_list.items[i]->as.lit_num.number;
                if (!bc_emit_f64(bc, v)) {
                    parser_error(p, "failed to emit BUILD_NUMBER_LIT value");
                    return 0;
                }
            }
            return 1;
        }

        for (int i = 0; i < count; i++) {
            if (!emit_expr(bc, p, e->as.cast_list.items[i])) return 0;
        }
        if (!bc_emit_u8(bc, BC_BUILD_NUMBER) || !bc_emit_u32(bc, (uint32_t)count)) {
            parser_error(p, "failed to emit BUILD_NUMBER");
            return 0;
        }
        return 1;
    }
    case EXPR_LITERAL_NUMBER_LIST: {
        int count = e->as.num_list.count;
        if (!bc_emit_u8(bc, BC_BUILD_NUMBER_LIT) || !bc_emit_u32(bc, (uint32_t)count)) {
            parser_error(p, "failed to emit BUILD_NUMBER_LIT");
            return 0;
        }
        for (int i = 0; i < count; i++) {
            if (!bc_emit_f64(bc, e->as.num_list.items[i])) {
                parser_error(p, "failed to emit BUILD_NUMBER_LIT value");
                return 0;
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
        uint8_t op = e->as.unary.op == TOK_MINUS ? BC_NEG : BC_NOT;
        if (!bc_emit_u8(bc, op)) {
            parser_error(p, "failed to emit unary op");
            return 0;
        }
        return 1;
    }
    case EXPR_BINARY: {
        if (!emit_expr(bc, p, e->as.binary.left)) return 0;
        if (!emit_expr(bc, p, e->as.binary.right)) return 0;
        uint8_t op = 0;
        switch (e->as.binary.op) {
        case TOK_PLUS: op = BC_ADD; break;
        case TOK_MINUS: op = BC_SUB; break;
        case TOK_STAR: op = BC_MUL; break;
        case TOK_SLASH: op = BC_DIV; break;
        case TOK_PERCENT: op = BC_MOD; break;
        case TOK_EQEQ: op = BC_EQ; break;
        case TOK_NEQ: op = BC_NEQ; break;
        case TOK_LT: op = BC_LT; break;
        case TOK_LTE: op = BC_LTE; break;
        case TOK_GT: op = BC_GT; break;
        case TOK_GTE: op = BC_GTE; break;
        case TOK_AND: op = BC_AND; break;
        case TOK_OR: op = BC_OR; break;
        default:
            parser_error(p, "unsupported binary operator");
            return 0;
        }
        if (!bc_emit_u8(bc, op)) {
            parser_error(p, "failed to emit binary op");
            return 0;
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
        }
        bc_free(body);
        body->data = NULL;
        body->len = 0;
        body->cap = 0;
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

static int emit_store(Bytecode *bc, Parser *p, Expr *lhs, Expr *rhs)
{
    if (!lhs || !rhs) return 0;

    if (lhs->kind == EXPR_NAME && !is_global_name(lhs)) {
        if (!emit_expr(bc, p, rhs)) return 0;
        if (!bc_emit_u8(bc, BC_STORE_GLOBAL) || !bc_emit_string(bc, lhs->as.name.name, lhs->as.name.len)) {
            parser_error(p, "failed to emit STORE_GLOBAL");
            return 0;
        }
        return 1;
    }

    if (lhs->kind == EXPR_MEMBER && is_global_name(lhs->as.member.base)) {
        if (!emit_expr(bc, p, rhs)) return 0;
        if (!bc_emit_u8(bc, BC_STORE_GLOBAL) || !bc_emit_string(bc, lhs->as.member.name, lhs->as.member.len)) {
            parser_error(p, "failed to emit STORE_GLOBAL");
            return 0;
        }
        return 1;
    }

    if (lhs->kind == EXPR_MEMBER || lhs->kind == EXPR_INDEX) {
        Expr *base = lhs->kind == EXPR_MEMBER ? lhs->as.member.base : lhs->as.index.base;
        if (!emit_expr(bc, p, base)) return 0;
        if (lhs->kind == EXPR_MEMBER) {
            if (!emit_key(bc, p, lhs->as.member.name, lhs->as.member.len)) return 0;
        } else {
            if (!emit_expr(bc, p, lhs->as.index.index)) return 0;
        }
        if (!emit_expr(bc, p, rhs)) return 0;
        if (!bc_emit_u8(bc, BC_STORE_INDEX)) {
            parser_error(p, "failed to emit STORE_INDEX");
            return 0;
        }
        return 1;
    }

    parser_error(p, "invalid assignment target");
    return 0;
}

static int parse_call(Parser *p, Expr *callee, Bytecode *bc)
{
    if (!expect(p, TOK_LPAREN, "expected '(' after function name")) return 0;

    if (callee->kind != EXPR_NAME && callee->kind != EXPR_MEMBER) {
        parser_error(p, "call target must be a name or member");
        return 0;
    }

    uint32_t argc = 0;
    if (p->current.kind != TOK_RPAREN) {
        for (;;) {
            Expr *arg = parse_expr(p);
            if (!arg) return 0;
            if (!emit_expr(bc, p, arg)) return 0;
            argc++;
            if (match(p, TOK_COMMA)) continue;
            break;
        }
    }

    if (!expect(p, TOK_RPAREN, "expected ')' after arguments")) return 0;

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
    } else {
        if (!emit_expr(bc, p, callee->as.member.base)) return 0;
        if (!bc_emit_u8(bc, BC_SET_THIS)) {
            parser_error(p, "failed to set this");
            return 0;
        }
    }

    const char *name = callee->kind == EXPR_NAME ? callee->as.name.name : callee->as.member.name;
    size_t len = callee->kind == EXPR_NAME ? callee->as.name.len : callee->as.member.len;

    if (!bc_emit_u8(bc, BC_CALL) ||
        !bc_emit_string(bc, name, len) ||
        !bc_emit_u32(bc, argc)) {
        parser_error(p, "failed to emit CALL");
        return 0;
    }

    return 1;
}

static int parse_statement(Parser *p, Bytecode *bc)
{
    Expr *expr = parse_expr(p);
    if (!expr) return 0;

    if (p->current.kind == TOK_LPAREN) {
        if (!parse_call(p, expr, bc)) return 0;
        if (!expect(p, TOK_SEMI, "expected ';' after call")) return 0;
        return 1;
    }

    if (match(p, TOK_EQ)) {
        if (!expr_is_lvalue(expr)) {
            parser_error(p, "left side is not assignable");
            return 0;
        }
        Expr *rhs = parse_expr(p);
        if (!rhs) return 0;
        if (!expect(p, TOK_SEMI, "expected ';' after assignment")) return 0;
        return emit_store(bc, p, expr, rhs);
    }

    parser_error(p, "expected assignment or call");
    return 0;
}

static int parse_program(Parser *p, Bytecode *bc)
{
    while (p->current.kind != TOK_EOF) {
        if (!parse_statement(p, bc)) return 0;
    }
    return 1;
}

void vm_exec_line(VM *vm, const char *line)
{
    Parser p;
    memset(&p, 0, sizeof(p));
    p.src = line;
    p.pos = 0;
    p.line = 1;
    p.col = 1;
    arena_init(&p.arena);
    p.current = next_token(&p);

    Bytecode bc;
    bc_init(&bc);

    int ok = parse_program(&p, &bc);
    if (p.had_error || !ok) {
        fprintf(stderr, "%s\n", p.err[0] ? p.err : "parse error");
        bc_free(&bc);
        arena_free(&p.arena);
        token_free(&p.current);
        return;
    }

    if (!vm_exec_bytecode(vm, bc.data, bc.len)) {
        bc_free(&bc);
        arena_free(&p.arena);
        token_free(&p.current);
        return;
    }

    bc_free(&bc);
    arena_free(&p.arena);
    token_free(&p.current);
}
