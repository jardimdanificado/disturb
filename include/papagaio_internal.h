#ifndef PAPAGAIO_INTERNAL_H
#define PAPAGAIO_INTERNAL_H 1

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *ptr;
    size_t len;
} StrView;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} StrBuf;

typedef enum {
    TOK_LITERAL,
    TOK_VAR,
    TOK_BLOCK,
    TOK_WS,
    TOK_REGEX,
    TOK_BLOCKSEQ
} TokenType;

typedef struct {
    TokenType type;
    StrView value;
    StrView var;
    StrView open;
    StrView close;
    char *open_str;
    char *close_str;
    char *regex_str;
    uint8_t *re_code;
    size_t re_len;
    int re_capture_count;
    unsigned optional : 1;
    int next_sig;
    unsigned all_opt : 1;
} Token;

typedef struct {
    const char *sigil;
    const char *open;
    const char *close;
    const char *pattern;
    const char *eval;
    const char *block;
    const char *blockseq;
    const char *regex;
} Symbols;

typedef struct {
    Token *t;
    int count;
    int cap;
    Symbols sym;
} Pattern;

typedef struct {
    StrView name;
    StrView value;
    char *owned;
} Capture;

typedef struct {
    Capture *cap;
    int count;
    int cap_size;
    int start;
    int end;
    const char *src;
    struct {
        const uint8_t **capture;
        int capture_count;
        size_t match_start;
        size_t match_end;
        const char *src;
    } regex;
} Match;

typedef struct {
    Pattern pattern;
    const char *replacement;
} Rule;

void sb_init(StrBuf *b);
void sb_grow(StrBuf *b, size_t n);
void sb_append_n(StrBuf *b, const char *s, size_t n);
void sb_append_char(StrBuf *b, char c);
void sb_free(StrBuf *b);

void parse_pattern_ex(const char *pat, Pattern *p, const Symbols *sym);
int match_pattern(const char *src, int src_len, const Pattern *p, int start, Match *m);
char *apply_replacement_ex(const char *rep, const Match *m, const Symbols *sym, VM *vm);

#endif // PAPAGAIO_INTERNAL_H
