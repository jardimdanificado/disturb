// papagaio.h - https://github.com/jardimdanificado/papagaio
// papagaio.h implements just the papagaio core

#ifndef PAPAGAIO_H
#define PAPAGAIO_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

typedef struct {
    const char *ptr;
    size_t len;
} StrView;

typedef struct {
    char   *data;
    size_t  len;
    size_t  cap;
} StrBuf;

static inline void sb_init(StrBuf *b)
{
    b->cap = 256;
    b->len = 0;
    b->data = (char*)malloc(b->cap);
    b->data[0] = 0;
}

static inline void sb_grow(StrBuf *b, size_t n)
{
    size_t need = b->len + n + 1;
    if (need <= b->cap) return;

    size_t cap = b->cap;
    while (cap < need) cap <<= 1;
    b->data = (char*)realloc(b->data, cap);
    b->cap  = cap;
}

static inline void sb_append_n(StrBuf *b, const char *s, size_t n)
{
    if (!n) return;
    sb_grow(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
}

static inline void sb_append_char(StrBuf *b, char c)
{
    sb_grow(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = 0;
}

typedef enum {
    TOK_LITERAL,
    TOK_VAR,
    TOK_BLOCK,
    TOK_WS
} TokenType;

typedef struct {
    TokenType type;
    StrView   value;
    StrView   var;
    StrView   open;
    StrView   close;
    unsigned  optional : 1;

    int next_sig;
    unsigned all_opt : 1;
} Token;

typedef struct {
    const char *sigil;
    const char *open;
    const char *close;
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
} Capture;

typedef struct {
    Capture *cap;
    int count;
    int cap_size;
    int end;
} Match;

typedef struct {
    Pattern pattern;
    const char *replacement;
} Rule;

static inline int sv_eq(StrView a, StrView b)
{
    return a.len == b.len && memcmp(a.ptr, b.ptr, a.len) == 0;
}

static inline int sv_starts_with(const char *s, StrView v)
{
    return memcmp(s, v.ptr, v.len) == 0;
}

static inline int starts_with_str(const char *s, const char *prefix)
{
    size_t len = strlen(prefix);
    return memcmp(s, prefix, len) == 0;
}

static inline void skip_ws(const char *s, int *p)
{
    while (isspace((unsigned char)s[*p])) (*p)++;
}

static inline void ensure_cap(Match *m)
{
    if (m->count >= m->cap_size) {
        m->cap_size <<= 1;
        m->cap = (Capture*)realloc(m->cap, sizeof(Capture) * m->cap_size);
    }
}

static int extract_block(
    const char *src, int pos,
    StrView o, StrView c,
    StrView *out
) {
    if (!sv_starts_with(src + pos, o))
        return pos;

    pos += o.len;
    int start = pos;
    int depth = 1;

    while (src[pos] && depth) {
        if (sv_starts_with(src + pos, o)) {
            depth++;
            pos += o.len;
        } else if (sv_starts_with(src + pos, c)) {
            depth--;
            if (!depth) {
                out->ptr = src + start;
                out->len = (size_t)(pos - start);
                return pos + (int)c.len;
            }
            pos += c.len;
        } else {
            pos++;
        }
    }

    out->ptr = src + start;
    out->len = strlen(src + start);
    return (int)strlen(src);
}

static void parse_pattern_ex(const char *pat, Pattern *p, const Symbols *sym)
{
    int n = (int)strlen(pat);
    p->cap = 16;
    p->count = 0;
    p->t = (Token*)malloc(sizeof(Token) * p->cap);
    p->sym = *sym;

    int sigil_len = (int)strlen(sym->sigil);
    int open_len = (int)strlen(sym->open);
    int close_len = (int)strlen(sym->close);
    int i = 0;

    while (i < n) {
        if (p->count == p->cap) {
            p->cap <<= 1;
            p->t = (Token*)realloc(p->t, sizeof(Token) * p->cap);
        }

        Token *t = &p->t[p->count];
        memset(t, 0, sizeof(*t));

        if (isspace((unsigned char)pat[i])) {
            while (i < n && isspace((unsigned char)pat[i])) i++;
            t->type = TOK_WS;
            p->count++;
            continue;
        }

        if (starts_with_str(pat + i, sym->sigil)) {
            i += sigil_len;

            if (starts_with_str(pat + i, sym->open)) {
                i += open_len;
                int o = i;
                while (i < n && !starts_with_str(pat + i, sym->close)) i++;
                t->open = (StrView){ pat + o, (size_t)(i - o) };
                if (starts_with_str(pat + i, sym->close)) i += close_len;

                if (starts_with_str(pat + i, sym->open)) {
                    i += open_len;
                    int c = i;
                    while (i < n && !starts_with_str(pat + i, sym->close)) i++;
                    t->close = (StrView){ pat + c, (size_t)(i - c) };
                    if (starts_with_str(pat + i, sym->close)) i += close_len;
                }

                int v = i;
                while (i < n && (isalnum((unsigned char)pat[i]) || pat[i] == '_')) i++;
                t->var = (StrView){ pat + v, (size_t)(i - v) };

                if (i < n && pat[i] == '?') {
                    t->optional = 1;
                    i++;
                }

                t->type = TOK_BLOCK;
                p->count++;
                continue;
            }

            int v = i;
            while (i < n && (isalnum((unsigned char)pat[i]) || pat[i] == '_')) i++;
            t->var = (StrView){ pat + v, (size_t)(i - v) };

            if (i < n && pat[i] == '?') {
                t->optional = 1;
                i++;
            }

            t->type = TOK_VAR;
            p->count++;
            continue;
        }

        int l = i;
        while (i < n && !isspace((unsigned char)pat[i]) && !starts_with_str(pat + i, sym->sigil)) i++;
        t->type = TOK_LITERAL;
        t->value = (StrView){ pat + l, (size_t)(i - l) };
        p->count++;
    }

    for (int a = 0; a < p->count; a++) {
        p->t[a].next_sig = -1;
        for (int b = a + 1; b < p->count; b++) {
            if (p->t[b].type != TOK_WS) {
                p->t[a].next_sig = b;
                break;
            }
        }

        int all = 1;
        for (int b = a + 1; b < p->count; b++) {
            if (p->t[b].type == TOK_WS) continue;
            if (!p->t[b].optional) {
                all = 0;
                break;
            }
        }
        p->t[a].all_opt = (unsigned)all;
    }
}

static int match_pattern(const char *src, const Pattern *p, int start, Match *m)
{
    m->cap_size = 16;
    m->count = 0;
    m->cap = (Capture*)malloc(sizeof(Capture) * m->cap_size);

    int pos = start;

    for (int i = 0; i < p->count; i++) {
        const Token *t = &p->t[i];

        if (t->type == TOK_WS) {
            if (!isspace((unsigned char)src[pos])) {
                if (!t->all_opt) goto fail;
                continue;
            }
            skip_ws(src, &pos);
            continue;
        }

        if (t->type == TOK_LITERAL) {
            if (!sv_starts_with(src + pos, t->value)) goto fail;
            pos += (int)t->value.len;
            continue;
        }

        const Token *nx = (t->next_sig >= 0) ? &p->t[t->next_sig] : NULL;

        if (t->type == TOK_VAR) {
            if (i == 0 || p->t[i-1].type != TOK_WS)
                skip_ws(src, &pos);

            int s = pos;
            while (src[pos]) {
                if (nx && isspace((unsigned char)src[pos])) break;
                if (nx) {
                    if (nx->type == TOK_LITERAL && sv_starts_with(src + pos, nx->value)) break;
                    if (nx->type == TOK_BLOCK && sv_starts_with(src + pos, nx->open)) break;
                } else if (isspace((unsigned char)src[pos])) break;
                pos++;
            }

            if (pos == s) {
                if (!t->optional) goto fail;
                ensure_cap(m);
                m->cap[m->count++] = (Capture){ t->var, { "", 0 } };
                continue;
            }

            ensure_cap(m);
            m->cap[m->count++] = (Capture){
                t->var,
                { src + s, (size_t)(pos - s) }
            };
            continue;
        }

        if (t->type == TOK_BLOCK) {
            if (!sv_starts_with(src + pos, t->open)) {
                if (!t->optional) goto fail;
                ensure_cap(m);
                m->cap[m->count++] = (Capture){ t->var, { "", 0 } };
                continue;
            }

            StrView v;
            pos = extract_block(src, pos, t->open, t->close, &v);
            ensure_cap(m);
            m->cap[m->count++] = (Capture){ t->var, v };
        }
    }

    m->end = pos;
    return 1;

fail:
    free(m->cap);
    return 0;
}

static char *apply_replacement_ex(const char *rep, const Match *m, const char *sigil)
{
    StrBuf out;
    sb_init(&out);

    int n = (int)strlen(rep);
    int sigil_len = (int)strlen(sigil);
    
    for (int i = 0; i < n;) {
        if (starts_with_str(rep + i, sigil)) {
            int s = i + sigil_len;
            int j = s;
            while (j < n && (isalnum((unsigned char)rep[j]) || rep[j] == '_')) j++;
            StrView name = { rep + s, (size_t)(j - s) };

            int found = 0;
            for (int k = 0; k < m->count; k++) {
                if (sv_eq(m->cap[k].name, name)) {
                    sb_append_n(&out, m->cap[k].value.ptr, m->cap[k].value.len);
                    found = 1;
                    break;
                }
            }

            if (!found) {
                sb_append_n(&out, sigil, sigil_len);
                sb_append_n(&out, name.ptr, name.len);
            }
            i = j;
        } else {
            sb_append_char(&out, rep[i++]);
        }
    }

    return out.data;
}

static inline char *_papagaio_process_ex(const char *input, const char *sigil, const char *open, const char *close, ...) {
    Symbols sym = { sigil, open, close };
    
    Rule *rules = NULL;
    int rule_count = 0;
    int rule_cap = 8;
    rules = (Rule*)malloc(sizeof(Rule) * rule_cap);
    
    va_list args;
    va_start(args, close);
    
    while (1) {
        const char *pattern = va_arg(args, const char*);
        if (!pattern) break;
        
        const char *replacement = va_arg(args, const char*);
        
        if (rule_count >= rule_cap) {
            rule_cap <<= 1;
            rules = (Rule*)realloc(rules, sizeof(Rule) * rule_cap);
        }
        
        parse_pattern_ex(pattern, &rules[rule_count].pattern, &sym);
        rules[rule_count].replacement = replacement;
        rule_count++;
    }
    
    va_end(args);
    
    StrBuf out;
    sb_init(&out);
    
    int len = (int)strlen(input);
    int pos = 0;
    
    while (pos < len) {
        int matched = 0;
        
        for (int i = 0; i < rule_count; i++) {
            Match m;
            if (match_pattern(input, &rules[i].pattern, pos, &m)) {
                char *r = apply_replacement_ex(rules[i].replacement, &m, sigil);
                sb_append_n(&out, r, strlen(r));
                free(r);
                pos = m.end;
                free(m.cap);
                matched = 1;
                break;
            }
        }
        
        if (!matched) {
            sb_append_char(&out, input[pos++]);
        }
    }
    
    for (int i = 0; i < rule_count; i++) {
        free(rules[i].pattern.t);
    }
    free(rules);
    
    return out.data;
}

#define papagaio_process_ex(input, sigil, open, close, ...) \
    _papagaio_process_ex(input, sigil, open, close, __VA_ARGS__, NULL);

#define papagaio_process(input, ...) \
    _papagaio_process_ex(input, "$", "{", "}", __VA_ARGS__, NULL);

#endif