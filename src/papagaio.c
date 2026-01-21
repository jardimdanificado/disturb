#include "papagaio.h"
#include "papagaio_internal.h"

#include "bytecode.h"
#include "libregexp.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAPAGAIO_DEFAULT_PATTERN "pattern"
#define PAPAGAIO_DEFAULT_EVAL "eval"
#define PAPAGAIO_DEFAULT_BLOCK "recursive"
#define PAPAGAIO_DEFAULT_BLOCKSEQ "sequential"
#define PAPAGAIO_DEFAULT_REGEX "regex"

static Symbols make_default_symbols(const char *sigil, const char *open, const char *close)
{
    Symbols sym;
    sym.sigil = sigil;
    sym.open = open;
    sym.close = close;
    sym.pattern = PAPAGAIO_DEFAULT_PATTERN;
    sym.eval = PAPAGAIO_DEFAULT_EVAL;
    sym.block = PAPAGAIO_DEFAULT_BLOCK;
    sym.blockseq = PAPAGAIO_DEFAULT_BLOCKSEQ;
    sym.regex = PAPAGAIO_DEFAULT_REGEX;
    return sym;
}

static int sv_starts_with(const char *s, StrView v);

void sb_init(StrBuf *b)
{
    b->cap = 256;
    b->len = 0;
    b->data = (char*)malloc(b->cap);
    b->data[0] = 0;
}

void sb_grow(StrBuf *b, size_t n)
{
    size_t need = b->len + n + 1;
    if (need <= b->cap) return;

    size_t cap = b->cap;
    while (cap < need) cap <<= 1;
    b->data = (char*)realloc(b->data, cap);
    b->cap  = cap;
}

void sb_append_n(StrBuf *b, const char *s, size_t n)
{
    if (!n) return;
    sb_grow(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
}

void sb_append_char(StrBuf *b, char c)
{
    sb_grow(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = 0;
}

void sb_free(StrBuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static StrView trim_view(StrView v)
{
    size_t start = 0;
    while (start < v.len && isspace((unsigned char)v.ptr[start])) start++;
    size_t end = v.len;
    while (end > start && isspace((unsigned char)v.ptr[end - 1])) end--;
    return (StrView){ v.ptr + start, end - start };
}

static char *papagaio_eval_code(VM *vm, const char *code, size_t len)
{
    ObjEntry *value = vm_eval_source(vm, code, len);
    if (!value) return NULL;
    ObjEntry *stringified = vm_stringify_value(vm, value, 1);
    const char *data = "";
    size_t slen = 0;
    if (stringified) {
        data = urb_bytes_data(stringified->obj);
        slen = urb_bytes_len(stringified->obj);
    }
    char *out = (char*)malloc(slen + 1);
    if (!out) {
        if (stringified) vm_release_entry(stringified);
        if (value != vm->null_entry) vm_release_entry(value);
        return NULL;
    }
    if (slen) memcpy(out, data, slen);
    out[slen] = 0;
    if (stringified) vm_release_entry(stringified);
    if (value != vm->null_entry) vm_release_entry(value);
    return out;
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

static int apply_regex_placeholder(
    StrBuf *out,
    const char *replacement,
    size_t repl_len,
    size_t *idx,
    const Symbols *sym,
    const Match *m
)
{
    if (!m->regex.capture) return 0;
    size_t sigil_len = strlen(sym->sigil);
    size_t regex_len = sym->regex ? strlen(sym->regex) : 0;
    size_t pos = *idx + sigil_len + regex_len;
    while (pos < repl_len && isspace((unsigned char)replacement[pos])) pos++;
    StrView open = { sym->open, strlen(sym->open) };
    StrView close = { sym->close, strlen(sym->close) };
    StrView block;
    int next = extract_block(replacement, (int)pos, open, close, &block);
    if (next == pos) return 0;
    StrView trimmed = trim_view(block);
    const char *base = m->regex.src ? m->regex.src : "";
    size_t group_start = m->regex.match_start;
    size_t group_end = m->regex.match_end;
    if (trimmed.len == 0 ||
        (trimmed.len == 5 && strncmp(trimmed.ptr, "match", 5) == 0)) {
        // entire match
    } else {
        if (trimmed.len >= 16) return 0;
        char tmp[16];
        memcpy(tmp, trimmed.ptr, trimmed.len);
        tmp[trimmed.len] = 0;
        char *endptr = NULL;
        long idx_val = strtol(tmp, &endptr, 10);
        if (!tmp[0] || *endptr != 0 || idx_val < 0) return 0;
        int idx_int = (int)idx_val;
        if (idx_int < m->regex.capture_count) {
            const uint8_t *start_ptr = m->regex.capture[2 * idx_int];
            const uint8_t *end_ptr = m->regex.capture[2 * idx_int + 1];
            if (start_ptr) group_start = (size_t)(start_ptr - (const uint8_t*)base);
            if (end_ptr) group_end = (size_t)(end_ptr - (const uint8_t*)base);
            if (group_end < group_start) group_end = group_start;
        } else {
            group_start = group_end = m->regex.match_start;
        }
    }
    if (group_end > strlen(base)) group_end = strlen(base);
    sb_append_n(out, base + group_start, group_end - group_start);
    *idx = (size_t)next;
    return 1;
}

static int apply_eval_placeholder(
    StrBuf *out,
    const char *replacement,
    size_t repl_len,
    size_t *idx,
    const Symbols *sym,
    VM *vm
)
{
    if (!sym->eval || !vm) return 0;
    size_t sigil_len = strlen(sym->sigil);
    size_t eval_len = strlen(sym->eval);
    size_t pos = *idx + sigil_len + eval_len;
    while (pos < repl_len && isspace((unsigned char)replacement[pos])) pos++;
    StrView open = { sym->open, strlen(sym->open) };
    StrView close = { sym->close, strlen(sym->close) };
    StrView block;
    int next = extract_block(replacement, (int)pos, open, close, &block);
    if (next == pos) return 0;
    StrView trimmed = trim_view(block);
    char *code = (char*)malloc(trimmed.len + 1);
    if (!code) return 0;
    memcpy(code, trimmed.ptr, trimmed.len);
    code[trimmed.len] = 0;
    char *result = papagaio_eval_code(vm, code, trimmed.len);
    free(code);
    if (!result) return 0;
    sb_append_n(out, result, strlen(result));
    free(result);
    *idx = (size_t)next;
    return 1;
}

static int sv_eq(StrView a, StrView b)
{
    return a.len == b.len && memcmp(a.ptr, b.ptr, a.len) == 0;
}

static int sv_starts_with(const char *s, StrView v)
{
    return memcmp(s, v.ptr, v.len) == 0;
}

static int starts_with_str(const char *s, const char *prefix)
{
    size_t len = strlen(prefix);
    return memcmp(s, prefix, len) == 0;
}

static void skip_ws(const char *s, int *p)
{
    while (isspace((unsigned char)s[*p])) (*p)++;
}

static void ensure_cap(Match *m)
{
    if (m->count >= m->cap_size) {
        m->cap_size <<= 1;
        m->cap = (Capture*)realloc(m->cap, sizeof(Capture) * m->cap_size);
    }
}

static void free_pattern(Pattern *p)
{
    if (!p || !p->t) return;
    for (int i = 0; i < p->count; i++) {
        free(p->t[i].regex_str);
        free(p->t[i].re_code);
    }
    free(p->t);
    p->t = NULL;
    p->count = 0;
    p->cap = 0;
}

static void free_match(Match *m)
{
    if (!m) return;
    if (m->cap) {
        free(m->cap);
        m->cap = NULL;
    }
    if (m->regex.capture) {
        free((void*)m->regex.capture);
        m->regex.capture = NULL;
    }
    m->count = 0;
    m->cap_size = 0;
}

void parse_pattern_ex(const char *pat, Pattern *p, const Symbols *sym)
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

        if (sym->regex && starts_with_str(pat + i, sym->sigil) &&
            starts_with_str(pat + i + sigil_len, sym->regex)) {
            int start = i;
            i += sigil_len + (int)strlen(sym->regex);
            while (i < n && isspace((unsigned char)pat[i])) i++;
            int v = i;
            while (i < n && (isalnum((unsigned char)pat[i]) || pat[i] == '_')) i++;
            t->var = (StrView){ pat + v, (size_t)(i - v) };
            while (i < n && isspace((unsigned char)pat[i])) i++;
            StrView open = { sym->open, strlen(sym->open) };
            StrView close = { sym->close, strlen(sym->close) };
            StrView block;
            i = extract_block(pat, i, open, close, &block);
            StrView trimmed = trim_view(block);
            if (trimmed.len == 0) {
                t->type = TOK_LITERAL;
                t->value = (StrView){ pat + start, (size_t)(i - start) };
                p->count++;
                continue;
            }
            t->regex_str = (char*)malloc(trimmed.len + 1);
            if (!t->regex_str) {
                t->type = TOK_LITERAL;
                t->value = (StrView){ pat + start, (size_t)(i - start) };
                p->count++;
                continue;
            }
            memcpy(t->regex_str, trimmed.ptr, trimmed.len);
            t->regex_str[trimmed.len] = 0;
            char err[256] = {0};
            int compiled_len = 0;
            t->re_code = lre_compile(&compiled_len, err, sizeof(err), t->regex_str, trimmed.len, 0, NULL);
            if (!t->re_code) {
                fprintf(stderr, "papagaio regex compile error: %s\n", err[0] ? err : "invalid pattern");
                free(t->regex_str);
                t->regex_str = NULL;
                t->type = TOK_LITERAL;
                t->value = (StrView){ pat + start, (size_t)(i - start) };
                p->count++;
                continue;
            }
            t->re_len = (size_t)compiled_len;
            t->re_capture_count = lre_get_capture_count(t->re_code);
            t->type = TOK_REGEX;
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

int match_pattern(const char *src, int src_len, const Pattern *p, int start, Match *m)
{
    m->cap_size = 16;
    m->count = 0;
    m->cap = (Capture*)malloc(sizeof(Capture) * m->cap_size);

    m->regex.capture = NULL;
    m->regex.capture_count = 0;
    m->regex.match_start = start;
    m->regex.match_end = start;
    m->regex.src = src;

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

        if (t->type == TOK_REGEX) {
            if (!t->re_code) goto fail;
            int capture_group_count = t->re_capture_count > 0 ? t->re_capture_count : 1;
            size_t capture_slots = (size_t)capture_group_count * 2;
            const uint8_t **capture = capture_slots ? (const uint8_t**)calloc(capture_slots, sizeof(const uint8_t*)) : NULL;
            if (capture_slots && !capture) goto fail;
            int ret = lre_exec((uint8_t**)capture, t->re_code, (const uint8_t*)src, pos, src_len, 0, NULL);
            if (ret != 1) {
                free((void*)capture);
                goto fail;
            }
            const uint8_t *start_ptr = capture[0];
            const uint8_t *end_ptr = capture[1];
            size_t match_start = start_ptr ? (size_t)(start_ptr - (const uint8_t*)src) : (size_t)pos;
            size_t match_end = end_ptr ? (size_t)(end_ptr - (const uint8_t*)src) : match_start;
            if (match_end > (size_t)src_len) match_end = (size_t)src_len;
            if (match_start > match_end) match_start = match_end;
            ensure_cap(m);
            m->cap[m->count++] = (Capture){
                t->var,
                { src + match_start, match_end - match_start }
            };
            if (m->regex.capture) {
                free((void*)m->regex.capture);
            }
            m->regex.capture = capture;
            m->regex.capture_count = capture_group_count;
            m->regex.match_start = match_start;
            m->regex.match_end = match_end;
            m->regex.src = src;
            pos = (int)match_end;
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
    if (m->regex.capture) {
        free((void*)m->regex.capture);
        m->regex.capture = NULL;
    }
    return 0;
}

char *apply_replacement_ex(const char *rep, const Match *m, const Symbols *sym, VM *vm)
{
    StrBuf out;
    sb_init(&out);

    size_t n = strlen(rep);
    size_t i = 0;
    size_t sigil_len = strlen(sym->sigil);

    while (i < n) {
        if (starts_with_str(rep + i, sym->sigil)) {
            if (sym->regex && apply_regex_placeholder(&out, rep, n, &i, sym, m)) {
                continue;
            }
            if (sym->eval && apply_eval_placeholder(&out, rep, n, &i, sym, vm)) {
                continue;
            }
            size_t name_start = i + sigil_len;
            size_t name_end = name_start;
            while (name_end < n && (isalnum((unsigned char)rep[name_end]) || rep[name_end] == '_')) {
                name_end++;
            }
            StrView name = { rep + name_start, name_end - name_start };
            int found = 0;
            if (name.len > 0) {
                for (int k = 0; k < m->count; k++) {
                    if (sv_eq(m->cap[k].name, name)) {
                        sb_append_n(&out, m->cap[k].value.ptr, m->cap[k].value.len);
                        found = 1;
                        break;
                    }
                }
            }
            if (!found) {
                sb_append_n(&out, sym->sigil, sigil_len);
                sb_append_n(&out, name.ptr, name.len);
            }
            if (name_end == name_start) {
                i += sigil_len;
            } else {
                i = name_end;
            }
            continue;
        }
        sb_append_char(&out, rep[i++]);
    }

    return out.data;
}

static char *_papagaio_process_ex_impl(VM *vm, const char *input, const char *sigil, const char *open, const char *close, va_list args) {
    Symbols sym = make_default_symbols(sigil, open, close);

    Rule *rules = NULL;
    int rule_count = 0;
    int rule_cap = 8;
    rules = (Rule*)malloc(sizeof(Rule) * rule_cap);

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

    StrBuf out;
    sb_init(&out);

    int len = (int)strlen(input);
    int pos = 0;

    while (pos < len) {
        int matched = 0;

        for (int i = 0; i < rule_count; i++) {
            Match m;
            if (match_pattern(input, len, &rules[i].pattern, pos, &m)) {
                char *r = apply_replacement_ex(rules[i].replacement, &m, &sym, vm);
                sb_append_n(&out, r, strlen(r));
                free(r);
                pos = m.end;
                free_match(&m);
                matched = 1;
                break;
            }
        }

        if (!matched) {
            sb_append_char(&out, input[pos++]);
        }
    }

    for (int i = 0; i < rule_count; i++) {
        free_pattern(&rules[i].pattern);
    }
    free(rules);

    char *result = (char*)malloc(out.len + 1);
    memcpy(result, out.data, out.len + 1);
    result[out.len] = 0;

    sb_free(&out);
    return result;
}

char *papagaio_process_ex(const char *input, const char *sigil, const char *open, const char *close, ...) {
    va_list args;
    va_start(args, close);
    char *result = _papagaio_process_ex_impl(NULL, input, sigil, open, close, args);
    va_end(args);
    return result;
}

char *papagaio_process(const char *input, ...) {
    va_list args;
    va_start(args, input);
    char *result = _papagaio_process_ex_impl(NULL, input, "$", "{", "}", args);
    va_end(args);
    return result;
}

char *papagaio_process_pairs(
    VM *vm,
    const char *input,
    const char **patterns,
    const char **repls,
    int pair_count
)
{
    Symbols sym = make_default_symbols("$", "{", "}");
    Rule *rules = (Rule*)malloc(sizeof(Rule) * pair_count);
    if (!rules) return NULL;

    for (int i = 0; i < pair_count; i++) {
        parse_pattern_ex(patterns[i], &rules[i].pattern, &sym);
        rules[i].replacement = repls[i];
    }

    StrBuf out;
    sb_init(&out);
    int len = (int)strlen(input);
    int pos = 0;
    while (pos < len) {
        int matched = 0;
        for (int i = 0; i < pair_count; i++) {
            Match m;
            if (match_pattern(input, len, &rules[i].pattern, pos, &m)) {
                char *r = apply_replacement_ex(rules[i].replacement, &m, &sym, vm);
                sb_append_n(&out, r, strlen(r));
                free(r);
                pos = m.end;
                free_match(&m);
                matched = 1;
                break;
            }
        }
        if (!matched) {
            sb_append_char(&out, input[pos++]);
        }
    }

    for (int i = 0; i < pair_count; i++) {
        free_pattern(&rules[i].pattern);
    }
    free(rules);

    char *result = (char*)malloc(out.len + 1);
    if (!result) {
        sb_free(&out);
        return NULL;
    }
    memcpy(result, out.data, out.len + 1);
    result[out.len] = 0;
    sb_free(&out);
    return result;
}
