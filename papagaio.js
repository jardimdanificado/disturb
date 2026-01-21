// papagaio.js - https://github.com/jardimdanificado/papagaio
// papagaio.js is the complete papagaio experience
// also check papagaio.h, a minimal core 

function parsePattern(p, pat) {
    const t = [], S = p.symbols.sigil, O = p.symbols.open, C = p.symbols.close;
    let i = 0;
    while (i < pat.length) {
        if (pat.startsWith(S + p.symbols.regex, i)) {
            let j = i + S.length + p.symbols.regex.length;
            while (j < pat.length && /\s/.test(pat[j])) j++;
            let v = '';
            while (j < pat.length && /[A-Za-z0-9_]/.test(pat[j])) v += pat[j++];
            if (v) {
                while (j < pat.length && /\s/.test(pat[j])) j++;
                if (pat[j] === O) {
                    const [rx, e] = extractBlock(p, pat, j);
                    t.push({ type: 'regex', varName: v, regex: rx.trim() });
                    i = e; continue;
                }
            }
        }
        if (pat[i] === S) {
            let j = i + S.length;
            const isDouble = pat[j] === S;
            if (isDouble) j++;
            if (pat[j] === O) {
                const [od, e1] = extractBlock(p, pat, j);
                if (pat[e1] === O) {
                    const [cd, e2] = extractBlock(p, pat, e1);
                    let v = '', k = e2;
                    while (k < pat.length && /[A-Za-z0-9_]/.test(pat[k])) v += pat[k++];
                    if (v) {
                        const optional = pat[k] === '?';
                        if (optional) k++;
                        t.push({ type: isDouble ? 'blockseq' : 'block', varName: v, open: unescapeDelim(od.trim()) || O, close: unescapeDelim(cd.trim()) || C, optional });
                        i = k; continue;
                    }
                }
            }
            j = i + S.length;
            let v = '';
            while (j < pat.length && /[A-Za-z0-9_]/.test(pat[j])) v += pat[j++];
            if (v) {
                const optional = pat[j] === '?';
                if (optional) j++;
                t.push({ type: 'var', varName: v, optional });
                i = j; continue;
            }
            t.push({ type: 'lit', value: S }); i += S.length; continue;
        }
        if (/\s/.test(pat[i])) {
            while (i < pat.length && /\s/.test(pat[i])) i++;
            t.push({ type: 'ws' }); continue;
        }
        let lit = '';
        while (i < pat.length && pat[i] !== S && !/\s/.test(pat[i])) lit += pat[i++];
        if (lit) t.push({ type: 'lit', value: lit });
    }
    return t;
}

function matchPattern(p, src, tok, pos = 0) {
    let cap = {};
    for (let ti = 0; ti < tok.length; ti++) {
        const t = tok[ti];
        if (t.type === 'ws') { while (pos < src.length && /\s/.test(src[pos])) pos++; continue; }
        if (t.type === 'lit') { if (!src.startsWith(t.value, pos)) return null; pos += t.value.length; continue; }
        if (t.type === 'regex') {
            try {
                const rx = new RegExp(t.regex), m = src.slice(pos).match(rx);
                if (!m || m.index !== 0) return null;
                cap[p.symbols.sigil + t.varName] = m[0];
                pos += m[0].length;
            } catch (e) { return null; }
            continue;
        }
        if (t.type === 'var') {
            while (pos < src.length && /\s/.test(src[pos])) pos++;
            const nx = findNext(tok, ti);
            let v = '';
            if (nx && (nx.type === 'block' || nx.type === 'lit')) {
                const stop = nx.type === 'block' ? nx.open : nx.value;
                while (pos < src.length && !src.startsWith(stop, pos) && src[pos] !== '\n') v += src[pos++];
                v = v.trimEnd();
            } else {
                while (pos < src.length && !/\s/.test(src[pos])) v += src[pos++];
            }
            if (!v && !t.optional) return null;
            cap[p.symbols.sigil + t.varName] = v;
            continue;
        }
        if (t.type === 'blockseq') {
            let blocks = [];
            while (pos < src.length && src.startsWith(t.open, pos)) {
                const [c, e] = extractBlock(p, src, pos, t.open, t.close);
                blocks.push(c);
                pos = e;
                while (pos < src.length && /\s/.test(src[pos])) pos++;
            }
            if (!blocks.length && !t.optional) return null;
            cap[p.symbols.sigil + t.varName] = blocks.join(' ');
            continue;
        }
        if (t.type === 'block') {
            if (!src.startsWith(t.open, pos)) {
                if (t.optional) {
                    cap[p.symbols.sigil + t.varName] = '';
                    continue;
                }
                return null;
            }
            const [c, e] = extractBlock(p, src, pos, t.open, t.close);
            cap[p.symbols.sigil + t.varName] = c; pos = e; continue;
        }
    }
    return { captures: cap, endPos: pos };
}

function findNext(t, i) { for (let k = i + 1; k < t.length; k++) if (t[k].type !== 'ws') return t[k]; return null; }

function extractBlock(p, src, i, od = p.symbols.open, cd = p.symbols.close) {
    if (od.length > 1 || cd.length > 1) {
        if (src.substring(i, i + od.length) === od) {
            i += od.length; const s = i; let d = 0;
            while (i < src.length) {
                if (src.substring(i, i + od.length) === od) { d++; i += od.length; }
                else if (src.substring(i, i + cd.length) === cd) {
                    if (!d) return [src.substring(s, i), i + cd.length];
                    d--; i += cd.length;
                } else i++;
            }
            return [src.substring(s), src.length];
        }
    }
    if (src[i] === od) {
        i++; const s = i;
        if (od === cd) { while (i < src.length && src[i] !== cd) i++; return [src.substring(s, i), i + 1]; }
        let d = 1;
        while (i < src.length && d > 0) { if (src[i] === od) d++; else if (src[i] === cd) d--; if (d > 0) i++; }
        return [src.substring(s, i), i + 1];
    }
    return ['', i];
}

function extractNested(p, txt) {
    const loc = [], S = p.symbols.sigil, O = p.symbols.open;
    let out = txt;
    const rx = new RegExp(`${esc(S)}${esc(p.symbols.pattern)}\\s*${esc(O)}`, "g");
    while (1) {
        rx.lastIndex = 0; const m = rx.exec(out); if (!m) break;
        const s = m.index, o = m.index + m[0].length - O.length;
        const [mp, em] = extractBlock(p, out, o); let k = em;
        while (k < out.length && /\s/.test(out[k])) k++;
        if (k < out.length && out.substring(k, k + O.length) === O) {
            const [rp, er] = extractBlock(p, out, k);
            loc.push({ m: mp.trim(), r: rp.trim() });
            out = out.slice(0, s) + out.slice(er); continue;
        }
        out = out.slice(0, s) + out.slice(em);
    }
    return [loc, out];
}

function extractEvals(p, txt) {
    const ev = [], S = p.symbols.sigil, O = p.symbols.open;
    let i = 0, out = txt, off = 0;
    while (i < txt.length) {
        if (txt.substring(i, i + S.length) === S && txt.substring(i + S.length).startsWith(p.symbols.eval)) {
            let j = i + S.length + p.symbols.eval.length;
            while (j < txt.length && /\s/.test(txt[j])) j++;
            if (j < txt.length && txt.substring(j, j + O.length) === O) {
                const sp = i, bp = j, [c, ep] = extractBlock(p, txt, bp);
                ev.push({ code: c, sp: sp - off, ep: ep - off });
                const ph = `__E${ev.length - 1}__`;
                out = out.substring(0, sp - off) + ph + out.substring(ep - off);
                off += (ep - sp) - ph.length; i = ep; continue;
            }
        }
        i++;
    }
    return [ev, out];
}

function applyEvals(p, txt, ev) {
    let r = txt;
    for (let i = ev.length - 1; i >= 0; i--) {
        const ph = `__E${i}__`;
        try { 
            r = r.replace(ph, String(
                Function("ctx", `"use strict";${ev[i].code}`).call(p, {})
            )); 
        }
        catch (e) { r = r.replace(ph, "error: " + e.message); }
    }
    return r;
}

function applyPats(p, src, pats) {
    for (const pat of pats) {
        const tok = parsePattern(p, pat.m); 
        let n = '', pos = 0, ok = false;
        while (pos < src.length) {
            const m = matchPattern(p, src, tok, pos);
            if (m) {
                ok = true; 
                let r = pat.r;
                const [loc, cln] = extractNested(p, r);
                r = cln;
                Object.keys(m.captures).forEach(k => {
                    r = r.replace(new RegExp(esc(k) + '(?![A-Za-z0-9_])', 'g'), m.captures[k]);
                });
                if (loc.length) r = applyPats(p, r, loc);
                p.match = src.slice(pos, m.endPos);
                const [ev, ct] = extractEvals(p, r);
                if (ev.length) r = applyEvals(p, ct, ev);
                n += r; pos = m.endPos;
            } else { n += src[pos]; pos++; }
        }
        if (ok) src = n;
    }
    return src;
}

function esc(s) { return s.replace(/[.*+?^${}()|[\]\\""']/g, '\\$&'); }
function unescapeDelim(s) {
    let r = ''; 
    for (let i = 0; i < s.length; i++) {
        if (s[i] === '\\' && i + 1 < s.length && (s[i+1] === '"' || s[i+1] === "'" || s[i+1] === '\\')) { r += s[i+1]; i++; }
        else r += s[i];
    }
    return r;
}

export default class Papagaio {
    constructor(sigil = '$', open = '{', close = '}', pattern = 'pattern', evalKw = 'eval', blockKw = 'recursive', regexKw = 'regex', blockseqKw = 'sequential') {
        this.symbols = { pattern, open, close, sigil, eval: evalKw, block: blockKw, regex: regexKw, blockseq: blockseqKw };
        this.content = "";
        this.match = "";
    }
    process(input) {
        const [loc, cln] = extractNested(this, input);
        const [evals, ph] = extractEvals(this, cln);
        let proc = applyEvals(this, ph, evals);
        if (loc.length === 0) {
            this.content = proc;
            return proc;
        }
        let src = proc, last = null;
        while (src !== last) {
            last = src;
            src = applyPats(this, src, loc);
            const [nested] = extractNested(this, src);
            if (nested.length === 0) break;
        }
        this.content = src;
        if (typeof this.exit == "function") this.exit();
        return this.content;
    }
}