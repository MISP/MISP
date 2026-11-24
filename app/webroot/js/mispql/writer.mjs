/*
 * MispQL console: the query writer. A real <textarea> holds the text (its
 * glyphs transparent, its caret visible) over a highlight layer that draws
 * the same text with colours, error underlines and the statement the caret
 * is in. Explain runs as you type; suggestions come from suggest.mjs.
 *
 * new MispQLWriter(host, {
 *     pack, explain(script) -> Promise<{status, body}>,
 *     onRun(statement), onRunAll(statements), onExplain(reply),
 *     placeholder, minRows, maxRows, gutter, recall() -> [statements]
 * })
 */
import * as T from './tokens.mjs';
import * as S from './suggest.mjs';

var AUTO_STATES = {
    from_table: 1, describe_table: 1, cond_start: 1, cond_field: 1, cond_not_op: 1, cond_value: 1,
    order_field: 1, format_name: 1, after_cols: 1, select_cols: 1, select_cols_more: 1,
    cond_field_dot: 1, col_dot: 1, after_table: 1, cond_done: 1, order_after_field: 1,
    after_limit: 1, show_what: 1, order_by_kw: 1, in_after_value: 1
};

var KIND_LABEL = {
    keyword: 'KW', statement: 'ST', client: 'CLI', table: 'TB', column: 'COL', field: 'FLD',
    operator: 'OP', value: 'VAL', sort: 'SRT', format: 'FMT', symbol: 'SYM'
};
var KIND_ICON = {
    keyword: 'fa-solid fa-key', statement: 'fa-solid fa-play', client: 'fa-solid fa-terminal',
    table: 'fa-solid fa-table', column: 'fa-solid fa-table-columns', field: 'fa-solid fa-filter',
    operator: 'fa-solid fa-equals', value: 'fa-solid fa-quote-right', sort: 'fa-solid fa-arrow-down-wide-short',
    format: 'fa-solid fa-file-export', symbol: 'fa-solid fa-code'
};

var uid = 0;
var TYPING_GRACE = 1200;

function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
}

function tokenClass(t) {
    switch (t.kind) {
        case 'keyword':
            return t.value === 'TRUE' || t.value === 'FALSE' ? 'mq-bool' : 'mq-kw';
        case 'string':
            return t.closed ? 'mq-str' : 'mq-str mq-open';
        case 'qname':
            return 'mq-qname';
        case 'number':
            return 'mq-num';
        case 'comment':
            return 'mq-cmt';
        case 'symbol':
            return t.value === ';' || t.value === ',' || t.value === '(' || t.value === ')' || t.value === '.' ? 'mq-punct' : 'mq-op';
        case 'bad':
            return 'mq-bad';
        case 'space':
            return t.unicode ? 'mq-uws' : '';
        case 'name':
            return t.digitWord ? 'mq-name mq-digitword' : 'mq-name';
        default:
            return '';
    }
}

/**
 * Highlighted HTML for a text: one .mq-line per line, segments split at
 * token, error and active-statement boundaries. Also used for the static
 * statements of result cards.
 * errors: [{start, end, code, message}] in string indices.
 */
function highlightHTML(text, errors, active) {
    var tokens = T.tokenize(text);
    errors = errors || [];
    var cuts = { 0: 1 };
    cuts[text.length] = 1;
    tokens.forEach(function (t) { cuts[t.start] = 1; cuts[t.end] = 1; });
    errors.forEach(function (e) { cuts[e.start] = 1; cuts[e.end] = 1; });
    if (active) {
        cuts[active.start] = 1;
        cuts[active.end] = 1;
    }
    for (var i = 0; i < text.length; i++) {
        if (text.charCodeAt(i) === 10) {
            cuts[i] = 1;
            cuts[i + 1] = 1;
        }
    }
    var points = Object.keys(cuts).map(Number).sort(function (a, b) { return a - b; });
    var ti = 0;
    var lines = [[]];
    var eofMarks = {};
    errors.forEach(function (e, k) {
        if (e.start === e.end) {
            eofMarks[e.start] = e.i === undefined ? k : e.i;
        }
    });
    for (var p = 0; p < points.length; p++) {
        var a = points[p];
        if (eofMarks[a] !== undefined) {
            lines[lines.length - 1].push('<span class="mq-err-eof" data-err="' + eofMarks[a] + '"></span>');
        }
        if (p === points.length - 1) {
            break;
        }
        var b = points[p + 1];
        if (a === b) {
            continue;
        }
        var chunk = text.slice(a, b);
        if (chunk === '\n') {
            lines.push([]);
            continue;
        }
        while (ti < tokens.length && tokens[ti].end <= a) {
            ti++;
        }
        var tok = tokens[ti] && tokens[ti].start <= a ? tokens[ti] : null;
        var cls = tok ? tokenClass(tok) : '';
        var errIdx = -1;
        for (var k = 0; k < errors.length; k++) {
            if (errors[k].start < errors[k].end && errors[k].start <= a && b <= errors[k].end) {
                errIdx = k;
                break;
            }
        }
        if (errIdx !== -1) {
            cls += ' mq-err';
        }
        if (active && active.start <= a && b <= active.end) {
            cls += ' mq-act';
        }
        cls = cls.trim();
        lines[lines.length - 1].push(cls
            ? '<span class="' + cls + '" data-at="' + a + '"' + (errIdx !== -1 ? ' data-err="' + (errors[errIdx].i === undefined ? errIdx : errors[errIdx].i) + '"' : '') + '>' + esc(chunk) + '</span>'
            : '<span data-at="' + a + '">' + esc(chunk) + '</span>');
    }
    return lines.map(function (l) {
        return '<div class="mq-line">' + (l.length ? l.join('') : '<br>') + '</div>';
    }).join('');
}

function MispQLWriter(host, options) {
    this.host = host;
    this.opts = Object.assign({ minRows: 3, maxRows: 14, gutter: true, placeholder: '' }, options || {});
    this.pack = this.opts.pack;
    this.errors = [];
    this.statements = null;
    this.explainSeq = 0;
    this.lastReply = null;
    this.sugg = null;
    this.suggIndex = 0;
    this.recallPos = -1;
    this.id = 'mqw' + (++uid);
    this.build();
    this.render();
}

MispQLWriter.highlightHTML = highlightHTML;

MispQLWriter.prototype = {
    build: function () {
        var o = this.opts;
        this.host.classList.add('mql-writer');
        if (o.gutter) {
            this.host.classList.add('mql-has-gutter');
        }
        this.host.innerHTML =
            '<div class="mql-editor">' +
            '<div class="mql-hl" aria-hidden="true"></div>' +
            '<textarea class="mql-input" rows="1" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off"' +
            ' aria-label="MispQL statement" aria-autocomplete="list" aria-haspopup="listbox" aria-expanded="false"' +
            ' aria-controls="' + this.id + '-pop" placeholder="' + esc(o.placeholder) + '"></textarea>' +
            '</div>' +
            '<div class="mql-pop" id="' + this.id + '-pop" role="listbox" aria-label="Suggestions" hidden></div>' +
            '<div class="mql-tip" role="tooltip" hidden></div>';
        this.editor = this.host.querySelector('.mql-editor');
        this.hl = this.host.querySelector('.mql-hl');
        this.ta = this.host.querySelector('.mql-input');
        this.pop = this.host.querySelector('.mql-pop');
        this.tip = this.host.querySelector('.mql-tip');

        var self = this;
        this.ta.addEventListener('input', function (e) { self.onInput(e); });
        this.ta.addEventListener('scroll', function () {
            self.tip.hidden = true;
            self.syncScroll();
        });
        if (o.gutter) {
            document.addEventListener('selectionchange', function () {
                if (document.activeElement === self.ta) {
                    self.markCaretLine();
                }
            });
        }
        this.ta.addEventListener('keydown', function (e) { self.onKeyDown(e); });
        this.ta.addEventListener('keyup', function (e) {
            if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].indexOf(e.key) !== -1) {
                self.render();
                self.updateSuggestions('refresh');
            }
        });
        this.ta.addEventListener('click', function () { self.render(); self.closeSuggestions(); });
        this.ta.addEventListener('blur', function () {
            setTimeout(function () {
                if (document.activeElement !== self.ta) {
                    self.closeSuggestions();
                }
            }, 120);
        });
        this.ta.addEventListener('mousemove', function (e) { self.onHover(e); });
        this.ta.addEventListener('mouseleave', function () { self.tip.hidden = true; });
        this.pop.addEventListener('mousedown', function (e) {
            var row = e.target.closest('[data-i]');
            e.preventDefault();
            if (row) {
                self.suggIndex = Number(row.getAttribute('data-i'));
                self.accept();
            }
        });
        if (window.ResizeObserver) {
            new ResizeObserver(function () { self.fit(); }).observe(this.editor);
        }
    },

    get value() { return this.ta.value; },

    /** Replaces the text through the native editing commands, so undo still works. */
    setValue: function (text, caret) {
        this.ta.focus();
        this.ta.setSelectionRange(0, this.ta.value.length);
        this.inserting = true;
        var native = text === '' ? document.execCommand('delete', false) : document.execCommand('insertText', false, text);
        this.inserting = false;
        this.lastInputAt = 0;
        if (!native || this.ta.value !== text) {
            this.ta.value = text;
            this.changed();
        }
        var at = caret === undefined ? text.length : caret;
        this.ta.setSelectionRange(at, at);
        this.closeSuggestions();
        this.render();
    },

    focus: function () { this.ta.focus(); },

    /** Inserts at the caret, as typing would (undo keeps working). */
    insert: function (text) {
        this.ta.focus();
        var s = this.ta.selectionStart;
        var e = this.ta.selectionEnd;
        var before = this.ta.value.charAt(s - 1);
        if (before && !/[\s(,.]/.test(before)) {
            text = ' ' + text;
        }
        this.inserting = true;
        var native = document.execCommand('insertText', false, text);
        this.inserting = false;
        if (!native) {
            this.ta.setRangeText(text, s, e, 'end');
            this.changed();
        }
        this.render();
    },

    onInput: function (e) {
        this.recallPos = -1;
        this.lastInputAt = Date.now();
        this.changed();
        if (this.inserting) {
            return;
        }
        var data = e.data || '';
        if (e.inputType === 'insertText' && /^[A-Za-z0-9_`]$/.test(data)) {
            this.updateSuggestions('typing');
        } else if (e.inputType === 'insertText' && /^[ .,(]$/.test(data)) {
            this.updateSuggestions('auto');
        } else if (e.inputType === 'deleteContentBackward') {
            this.updateSuggestions('refresh');
        } else {
            this.closeSuggestions();
        }
    },

    changed: function () {
        var text = this.ta.value;
        var prev = this.prevText || '';
        var cut = 0;
        while (cut < prev.length && cut < text.length && prev.charCodeAt(cut) === text.charCodeAt(cut)) {
            cut++;
        }
        // Until explain answers, only what lies before the edit keeps its offsets.
        this.errors = this.errors.filter(function (e) { return e.from < e.to && e.to <= cut; });
        this.statements = null;
        this.prevText = text;
        this.tip.hidden = true;
        this.render();
        this.scheduleExplain();
        if (this.opts.onChange) {
            this.opts.onChange(this.ta.value);
        }
    },

    scheduleExplain: function () {
        var self = this;
        clearTimeout(this.explainTimer);
        var seq = ++this.explainSeq;
        var text = this.ta.value;
        if (!text.trim()) {
            this.errors = [];
            this.statements = [];
            this.lastReply = null;
            this.render();
            this.emitExplain(null);
            return;
        }
        this.explainTimer = setTimeout(function () {
            self.opts.explain(text).then(function (reply) {
                if (seq !== self.explainSeq) {
                    return;
                }
                self.applyExplain(text, reply);
            });
        }, 220);
    },

    /** Explain's reply -> underlines and statement boundaries, converted from code points. */
    applyExplain: function (text, reply) {
        if (text !== this.ta.value) {
            return;
        }
        this.lastReply = reply;
        if (reply.status === 200) {
            this.errors = [];
            this.statements = reply.body.statements.map(function (s) {
                var r = T.cpRangeToIndex(text, s.start, s.end);
                return Object.assign({}, s, { from: r.start, to: r.end });
            });
        } else {
            this.statements = null;
            this.errors = (reply.body.errors || []).map(function (e) {
                var r = T.cpRangeToIndex(text, e.start, e.end);
                return Object.assign({}, e, { from: r.start, to: r.end });
            });
        }
        this.render();
        this.emitExplain(reply);
    },

    emitExplain: function (reply) {
        if (this.opts.onExplain) {
            this.opts.onExplain(reply, this);
        }
    },

    /** Statement ranges: explain's when it succeeded, else the ';' tokens. */
    ranges: function () {
        var text = this.ta.value;
        if (this.statements && this.lastReply && this.lastReply.status === 200) {
            return this.statements.map(function (s, i) {
                return { from: s.from, to: s.to, index: i, plan: s };
            });
        }
        return T.splitStatements(text).map(function (r, i) {
            return { from: r.start, to: r.end, index: i, plan: null };
        });
    },

    statementAtCursor: function () {
        var text = this.ta.value;
        var caret = this.ta.selectionStart;
        var ranges = this.ranges();
        if (!ranges.length) {
            return null;
        }
        var pick = ranges[0];
        for (var i = 0; i < ranges.length; i++) {
            if (ranges[i].from <= caret) {
                pick = ranges[i];
            }
        }
        for (var j = 0; j < ranges.length; j++) {
            if (ranges[j].from <= caret && caret <= ranges[j].to) {
                pick = ranges[j];
            }
        }
        return Object.assign({ text: text.slice(pick.from, pick.to), count: ranges.length }, pick);
    },

    allStatements: function () {
        var text = this.ta.value;
        return this.ranges().map(function (r) {
            return Object.assign({ text: text.slice(r.from, r.to) }, r);
        });
    },

    /**
     * Errors to draw. One at the caret waits until typing pauses, so the
     * word being written is not flagged before it is finished.
     */
    visibleErrors: function () {
        var wait = TYPING_GRACE - (Date.now() - (this.lastInputAt || 0));
        if (wait <= 0) {
            return this.errors;
        }
        var caret = this.ta.selectionStart;
        var text = this.ta.value;
        var shown = this.errors.filter(function (e) {
            return !(e.from <= caret && (caret <= e.to || /^\s*$/.test(text.slice(e.to, caret))));
        });
        if (shown.length !== this.errors.length) {
            var self = this;
            clearTimeout(this.graceTimer);
            this.graceTimer = setTimeout(function () {
                self.render();
                self.emitExplain(self.lastReply);
            }, wait + 20);
        }
        return shown;
    },

    render: function () {
        var text = this.ta.value;
        var visible = this.visibleErrors();
        var all = this.errors;
        var errs = visible.map(function (e) { return { start: e.from, end: e.to, code: e.code, message: e.message, i: all.indexOf(e) }; });
        var active = null;
        if (text.trim()) {
            var ranges = this.ranges();
            if (ranges.length > 1) {
                var st = this.statementAtCursor();
                active = st ? { start: st.from, end: st.to } : null;
            }
        }
        this.hl.innerHTML = highlightHTML(text, errs, active) + '<div class="mq-line mq-tail"><br></div>';
        this.host.classList.toggle('is-empty', !text);
        this.host.classList.toggle('has-errors', errs.length > 0);
        this.host.classList.toggle('is-writing', errs.length < all.length);
        if (!this.tip.hidden && visible.indexOf(this.tipErr) === -1) {
            this.tip.hidden = true;
        }
        if (this.opts.gutter) {
            var digits = String(this.hl.children.length - 1).length;
            if (digits !== this.digits) {
                this.digits = digits;
                this.host.style.setProperty('--mql-digits', Math.max(2, digits));
            }
            this.markCaretLine();
        }
        this.fit();
        this.syncScroll();
    },

    /** Marks the caret's line, whose number the gutter shows brighter. */
    markCaretLine: function () {
        var text = this.ta.value;
        var caret = this.ta.selectionStart;
        var line = 0;
        for (var i = text.indexOf('\n'); i !== -1 && i < caret; i = text.indexOf('\n', i + 1)) {
            line++;
        }
        var el = this.hl.children[line] || null;
        if (el === this.caretLine) {
            return;
        }
        if (this.caretLine) {
            this.caretLine.classList.remove('is-caret');
        }
        if (el) {
            el.classList.add('is-caret');
        }
        this.caretLine = el;
    },

    fit: function () {
        var cs = getComputedStyle(this.ta);
        var line = parseFloat(cs.lineHeight) || 20;
        var padding = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom);
        var tail = this.hl.querySelector('.mq-tail');
        var content = tail ? tail.offsetTop : this.hl.scrollHeight;
        var min = this.opts.minRows * line + padding;
        var max = this.opts.maxRows * line + padding;
        var h = Math.max(min, Math.min(max, content + padding / 2));
        this.editor.style.height = Math.ceil(h) + 'px';
    },

    syncScroll: function () {
        this.hl.scrollTop = this.ta.scrollTop;
        this.hl.scrollLeft = this.ta.scrollLeft;
    },

    onHover: function (e) {
        if (!this.errors.length) {
            this.tip.hidden = true;
            return;
        }
        var spans = this.hl.querySelectorAll('[data-err]');
        var hit = null;
        for (var i = 0; i < spans.length && !hit; i++) {
            var rects = spans[i].getClientRects();
            for (var j = 0; j < rects.length; j++) {
                var r = rects[j];
                if (e.clientX >= r.left - 2 && e.clientX <= r.right + 6 && e.clientY >= r.top - 2 && e.clientY <= r.bottom + 4) {
                    hit = { el: spans[i], rect: r };
                    break;
                }
            }
        }
        if (!hit) {
            this.tip.hidden = true;
            return;
        }
        var err = this.errors[Number(hit.el.getAttribute('data-err'))];
        if (!err || this.sugg) {
            return;
        }
        this.tipErr = err;
        this.tip.innerHTML = '<span class="mq-code">' + esc(err.code) + '</span>' + esc(err.message) +
            (err.path ? '<span class="mq-path">' + esc(err.path) + '</span>' : '');
        this.tip.hidden = false;
        var hostRect = this.host.getBoundingClientRect();
        var left = Math.min(hit.rect.left - hostRect.left, hostRect.width - this.tip.offsetWidth - 4);
        var top = hit.rect.bottom - hostRect.top + 6;
        if (hit.rect.bottom + this.tip.offsetHeight + 12 > window.innerHeight) {
            top = hit.rect.top - hostRect.top - this.tip.offsetHeight - 6;
        }
        this.tip.style.left = Math.max(0, left) + 'px';
        this.tip.style.top = top + 'px';
    },

    onKeyDown: function (e) {
        var mod = e.ctrlKey || e.metaKey;
        if (mod && e.key === 'Enter') {
            e.preventDefault();
            this.closeSuggestions();
            if (e.shiftKey && this.opts.onRunAll) {
                this.opts.onRunAll(this.allStatements());
            } else if (this.opts.onRun) {
                var st = this.statementAtCursor();
                if (st) {
                    this.opts.onRun(st);
                }
            }
            return;
        }
        if (mod && (e.key === ' ' || e.code === 'Space')) {
            e.preventDefault();
            this.updateSuggestions('force');
            return;
        }
        if (this.sugg && this.sugg.items.length) {
            var n = this.sugg.items.length;
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                this.suggIndex = (this.suggIndex + (e.key === 'ArrowDown' ? 1 : n - 1)) % n;
                this.drawSuggestions();
                return;
            }
            if (e.key === 'PageDown' || e.key === 'PageUp') {
                e.preventDefault();
                this.suggIndex = Math.max(0, Math.min(n - 1, this.suggIndex + (e.key === 'PageDown' ? 8 : -8)));
                this.drawSuggestions();
                return;
            }
            if ((e.key === 'Enter' && !e.shiftKey) || e.key === 'Tab') {
                e.preventDefault();
                this.accept();
                return;
            }
            if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                this.closeSuggestions();
                return;
            }
        } else if (e.key === 'Escape' && this.sugg) {
            this.closeSuggestions();
        }
        if ((e.key === 'ArrowUp' || e.key === 'ArrowDown') && this.opts.recall && !e.shiftKey && !mod && !e.altKey) {
            this.recall(e);
        }
    },

    recall: function (e) {
        var text = this.ta.value;
        var caret = this.ta.selectionStart;
        var up = e.key === 'ArrowUp';
        var onEdge = up ? text.lastIndexOf('\n', caret - 1) === -1 : text.indexOf('\n', caret) === -1;
        if (!onEdge || (text.trim() && this.recallPos === -1)) {
            return;
        }
        var list = this.opts.recall();
        if (!list.length) {
            return;
        }
        var pos = this.recallPos + (up ? 1 : -1);
        if (pos < -1 || pos >= list.length) {
            return;
        }
        e.preventDefault();
        this.recallPos = pos;
        var next = pos === -1 ? '' : list[pos];
        this.setValue(next);
        this.recallPos = pos;
    },

    /**
     * mode: typing (a word character: needs a prefix), auto (after a space
     * or punctuation: only where the next word is predictable), force
     * (Ctrl-Space), refresh (only while the popover is open).
     */
    updateSuggestions: function (mode) {
        var caret = this.ta.selectionStart;
        if (caret !== this.ta.selectionEnd) {
            return this.closeSuggestions();
        }
        if (mode === 'refresh' && !this.sugg) {
            return;
        }
        var s = S.suggest(this.ta.value, caret, this.pack);
        var show = s.items.length > 0 || (mode === 'force' && s.hint);
        if (mode === 'typing') {
            show = show && (s.prefix !== '' || this.sugg !== null);
        } else if (mode === 'auto') {
            show = show && (s.prefix !== '' || AUTO_STATES[s.state] === 1);
        }
        if (!show) {
            return this.closeSuggestions();
        }
        var keep = this.sugg && this.sugg.items[this.suggIndex];
        this.sugg = s;
        this.suggIndex = 0;
        if (keep) {
            for (var i = 0; i < s.items.length; i++) {
                if (s.items[i].label === keep.label && s.items[i].kind === keep.kind) {
                    this.suggIndex = i;
                    break;
                }
            }
        }
        this.drawSuggestions();
    },

    closeSuggestions: function () {
        this.sugg = null;
        this.pop.hidden = true;
        this.ta.setAttribute('aria-expanded', 'false');
        this.ta.removeAttribute('aria-activedescendant');
    },

    drawSuggestions: function () {
        var s = this.sugg;
        var self = this;
        var prefix = s.prefix.toLowerCase();
        var rows = s.items.slice(0, 60).map(function (it, i) {
            var label = esc(it.label);
            var at = prefix ? it.label.toLowerCase().indexOf(prefix) : -1;
            if (at !== -1) {
                label = esc(it.label.slice(0, at)) + '<mark>' + esc(it.label.slice(at, at + prefix.length)) + '</mark>' +
                    esc(it.label.slice(at + prefix.length));
            }
            return '<div class="mql-opt' + (i === self.suggIndex ? ' is-active' : '') + '" role="option" id="' + self.id + '-o' + i +
                '" aria-selected="' + (i === self.suggIndex) + '" data-i="' + i + '">' +
                '<span class="mql-kind mql-kind-' + it.kind + '" title="' + it.kind + '"><i class="' + KIND_ICON[it.kind] + '"></i></span>' +
                '<span class="mql-label">' + label + '</span>' +
                (it.detail ? '<span class="mql-detail' + (it.kind === 'field' ? ' mql-type mql-type-' + esc(it.detail) : '') + '">' + esc(it.detail) + '</span>' : '') +
                '</div>';
        }).join('');
        var cur = s.items[this.suggIndex];
        var info = '';
        if (cur && cur.kind === 'field') {
            info = '<div class="mql-info"><div class="mql-info-head"><code>' + esc(cur.label) + '</code>' +
                '<span class="mql-type mql-type-' + esc(cur.detail) + '">' + esc(cur.detail) + '</span>' +
                '<span class="mql-level">' + esc(cur.level.join(' · ')) + '</span></div>' +
                '<div class="mql-ops">' + cur.operators.map(function (op) { return '<code>' + esc(op) + '</code>'; }).join('') + '</div>' +
                '<div class="mql-doc">' + esc(cur.doc || '') + (cur.note ? '<br><span class="mql-note">' + esc(cur.note) + '</span>' : '') + '</div></div>';
        } else if (cur && (cur.doc || cur.kind === 'client')) {
            info = '<div class="mql-info"><div class="mql-doc">' +
                (cur.kind === 'client' ? 'Switches between MISP servers: runs in the mispql CLI, not in this console.' : esc(cur.doc)) +
                '</div></div>';
        }
        var hint = s.hint ? '<div class="mql-pop-hint"><i class="fa-solid fa-circle-info"></i>' + esc(s.hint) + '</div>' : '';
        this.pop.innerHTML = '<div class="mql-pop-list">' + rows + '</div>' + info + hint +
            '<div class="mql-pop-foot"><span><kbd>↑</kbd><kbd>↓</kbd> choose</span><span><kbd>↵</kbd> insert</span><span><kbd>esc</kbd> close</span></div>';
        this.pop.hidden = false;
        this.tip.hidden = true;
        this.ta.setAttribute('aria-expanded', 'true');
        this.ta.setAttribute('aria-activedescendant', this.id + '-o' + this.suggIndex);
        var active = this.pop.querySelector('.is-active');
        if (active) {
            var list = this.pop.querySelector('.mql-pop-list');
            if (active.offsetTop < list.scrollTop) {
                list.scrollTop = active.offsetTop - 4;
            } else if (active.offsetTop + active.offsetHeight > list.scrollTop + list.clientHeight) {
                list.scrollTop = active.offsetTop + active.offsetHeight - list.clientHeight + 4;
            }
        }
        this.placePopover();
    },

    /** Caret position from the highlight layer, which lays the text out like the textarea. */
    caretRect: function (index) {
        var spans = this.hl.querySelectorAll('[data-at]');
        var target = null;
        for (var i = 0; i < spans.length; i++) {
            var at = Number(spans[i].getAttribute('data-at'));
            var len = spans[i].textContent.length;
            if (at <= index && index <= at + len) {
                target = { el: spans[i], offset: index - at };
                if (index < at + len) {
                    break;
                }
            }
        }
        if (!target) {
            var r = this.hl.getBoundingClientRect();
            var cs = getComputedStyle(this.ta);
            return { left: r.left + parseFloat(cs.paddingLeft), top: r.top + parseFloat(cs.paddingTop), bottom: r.top + parseFloat(cs.paddingTop) + parseFloat(cs.lineHeight) };
        }
        var range = document.createRange();
        var node = target.el.firstChild;
        range.setStart(node, Math.min(target.offset, node.length));
        range.setEnd(node, Math.min(target.offset, node.length));
        var rects = range.getClientRects();
        var rect = rects.length ? rects[rects.length - 1] : target.el.getBoundingClientRect();
        return { left: rect.left, top: rect.top, bottom: rect.bottom };
    },

    placePopover: function () {
        var caret = this.caretRect(this.sugg.from);
        var host = this.host.getBoundingClientRect();
        var pop = this.pop;
        var w = pop.offsetWidth;
        var h = pop.offsetHeight;
        var left = caret.left - host.left - 30;
        left = Math.max(0, Math.min(left, host.width - w));
        var below = caret.bottom + 6;
        var top;
        if (below + h > window.innerHeight - 8 && caret.top - h - 6 > 8) {
            top = caret.top - host.top - h - 6;
            pop.classList.add('is-above');
        } else {
            top = caret.bottom - host.top + 6;
            pop.classList.remove('is-above');
        }
        pop.style.left = left + 'px';
        pop.style.top = top + 'px';
    },

    accept: function () {
        var s = this.sugg;
        var it = s && s.items[this.suggIndex];
        if (!it) {
            return;
        }
        var text = this.ta.value;
        var insert = it.insert;
        if (it.label === ',') {
            insert = ', ';
        } else if (it.label === ')' && s.state !== 'in_after_value') {
            insert = ') ';
        }
        // Reuse a space already after the word instead of doubling it.
        var skip = insert.slice(-1) === ' ' && /\s/.test(text.charAt(s.to));
        if (skip) {
            insert = insert.slice(0, -1);
        }
        this.ta.focus();
        this.ta.setSelectionRange(s.from, s.to);
        this.inserting = true;
        var native = document.execCommand('insertText', false, insert);
        this.inserting = false;
        if (!native) {
            this.ta.setRangeText(insert, s.from, s.to, 'end');
            this.changed();
        }
        if (skip) {
            var p = this.ta.selectionStart + 1;
            this.ta.setSelectionRange(p, p);
        }
        this.closeSuggestions();
        this.render();
        if (it.chain) {
            this.updateSuggestions('auto');
        }
    },

    /** The error under the caret, else the first one: for the status line. */
    focusError: function () {
        var errors = this.visibleErrors();
        if (!errors.length) {
            return null;
        }
        var caret = this.ta.selectionStart;
        for (var i = 0; i < errors.length; i++) {
            if (errors[i].from <= caret && caret <= errors[i].to) {
                return errors[i];
            }
        }
        return errors[0];
    },

    selectRange: function (from, to) {
        this.ta.focus();
        this.ta.setSelectionRange(from, to);
        this.render();
    }
};

export { MispQLWriter, highlightHTML };
