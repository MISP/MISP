/*
 * `/values/index` — the prompt's behaviour.
 *
 * **It waits for the DOM.** `assetLoader` puts this script tag above
 * the markup, so a binding made at parse time binds to nothing and the
 * page still draws perfectly — which is how a dead prompt ships
 * looking finished.
 *
 * Five jobs, and the page works without all but the fourth:
 *
 *   1. Enter submits, Shift+Enter makes a line, an empty box cannot
 *      be pressed. Phase 3's.
 *   2. The counter and the verb, live as the reader types.
 *   3. A list is posted to `/values/triage` and its answer swapped in
 *      under the box, rather than reloading the page around a paste
 *      the reader can still see. With no script the same form posts
 *      to `/values/resolve`, which routes a list to the same rows and
 *      renders the whole page.
 *   4. The worklist: each row's assessment fetched on its own, five
 *      lanes at a time, and the batch worked from there. **This one
 *      the page cannot do without** — a row's assessment is a request
 *      and nothing renders it otherwise — which is why every control
 *      that acts on an assessment is hidden until this boots, and why
 *      what is left without it is exactly the list phase 4 shipped.
 *   5. The method note remembers which way this reader left it. A
 *      real `<details>` opens and closes with no script at all; this
 *      only carries the choice to the next page load.
 *   6. Clear puts the box and the region back to how the page
 *      arrived, which without it is a reload — and a reload also
 *      re-reads the tiles, the strip and the carried-over line, none
 *      of which the reader's paste changed. The control is hidden in
 *      the markup and shown from here, so a page whose script never
 *      boots does not offer it.
 */
(function () {
    'use strict';

    function ready(fn) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', fn);
        } else {
            fn();
        }
    }

    /*
     * **A second parser, and deliberately a cruder one.**
     * `ValueInputTool` is the authority and this only has to put a
     * number beside the box before the reader presses: it picks the
     * same separator, strips the same wrapping quotes, splits the same
     * composites and drops the same exact duplicates.
     *
     * What it does not do is refang, because the refang table is
     * `ComplexTypeTool`'s and copying it here would be two tables to
     * keep in step for a number. The only paste where that changes a
     * count is one carrying an indicator in both its fanged and its
     * defanged spelling — two values here, one there. **That is why
     * the button stays pressable over the cap** where the prototype
     * disabled it: a count that can be one high must not be the thing
     * that refuses, so the counter warns and the server, which parsed
     * properly, refuses with the real number.
     */
    var QUOTES = {
        '"': '"',
        "'": "'",
        '`': '`',
        '“': '”',
        '‘': '’'
    };
    /*
     * The same invisible characters `ValueInputTool::TRIM_WIDE`
     * takes — a non-breaking space off a PDF, a zero-width space
     * off a web page, a BOM off an exported CSV — on top of
     * ordinary whitespace. Any of the three makes a field that
     * looks empty count as a value, or one that looks like its
     * neighbour fail to dedupe against it.
     */
    var TRIM = /^[\s\u00a0\u200b\ufeff]+|[\s\u00a0\u200b\ufeff]+$/g;
    /* `preg_split('/\R/')`'s line breaks, as a literal. */
    var BREAK = /\r\n|[\n\r\u000b\f\u0085\u2028\u2029]/;

    function trimValue(text) {
        return text.replace(TRIM, '');
    }

    function unquote(text) {
        if (text.length < 2) {
            return text;
        }
        var close = QUOTES[text.charAt(0)];
        if (close && text.charAt(text.length - 1) === close) {
            return trimValue(text.slice(1, -1));
        }
        return text;
    }

    function fields(raw) {
        var lines = raw.split(BREAK)
            .map(trimValue)
            .filter(function (line) { return line !== ''; });
        if (lines.length > 1) {
            return lines;
        }
        return (lines[0] || '').split(',')
            .map(trimValue)
            .filter(function (field) { return field !== ''; });
    }

    function countValues(raw) {
        var seen = Object.create(null);
        var n = 0;
        fields(raw).forEach(function (field) {
            var value = trimValue(unquote(field));
            if (value === '') {
                return;
            }
            var parts = value.indexOf('|') === -1
                ? [value]
                : [value.slice(0, value.indexOf('|')),
                    value.slice(value.indexOf('|') + 1)];
            parts.forEach(function (part) {
                part = trimValue(unquote(trimValue(part)));
                if (part === '' || seen[part]) {
                    return;
                }
                seen[part] = true;
                n++;
            });
        });
        return n;
    }


    /* ==============================================================
     * The worklist
     * --------------------------------------------------------------
     * The rows arrive from the server with no assessment on them, and
     * this fills each one: **one POST per value, five in flight**, as
     * `02a-contract.md` §12.4 decided and the enrichment strip already
     * fans out. One request that assessed a hundred values would answer
     * when the last one landed; a hundred small ones put the first
     * answers on screen in about ten milliseconds and cost the
     * instance no request held open for the length of the batch.
     *
     * **Nothing here builds a row.** Every state a row can be in —
     * waiting, in flight, assessed, opened, cleared, failed — is
     * markup the server already sent, shown by the row's `data-s` and
     * its classes. A skeleton assembled in JavaScript would be a
     * second place a row's shape is decided, and the two drift; it
     * would also put the §4.2 identity, which is checked as a byte
     * diff of two rendered rows, half in a file no check reads.
     *
     * The two views are the same DOM and the toggle is one class, so
     * switching cannot lose the cursor, the marks, the filter or the
     * sort — which is what the pick asked for when it took A's compact
     * table into C as a second view over one model.
     * ============================================================== */

    /*
     * Five, the same cap the Value Intelligence's enrichment strip uses
     * (`data-vp-eb-max="5"`). It is not optional: a hundred parallel
     * requests is a reader's browser deciding how hard to hit their
     * own instance.
     */
    var LANES = 5;

    /*
     * Worst first: the states an analyst has to act on before the ones
     * they do not. *Nothing asserted* outranks *Asserted benign*
     * because an unknown value is work and a value the record settles
     * is not. *Unflagged* sits above it: the record holds it, and
     * nobody has said what it is.
     */
    var ORDER = { threat: 0, contested: 1, unflagged: 2, none: 3, benign: 4 };

    /*
     * The rail marks, monochrome and in `currentColor` — the state is
     * a shape, never a hue. Hue on this page belongs to the lean, and
     * a rail that took one would put two colour vocabularies in the
     * same 22px gutter.
     */
    var RAIL = {
        todo: '<rect x="2.5" y="2.5" width="7" height="7" rx="1"'
            + ' fill="none" stroke="currentColor" stroke-width="1.3"/>',
        opened: '<rect x="2" y="2" width="8" height="8" rx="1.5"'
            + ' fill="currentColor"/>',
        cleared: '<rect x="2.5" y="2.5" width="7" height="7" rx="1"'
            + ' fill="none" stroke="currentColor" stroke-width="1"'
            + ' opacity=".6"/><path d="M1 6h10" stroke="currentColor"'
            + ' stroke-width="1.4" stroke-linecap="round"/>',
        flight: '<circle cx="6" cy="6" r="3.6" fill="none"'
            + ' stroke="currentColor" stroke-width="1.3"'
            + ' stroke-dasharray="2.2 2.2"/>',
        queued: '<circle cx="6" cy="6" r="1.3" fill="currentColor"/>',
        failed: '<path d="M3 3l6 6M9 3l-6 6" stroke="currentColor"'
            + ' stroke-width="1.4" stroke-linecap="round"/>'
    };

    function esc(text) {
        return String(text).replace(/&/g, '&amp;')
            .replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    /*
     * The `printf` the templates in the markup are written in, with
     * the numbers emphasised. Only `%d` and `%n$d` are understood,
     * because only numbers are ever substituted here — a value never
     * reaches one of these sentences.
     */
    function fill(template, args) {
        var next = 0;
        return esc(template).replace(/%(?:(\d+)\$)?d/g,
            function (whole, position) {
                var index = position ? parseInt(position, 10) - 1 : next++;
                return '<b>' + esc(String(args[index])) + '</b>';
            });
    }

    function rank(lean) {
        return ORDER[lean] === undefined ? ORDER.none : ORDER[lean];
    }

    function landed(row) {
        return row.state !== 'queued' && row.state !== 'flight'
            && row.state !== 'failed';
    }

    function decided(row) {
        return row.state === 'opened' || row.state === 'cleared';
    }

    /*
     * The CSRF token off the prompt's own form. `csrfUseOnce` is off
     * for this controller — `ValuesController::beforeFilter` says
     * why — so one token serves a hundred lanes, which is the property
     * this page needs and the reason that line exists.
     */
    function tokenFor() {
        var field = document.querySelector(
            '[name="data[_Token][key]"]'
        );
        return field ? field.value : null;
    }

    function Work(root) {
        var self = this;
        this.root = root;
        this.url = root.getAttribute('data-vi-assess');
        this.wrap = root.querySelector('.vi-listwrap');
        this.list = root.querySelector('[data-vi-rows]');
        this.tape = root.querySelector('[data-vi-tape]');
        this.progress = root.querySelector('[data-vi-progress]');
        this.note = root.querySelector('[data-vi-sortnote]');
        this.blank = root.querySelector('[data-vi-empty]');
        this.done = root.querySelector('[data-vi-done]');
        this.token = tokenFor();
        this.rows = [];
        Array.prototype.forEach.call(
            this.list.querySelectorAll('.vi-row'),
            function (el, i) {
                var said = el.querySelector('.vi-val');
                self.rows.push({
                    el: el,
                    fill: el.querySelector('[data-vi-fill]'),
                    rail: el.querySelector('[data-vi-rail]'),
                    value: el.getAttribute('data-vi-value'),
                    said: said ? said.textContent : null,
                    state: 'queued',
                    toggled: false,
                    lean: null,
                    signalStrength: null,
                    cell: null,
                    i: i
                });
            }
        );
        this.cur = this.rows[0] || null;
        this.marks = [];
        this.filter = 'all';
        this.sort = 'paste';
        this.flying = 0;
        this.stopped = false;
        this.buildTape();
        this.bind();
        root.classList.add('is-live');
        this.paint();
        this.pump();
    }

    Work.prototype.buildTape = function () {
        if (!this.tape) {
            return;
        }
        var self = this;
        var fragment = document.createDocumentFragment();
        this.rows.forEach(function (row, i) {
            var cell = document.createElement('button');
            cell.type = 'button';
            cell.className = 'vi-cell';
            cell.setAttribute('data-s', 'queued');
            cell.setAttribute('data-vi-jump', String(i));
            cell.setAttribute('aria-label', String(i + 1));
            row.cell = cell;
            fragment.appendChild(cell);
        });
        this.tape.appendChild(fragment);
        this.tape.addEventListener('click', function (event) {
            var cell = event.target.closest('[data-vi-jump]');
            if (!cell) {
                return;
            }
            self.cur = self.rows[parseInt(
                cell.getAttribute('data-vi-jump'), 10
            )] || self.cur;
            self.paint();
            self.reveal();
        });
    };

    Work.prototype.bind = function () {
        var self = this;
        var root = this.root;

        root.querySelectorAll('[data-vi-f]').forEach(function (button) {
            button.addEventListener('click', function () {
                self.filter = button.getAttribute('data-vi-f');
                self.paint();
            });
        });
        var sort = root.querySelector('[data-vi-sort]');
        if (sort) {
            sort.addEventListener('click', function () {
                self.sort = self.sort === 'paste' ? 'worst' : 'paste';
                self.paint();
            });
        }
        /*
         * Which view a reader last used is viewer state rather than
         * anything about a value, and the toggle is a class on the
         * list: the rows are not rebuilt, reordered or refetched, so
         * the cursor, the marks, the filter and the sort all survive
         * the switch by not being involved in it.
         */
        root.querySelectorAll('[data-vi-view]').forEach(function (button) {
            button.addEventListener('click', function () {
                self.wrap.classList.toggle('is-table',
                    button.getAttribute('data-vi-view') === 'table');
                self.paint();
                self.reveal();
            });
        });

        this.list.addEventListener('click', function (event) {
            var button = event.target.closest('[data-vi-act]');
            if (!button) {
                return;
            }
            var row = self.rowOf(button);
            if (!row) {
                return;
            }
            /*
             * The opener is a real anchor and stays one: it is the
             * link every hover card in MISP already offers, and taking
             * the click off it would be this page becoming the one
             * place a profile cannot be opened in a new tab. The mark
             * is made beside the navigation rather than instead of it.
             */
            self.act(button.getAttribute('data-vi-act'), row, button);
        });
        this.list.addEventListener('keydown', function (event) {
            self.key(event);
        });

        if (this.done) {
            var copy = this.done.querySelector('[data-vi-copy]');
            if (copy) {
                copy.addEventListener('click', function () {
                    self.copy();
                });
            }
            var again = this.done.querySelector('[data-vi-again]');
            if (again) {
                again.addEventListener('click', function () {
                    self.rows.forEach(function (row) {
                        if (decided(row)) {
                            row.state = 'todo';
                        }
                    });
                    self.marks = [];
                    self.cur = self.rows[0] || null;
                    self.filter = 'all';
                    self.paint();
                });
            }
        }
    };

    Work.prototype.rowOf = function (node) {
        var el = node.closest('.vi-row');
        if (!el) {
            return null;
        }
        for (var i = 0; i < this.rows.length; i++) {
            if (this.rows[i].el === el) {
                return this.rows[i];
            }
        }
        return null;
    };

    /* ---------------------------------------------------------------
     * The lanes
     * --------------------------------------------------------------- */

    /*
     * Abandoned. The rows go with the region the clear control
     * refills, and a lane that comes back to a detached node writes
     * into nothing — but it has already cost a statement on the
     * server, so the queue stops being fed as well.
     */
    Work.prototype.stop = function () {
        this.stopped = true;
    };

    /* Whether anything in the batch has been opened or cleared. */
    Work.prototype.worked = function () {
        return this.rows.some(decided);
    };

    Work.prototype.pump = function () {
        if (this.stopped) {
            return;
        }
        while (this.flying < LANES) {
            var row = null;
            for (var i = 0; i < this.rows.length; i++) {
                if (this.rows[i].state === 'queued') {
                    row = this.rows[i];
                    break;
                }
            }
            if (!row) {
                break;
            }
            row.state = 'flight';
            this.flying++;
            this.ask(row);
        }
        this.paint();
    };

    Work.prototype.ask = function (row) {
        var self = this;
        var body = new FormData();
        body.append('data[Value][value]', row.value);
        if (this.token) {
            body.append('data[_Token][key]', this.token);
        }
        fetch(this.url, {
            method: 'POST',
            body: body,
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (response) {
            if (!response.ok) {
                throw new Error(String(response.status));
            }
            return response.text();
        }).then(function (html) {
            row.fill.innerHTML = html;
            /*
             * The card names the value as the instance spells it; the
             * row keeps the reader's spelling so a worked list can be
             * read against the report it was pasted from.
             */
            var val = row.fill.querySelector('.vi-val');
            if (val && row.said !== null) {
                val.textContent = row.said;
            }
            var card = row.fill.querySelector('.vi-card');
            var signalStrength = card
                ? card.getAttribute('data-vi-signal-strength')
                : '';
            row.lean = card ? card.getAttribute('data-vi-lean') : null;
            row.signalStrength = signalStrength
                ? parseInt(signalStrength, 10)
                : null;
            row.state = 'todo';
            self.flying--;
            self.pump();
        }).catch(function () {
            /*
             * **A lane that failed is unknown, not empty**, and it is
             * counted in nothing: a row drawn as *nothing asserted*
             * because a request timed out is the one failure on this
             * page that a reader cannot see and would act on.
             */
            row.state = 'failed';
            self.flying--;
            self.pump();
        });
    };

    /* ---------------------------------------------------------------
     * The model
     * --------------------------------------------------------------- */

    Work.prototype.arrange = function () {
        if (this.sort !== 'worst') {
            return this.rows.slice();
        }
        var here = [];
        var coming = [];
        this.rows.forEach(function (row) {
            (landed(row) ? here : coming).push(row);
        });
        /*
         * Sorted on the assessment, and a row without one keeps its
         * place below rather than being ranked on a default — the
         * reader watching rows move needs the ones underneath to mean
         * *not answered yet* and not *least urgent*.
         */
        here.sort(function (a, b) {
            var by = rank(a.lean) - rank(b.lean);
            return by ? by : (b.signalStrength || 0)
                - (a.signalStrength || 0);
        });
        return here.concat(coming);
    };

    Work.prototype.shows = function (row) {
        if (this.filter === 'all') {
            return true;
        }
        if (this.filter === 'opened' || this.filter === 'cleared') {
            return row.state === this.filter;
        }
        return !decided(row);
    };

    Work.prototype.paint = function () {
        var self = this;
        var order = this.arrange();
        var opened = 0;
        var cleared = 0;
        var waiting = 0;
        var failed = 0;
        var here = 0;
        var visible = 0;

        this.rows.forEach(function (row) {
            if (row.state === 'opened') {
                opened++;
            } else if (row.state === 'cleared') {
                cleared++;
            } else if (row.state === 'failed') {
                failed++;
            } else if (!landed(row)) {
                waiting++;
            }
            if (landed(row)) {
                here++;
            }
        });

        order.forEach(function (row) {
            var isCursor = row === self.cur;
            var shown = self.shows(row);
            var open = landed(row) && !decided(row)
                && (row.toggled !== isCursor);
            if (shown) {
                visible++;
            }
            row.el.setAttribute('data-s', row.state);
            row.el.classList.toggle('is-done', decided(row));
            row.el.classList.toggle('is-cursor', isCursor);
            row.el.classList.toggle('is-out', !shown);
            row.el.classList.toggle('is-open', open);
            var disc = row.el.querySelector('.vi-disc');
            if (disc) {
                disc.setAttribute('aria-expanded', String(open));
            }
            if (row.rail) {
                row.rail.innerHTML = '<svg width="12" height="12"'
                    + ' viewBox="0 0 12 12" aria-hidden="true">'
                    + (RAIL[row.state] || RAIL.todo) + '</svg>';
            }
            if (row.cell) {
                row.cell.setAttribute('data-s', row.state);
                row.cell.classList.toggle('is-cursor', isCursor);
            }
        });

        this.reorder(order);
        if (this.blank) {
            this.blank.hidden = visible > 0;
        }
        this.say(here, opened + cleared, failed, waiting);
        this.counts(opened, cleared);
        this.sortNote(here, waiting);
        this.band(opened, cleared);
    };

    Work.prototype.reorder = function (order) {
        var kids = this.list.children;
        var same = kids.length === order.length;
        for (var i = 0; same && i < order.length; i++) {
            if (kids[i] !== order[i].el) {
                same = false;
            }
        }
        if (same) {
            return;
        }
        var fragment = document.createDocumentFragment();
        order.forEach(function (row) {
            fragment.appendChild(row.el);
        });
        this.list.appendChild(fragment);
    };

    /*
     * The one sentence that says where the reader is, and the only
     * thing on this page that is announced: a batch's progress is
     * exactly what somebody who looked away needs told.
     */
    Work.prototype.say = function (here, done, failed, waiting) {
        if (!this.progress) {
            return;
        }
        var total = this.rows.length;
        var text;
        if (waiting > 0) {
            text = fill(this.progress.getAttribute('data-vi-filling'),
                [here, total, done]);
        } else if (done === total) {
            text = fill(this.progress.getAttribute('data-vi-worked'),
                [total]);
        } else {
            text = fill(this.progress.getAttribute('data-vi-left'),
                [done, total, total - done]);
        }
        if (failed) {
            text += ' — ' + fill(
                this.progress.getAttribute('data-vi-lost'), [failed]
            );
        }
        this.progress.innerHTML = text;
    };

    Work.prototype.counts = function (opened, cleared) {
        var self = this;
        var total = this.rows.length;
        var tally = {
            all: total,
            todo: total - opened - cleared,
            opened: opened,
            cleared: cleared
        };
        this.root.querySelectorAll('[data-vi-f]').forEach(function (b) {
            var key = b.getAttribute('data-vi-f');
            b.setAttribute('aria-pressed', String(key === self.filter));
            var slot = b.querySelector('b');
            if (slot) {
                slot.textContent = String(tally[key]);
            }
        });
        var sort = this.root.querySelector('[data-vi-sort]');
        if (sort) {
            sort.setAttribute('aria-pressed',
                String(this.sort === 'worst'));
        }
        var table = this.wrap.classList.contains('is-table');
        this.root.querySelectorAll('[data-vi-view]').forEach(function (b) {
            b.setAttribute('aria-pressed', String(
                (b.getAttribute('data-vi-view') === 'table') === table
            ));
        });
    };

    Work.prototype.sortNote = function (here, waiting) {
        if (!this.note) {
            return;
        }
        if (this.sort !== 'worst') {
            this.note.hidden = true;
            return;
        }
        var self = this;
        this.note.hidden = false;
        this.note.innerHTML = (waiting > 0
            ? fill(this.note.getAttribute('data-vi-mid'), [here, waiting])
            : esc(this.note.getAttribute('data-vi-settled')))
            + ' <button type="button" class="vi-linkish" data-vi-unsort>'
            + esc(this.note.getAttribute('data-vi-back')) + '</button>';
        this.note.querySelector('[data-vi-unsort]')
            .addEventListener('click', function () {
                self.sort = 'paste';
                self.paint();
            });
    };

    /*
     * The end of the batch. A page that writes nothing cannot hand the
     * reader their work back later, so it hands it over now — and says
     * so, rather than letting them find out at the next refresh.
     */
    Work.prototype.band = function (opened, cleared) {
        if (!this.done) {
            return;
        }
        var total = this.rows.length;
        var over = opened + cleared === total && total > 1;
        this.done.hidden = !over;
        if (!over) {
            return;
        }
        var lead = this.done.querySelector('[data-vi-done-lead]');
        var tally = this.done.querySelector('[data-vi-done-counts]');
        var copy = this.done.querySelector('[data-vi-copy]');
        lead.innerHTML = fill(lead.getAttribute('data-vi-tpl'), [total]);
        tally.innerHTML = fill(tally.getAttribute('data-vi-tpl'),
            [opened, cleared]);
        /*
         * *Copy the 0 you opened* is an offer with nothing behind it.
         * A reader who cleared the whole batch has no shortlist to
         * take, and a button that says so is worse than one that is
         * not there.
         */
        copy.hidden = opened === 0;
        copy.innerHTML = fill(copy.getAttribute('data-vi-tpl'), [opened]);
    };

    Work.prototype.copy = function () {
        var box = this.done.querySelector('[data-vi-short]');
        box.hidden = false;
        box.value = this.rows.filter(function (row) {
            return row.state === 'opened';
        }).map(function (row) {
            return row.value;
        }).join('\n');
        box.focus();
        box.select();
        /*
         * The clipboard is the convenience and the selected textarea
         * is the mechanism: a browser may refuse the first, and a
         * reader can always press the two keys themselves.
         */
        try {
            if (navigator.clipboard) {
                var promise = navigator.clipboard.writeText(box.value);
                if (promise && promise.catch) {
                    promise.catch(function () {});
                }
            }
        } catch (error) {
            /* refused: the selection above is still the answer */
        }
    };

    /* ---------------------------------------------------------------
     * Working the batch
     * --------------------------------------------------------------- */

    Work.prototype.act = function (what, row, button) {
        if (what === 'collect') {
            if (typeof window.openModal === 'function') {
                window.openModal(button.getAttribute('data-vi-collect'), 'xl');
            }
            return;
        }
        if (what === 'toggle') {
            row.toggled = !row.toggled;
        } else if (what === 'open' || what === 'clear') {
            this.marks.push({ row: row, was: row.state });
            row.state = what === 'open' ? 'opened' : 'cleared';
            this.advance();
        } else if (what === 'undo') {
            row.state = 'todo';
            this.cur = row;
            this.forget(row);
        } else if (what === 'retry') {
            row.state = 'queued';
            this.pump();
            return;
        }
        this.paint();
    };

    /*
     * `u` undoes the last mark made rather than whatever the cursor
     * happens to sit on: by the time a reader reaches for it the
     * cursor has already moved to the next row.
     */
    Work.prototype.undoLast = function () {
        var mark = this.marks.pop();
        if (!mark) {
            return;
        }
        mark.row.state = mark.was;
        this.cur = mark.row;
        this.paint();
        this.reveal();
    };

    Work.prototype.forget = function (row) {
        this.marks = this.marks.filter(function (mark) {
            return mark.row !== row;
        });
    };

    Work.prototype.advance = function () {
        var order = this.arrange().filter(function (row) {
            return !decided(row);
        });
        if (!order.length) {
            return;
        }
        var at = order.indexOf(this.cur);
        this.cur = order[at + 1 >= order.length ? 0 : at + 1];
    };

    Work.prototype.move = function (step) {
        var self = this;
        var order = this.arrange().filter(function (row) {
            return self.shows(row);
        });
        if (!order.length) {
            return;
        }
        var at = order.indexOf(this.cur) + step;
        this.cur = order[Math.max(0, Math.min(order.length - 1, at))];
        this.paint();
        this.reveal();
    };

    Work.prototype.reveal = function () {
        var el = this.list.querySelector('.vi-row.is-cursor');
        if (el && el.scrollIntoView) {
            el.scrollIntoView({ block: 'nearest' });
        }
    };

    Work.prototype.key = function (event) {
        if (event.ctrlKey || event.metaKey || event.altKey) {
            return;
        }
        var key = event.key;
        if (key === 'j' || key === 'ArrowDown') {
            event.preventDefault();
            this.move(1);
        } else if (key === 'k' || key === 'ArrowUp') {
            event.preventDefault();
            this.move(-1);
        } else if (key === 'o'
            || (key === 'Enter' && event.target === this.list)) {
            event.preventDefault();
            this.opener();
        } else if (key === 'x') {
            event.preventDefault();
            if (this.cur && landed(this.cur)) {
                this.act('clear', this.cur);
            }
        } else if (key === 'u') {
            event.preventDefault();
            this.undoLast();
        } else if (key === 'g') {
            event.preventDefault();
            this.cur = this.arrange()[0] || this.cur;
            this.paint();
            this.reveal();
        }
    };

    /*
     * `o` presses the row's own anchor rather than calling
     * `window.open`: the key is a user gesture, the anchor already
     * carries the target, the `rel` and the URL the page built, and a
     * second way of opening a profile is a second URL to keep right.
     */
    Work.prototype.opener = function () {
        if (!this.cur || !landed(this.cur)) {
            return;
        }
        var link = this.cur.el.querySelector('a[data-vi-act="open"]');
        if (link) {
            link.click();
        }
    };

    function bootWork(scope) {
        if (!window.fetch || !window.FormData) {
            return;
        }
        var root = scope.querySelector('[data-vi-work]');
        if (!root || root.getAttribute('data-vi-booted')) {
            return;
        }
        if (!root.querySelector('.vi-row')) {
            return;
        }
        root.setAttribute('data-vi-booted', '1');
        return new Work(root);
    }

    /*
     * The method note's open state, carried to the next page load.
     *
     * **Viewer state and nothing else.** It records that somebody
     * reads the note or does not, which is neither a fact about a
     * value nor visible to anyone but them — the second of the two
     * exemptions from *nothing writes about a value*
     * (`02a-contract.md` §4.2), and the reason it is `localStorage`
     * rather than a `UserSetting`: a preference the server never needs
     * to know is a round trip the page never needs to make.
     *
     * Every access is guarded. A private window, a browser set to
     * block site data and a thumbnailer all throw on the accessor
     * itself rather than answering null, and a note that took the page
     * down with it would be a broken prompt in exchange for a
     * remembered chevron. No stored value means the default, which is
     * shut.
     */
    var NOTE_KEY = 'valueIndexMethodNote';

    ready(function () {
        var note = document.querySelector('[data-vi-note]');
        if (!note) {
            return;
        }
        var stored = null;
        try {
            stored = window.localStorage.getItem(NOTE_KEY);
        } catch (e) {
            stored = null;
        }
        if (stored === 'open') {
            note.open = true;
        }
        note.addEventListener('toggle', function () {
            try {
                window.localStorage.setItem(
                    NOTE_KEY,
                    note.open ? 'open' : 'shut'
                );
            } catch (e) {
                /* A reader who cannot be remembered still gets to read. */
            }
        });
    });

    ready(function () {
        var form = document.getElementById('vi-prompt');
        if (!form) {
            return;
        }
        var box = form.querySelector('[data-vi-box]');
        var go = form.querySelector('[data-vi-go]');
        if (!box || !go) {
            return;
        }
        var counter = form.querySelector('[data-vi-count]');
        var verb = form.querySelector('[data-vi-verb]');
        var out = document.querySelector('[data-vi-out]');
        var wipe = form.querySelector('[data-vi-clear]');
        var mode = form.querySelector('[data-vi-extract]');
        var blank = document.querySelector('[data-vi-invite]');
        var cap = counter
            ? parseInt(counter.getAttribute('data-vi-cap'), 10) || 100
            : 100;
        var n = 0;
        var busy = false;
        var work = null;
        var asking = false;
        var askTimer = null;
        var wipeWord = wipe
            ? wipe.querySelector('[data-vi-clear-verb]')
            : null;
        var wipeSaid = wipeWord ? wipeWord.textContent : '';

        /*
         * Whether there is anything to clear. The box holding a value
         * is the obvious half; the other is a region showing an answer
         * or a worklist over an empty box, which is what a reader has
         * in front of them after clearing the box by hand.
         */
        function dirty() {
            return box.value !== ''
                || (mode && mode.checked)
                || !!(out && !out.querySelector('.vi-invite'));
        }

        /* Whether the reader asked for the paste to be read as text. */
        function extracting() {
            return !!(mode && mode.checked);
        }

        /*
         * The confirmation lives in the button and expires. A reader
         * who pressed clear by accident does nothing and it goes back
         * to saying *Clear* — the shape a dialog cannot have, since a
         * dialog has to be answered before the page can be used again.
         */
        function ask(on) {
            asking = on;
            if (askTimer) {
                window.clearTimeout(askTimer);
                askTimer = null;
            }
            if (!wipe) {
                return;
            }
            wipe.classList.toggle('is-asking', on);
            if (wipeWord) {
                wipeWord.textContent = on
                    ? wipe.getAttribute('data-vi-ask')
                    : wipeSaid;
            }
            if (on) {
                askTimer = window.setTimeout(function () {
                    ask(false);
                }, 4000);
            }
        }

        /*
         * Clear. The state a reload would reach, minus the reload:
         * the box empty, the region back to its invitation and the
         * batch abandoned. The tiles, the conditions strip and the
         * carried-over line are untouched, because none of them came
         * from what the reader pasted.
         */
        function clear() {
            ask(false);
            if (work) {
                work.stop();
                work = null;
            }
            box.value = '';
            /*
             * The mode goes with the paste it was about. Nothing
             * remembers it between pastes by design, so a page put
             * back to how it arrived is a page with it off.
             */
            if (mode) {
                mode.checked = false;
            }
            if (out && blank && blank.content) {
                out.innerHTML = '';
                out.appendChild(blank.content.cloneNode(true));
                out.removeAttribute('aria-busy');
            }
            say();
            box.focus();
        }

        /*
         * The verb says what pressing will do, which is the whole of
         * how a reader learns this box does two things. One value
         * opens a profile; a list is assessed, and the count is in the
         * label because *Assess* over forty values and *Assess* over
         * four read identically at a glance.
         */
        function say() {
            n = countValues(box.value);
            /*
             * **The counter goes when the mode comes on.** It counts
             * fields, and an extraction's answer is however many
             * indicators are buried in them — a number no parser in
             * this file can produce, since the one that can is
             * `ComplexTypeTool` on the server. A count that cannot be
             * right must not be shown at all: V19 tolerates it being
             * one out against a cap, not it being forty out against
             * the answer.
             */
            var finding = extracting();
            if (counter) {
                counter.hidden = finding;
                counter.innerHTML = '';
                var strong = document.createElement('b');
                strong.textContent = String(n);
                counter.appendChild(strong);
                counter.appendChild(
                    document.createTextNode('/' + cap)
                );
                counter.classList.toggle('is-over',
                    !finding && n > cap);
            }
            if (verb) {
                if (finding) {
                    verb.textContent = verb.getAttribute('data-vi-find');
                } else {
                    verb.textContent = n > 1
                        ? verb.getAttribute('data-vi-many')
                            .replace('%d', String(n))
                        : verb.getAttribute('data-vi-one');
                }
            }
            go.disabled = busy || box.value.trim() === '';
            if (wipe) {
                wipe.hidden = !dirty();
                if (wipe.hidden && asking) {
                    ask(false);
                }
            }
        }

        /*
         * Enter submits and Shift+Enter makes a line, which is the
         * shape every paste box the reader already uses has. It is a
         * textarea rather than an input because a paste is many
         * lines, and a one-line field that grows would change under
         * the reader's cursor between one press and the next.
         */
        box.addEventListener('keydown', function (event) {
            if (event.key !== 'Enter' || event.shiftKey) {
                return;
            }
            if (event.ctrlKey || event.metaKey || event.altKey) {
                return;
            }
            event.preventDefault();
            if (box.value.trim() === '') {
                return;
            }
            if (typeof form.requestSubmit === 'function') {
                form.requestSubmit();
            } else {
                form.submit();
            }
        });

        /*
         * `Esc` clears, and it is bound on the form rather than on the
         * document: the worklist below has its own keys and a page-wide
         * `Esc` would be a second handler competing with every dialog
         * MISP opens over this one. The reader who wants it from the
         * rows has the button, which `Tab` reaches.
         */
        function wipeAsked() {
            if (!dirty()) {
                return;
            }
            if (work && work.worked() && !asking) {
                ask(true);
                return;
            }
            clear();
        }

        form.addEventListener('keydown', function (event) {
            if (event.key !== 'Escape' && event.key !== 'Esc') {
                return;
            }
            if (!dirty()) {
                return;
            }
            event.preventDefault();
            wipeAsked();
        });

        if (wipe) {
            wipe.addEventListener('click', wipeAsked);
            wipe.addEventListener('blur', function () {
                if (asking) {
                    ask(false);
                }
            });
        }

        /*
         * A list is worked in place. A single value is left to the
         * browser, because its answer is a redirect to the profile
         * and following one in script would fetch that whole page to
         * throw it away.
         *
         * A failed fetch does not swallow the press: the form is
         * submitted normally, which is the same answer by the longer
         * road.
         */
        form.addEventListener('submit', function (event) {
            /*
             * **An extraction always goes to `triage`**, however few
             * lines it started from, because its answer is a list —
             * even a list of one, which is an answer about the
             * reader's report and not just about a value. `resolve()`
             * routes the same way for the same reason, so the two
             * roads cannot disagree.
             */
            var listish = extracting()
                ? box.value.trim() !== ''
                : n >= 2;
            if (busy || !listish || !out || !window.fetch) {
                return;
            }
            event.preventDefault();
            busy = true;
            say();
            out.setAttribute('aria-busy', 'true');
            fetch(form.getAttribute('data-vi-triage'), {
                method: 'POST',
                body: new FormData(form),
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            }).then(function (response) {
                if (!response.ok) {
                    throw new Error(String(response.status));
                }
                return response.text();
            }).then(function (html) {
                out.innerHTML = html;
                work = bootWork(out) || null;
                busy = false;
                out.removeAttribute('aria-busy');
                say();
            }).catch(function () {
                busy = false;
                out.removeAttribute('aria-busy');
                form.submit();
            });
        });

        box.addEventListener('input', say);
        if (mode) {
            mode.addEventListener('change', say);
        }
        say();
        /*
         * A worklist that came with the page rather than through the
         * script — the no-JavaScript road, taken by a reader who has
         * JavaScript — is the same block and boots the same way.
         */
        work = bootWork(document) || null;

        /*
         * The caret goes to the end rather than to the start: the box
         * comes back filled after an answer, and a reader correcting
         * what they pasted is at the end of it.
         */
        if (box.value !== '') {
            box.setSelectionRange(box.value.length, box.value.length);
        }
    });
}());
