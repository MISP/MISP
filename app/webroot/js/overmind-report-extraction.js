/**
 * Manual entity extraction in the Overmind event report editor: the stock
 * theme's "Extract entities > Manual extraction" (js/markdownEditor/
 * event-report.js) without jQuery. eventReports/extractFromReport answers
 * three lists, one tab each:
 *
 *   replacement  text already present as an attribute   → @[attribute](uuid)
 *   context      text naming a tag or a galaxy cluster  → @[tag](name)
 *   extraction   values the freetext tool recognises    → a new attribute
 *
 * Picking a row puts a checkbox on each of its occurrences in the preview; the
 * row's button saves the ticked ones. The preview renders a copy of the text
 * carrying `@[suggestion](n)` markers (see setSuggestionRenderer in
 * misp-report-markdown.js); the editor's own text only changes on a save, so
 * closing the panel discards nothing.
 *
 *   OvReportExtraction.start({ reportId, panel, editorParts, preview,
 *       renderer, getContent, save, onSaved, onClose, strings })
 */
(function () {
    'use strict';

    var ELEMENT_RE = /@!?\[(?:attribute|object|tag|galaxymatrix)\]\([^)\n]*\)/g;
    var TABS = ['replacement', 'context', 'extraction'];

    var active = null;

    function root() {
        return typeof baseurl !== 'undefined' ? baseurl : '';
    }

    function esc(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function toast(message, variant) {
        if (typeof showToast === 'function') {
            showToast(message, variant);
        }
    }

    /* Every place `needle` occurs, case-sensitive, except inside an element
       the report already references (the stock check only looked 10 chars
       back for a 13-char `@[attribute](` and so never matched it). */
    function occurrencesOf(content, needle) {
        var found = [];
        if (!needle) {
            return found;
        }
        var taken = [];
        var match;
        ELEMENT_RE.lastIndex = 0;
        while ((match = ELEMENT_RE.exec(content)) !== null) {
            taken.push([match.index, match.index + match[0].length]);
        }
        var from = 0;
        var at;
        while ((at = content.indexOf(needle, from)) !== -1) {
            var inside = taken.some(function (range) { return at >= range[0] && at < range[1]; });
            if (!inside) {
                found.push({ start: at, length: needle.length, checked: true, rendered: false });
            }
            from = at + needle.length;
        }
        return found;
    }

    function fetchJson(url) {
        return fetch(url, {
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (r) {
            if (!r.ok) {
                throw new Error(r.status + ' ' + r.statusText);
            }
            return r.json();
        });
    }

    function start(options) {
        if (active) {
            return active;
        }
        active = new Extraction(options);
        active.open();
        return active;
    }

    function Extraction(o) {
        this.o = o;
        this.t = o.strings;
        this.tab = null;
        this.rows = { replacement: [], context: [], extraction: [] };
        this.typeToCategory = {};
        this.picked = null;      // { tab, index }
        this.occurrences = [];
        this.current = -1;       // occurrence the prev/next buttons stand on
        this.original = '';
    }

    Extraction.prototype.open = function () {
        var self = this;
        this.o.editorParts.forEach(function (el) { el.classList.add('d-none'); });
        this.o.panel.classList.remove('d-none');
        this.o.panel.innerHTML = this.chrome();
        this.o.panel.addEventListener('click', this.onClick = function (e) { self.click(e); });
        this.o.panel.addEventListener('change', this.onChange = function (e) { self.change(e); });
        this.o.preview.addEventListener('click', this.onPreviewClick = function (e) { self.previewClick(e); });
        this.o.renderer.setSuggestionRenderer(function (n) { return self.pill(n); });
        this.load();
    };

    Extraction.prototype.close = function () {
        this.o.panel.removeEventListener('click', this.onClick);
        this.o.panel.removeEventListener('change', this.onChange);
        this.o.preview.removeEventListener('click', this.onPreviewClick);
        this.o.renderer.setSuggestionRenderer(null);
        this.o.panel.classList.add('d-none');
        this.o.panel.innerHTML = '';
        this.o.editorParts.forEach(function (el) { el.classList.remove('d-none'); });
        active = null;
        if (this.o.onClose) {
            this.o.onClose();
        }
    };

    Extraction.prototype.busy = function (on, label) {
        var veil = this.o.panel.querySelector('[data-x-busy]');
        if (!veil) {
            return;
        }
        veil.classList.toggle('d-none', !on);
        veil.querySelector('[data-x-busy-label]').textContent = label || this.t.working;
    };

    /* ── data ──────────────────────────────────────────────────── */

    Extraction.prototype.load = function () {
        var self = this;
        this.busy(true, this.t.extracting);
        this.original = this.o.getContent();
        return Promise.all([
            fetchJson(root() + '/eventReports/extractFromReport/' + this.o.reportId),
            this.o.renderer.ready
        ]).then(function (results) {
            var data = results[0];
            self.typeToCategory = data.typeToCategoryMapping || self.typeToCategory;
            self.build(data.complexTypeToolResult, data.replacementValues, data.replacementContext);
        }).catch(function (error) {
            toast(self.t.extractFailed + ' ' + error.message, 'danger');
            self.close();
        }).then(function () {
            self.busy(false);
        });
    };

    Extraction.prototype.build = function (entities, values, context) {
        var self = this;
        var content = this.original;
        var renderer = this.o.renderer;

        this.rows.replacement = [];
        Object.keys(values || {}).forEach(function (key) {
            var entry = values[key];
            var attributes = (entry.attributeUUIDs || []).map(function (uuid) {
                return renderer.attribute(uuid);
            }).filter(Boolean);
            var needle = entry.valueInReport;
            if (attributes.length && occurrencesOf(content, needle).length) {
                self.rows.replacement.push({ value: needle, needle: needle, attributes: attributes, chosen: attributes[0].uuid });
            }
        });

        this.rows.context = [];
        Object.keys(context || {}).forEach(function (rawText) {
            var tags = Object.keys(context[rawText]).filter(function (name) { return name !== 'indices'; }).map(function (name) {
                return { name: name, colour: context[rawText][name].colour || '' };
            });
            if (tags.length && occurrencesOf(content, rawText).length) {
                self.rows.context.push({ value: rawText, needle: rawText, tags: tags, chosen: tags[0].name });
            }
        });

        this.rows.extraction = (entities || []).map(function (entity) {
            var type = entity.default_type || (entity.types || [])[0];
            var categories = self.typeToCategory[type] || [];
            return {
                value: entity.value,
                needle: entity.importRegexMatch || entity.original_value || entity.value,
                types: entity.types && entity.types.length ? entity.types : [type],
                type: type,
                category: categories[0] || '',
                toIds: entity.to_ids
            };
        });

        this.picked = null;
        this.occurrences = [];
        if (!this.tab || !this.rows[this.tab].length) {
            this.tab = TABS.filter(function (tab) { return self.rows[tab].length; })[0] || 'extraction';
        }
        this.drawTabs();
        this.drawTable();
        this.renderPreview();
    };

    /* ── panel ─────────────────────────────────────────────────── */

    Extraction.prototype.chrome = function () {
        var t = this.t;
        return '<div class="d-flex align-items-center gap-2 px-2 py-1 border-bottom bg-body-tertiary small">'
            + '<i class="fas fa-highlighter text-report"></i>'
            + '<span class="fw-semibold">' + esc(t.title) + '</span>'
            + '<span class="text-body-secondary d-none d-xl-inline">' + esc(t.hint) + '</span>'
            + '<button type="button" class="btn btn-sm btn-outline-secondary py-0 ms-auto" data-x-close>'
            + '<i class="fas fa-xmark me-1"></i>' + esc(t.close) + '</button></div>'
            + '<div class="d-flex flex-wrap gap-1 px-2 pt-2" role="tablist" data-x-tabs></div>'
            + '<div class="position-relative flex-grow-1 overflow-auto p-2" data-x-table></div>'
            + '<div class="position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center bg-body bg-opacity-75 d-none" style="z-index:5;" data-x-busy>'
            + '<div class="spinner-border spinner-border-sm text-secondary me-2" role="status"></div>'
            + '<span class="small text-body-secondary" data-x-busy-label></span></div>';
    };

    Extraction.prototype.drawTabs = function () {
        var self = this;
        var icons = { replacement: 'misp-icon misp-icon-attribute misp-simple', context: 'misp-icon misp-icon-tag misp-simple', extraction: 'fas fa-wand-magic-sparkles' };
        this.o.panel.querySelector('[data-x-tabs]').innerHTML = TABS.map(function (tab) {
            var on = tab === self.tab;
            return '<button type="button" role="tab" aria-selected="' + on + '" data-x-tab="' + tab + '"'
                + ' class="btn btn-sm d-flex align-items-center gap-2 ' + (on ? 'btn-report' : 'btn-outline-secondary') + '"'
                + ' title="' + esc(self.t['tip_' + tab]) + '">'
                + '<i class="' + icons[tab] + '"></i>' + esc(self.t['tab_' + tab])
                + '<span class="badge rounded-pill ' + (on ? 'text-bg-light' : 'text-bg-secondary') + '">' + self.rows[tab].length + '</span>'
                + '</button>';
        }).join('');
    };

    Extraction.prototype.drawTable = function () {
        var self = this;
        var t = this.t;
        var tab = this.tab;
        var rows = this.rows[tab];
        var box = this.o.panel.querySelector('[data-x-table]');
        if (!rows.length) {
            box.innerHTML = '<div class="text-center text-body-secondary small py-4">' + esc(t['empty_' + tab]) + '</div>';
            return;
        }
        var head = tab === 'extraction'
            ? '<th>' + esc(t.value) + '</th><th>' + esc(t.type) + '</th><th>' + esc(t.category) + '</th>'
            : '<th>' + esc(t.value) + '</th><th>' + esc(tab === 'context' ? t.existingContext : t.existingAttribute) + '</th>';
        var body = rows.map(function (row, i) {
            var picked = self.picked && self.picked.index === i;
            var disabled = picked ? '' : ' disabled';
            var cells = '<td class="fw-semibold text-break">' + esc(row.value) + '</td>';
            if (tab === 'extraction') {
                cells += '<td>' + (row.types.length > 1
                    ? '<select class="form-select form-select-sm" data-x-field="type"' + disabled + '>'
                        + row.types.map(function (type) { return '<option' + (type === row.type ? ' selected' : '') + '>' + esc(type) + '</option>'; }).join('')
                        + '</select>'
                    : '<span class="font-monospace">' + esc(row.type) + '</span>') + '</td>';
                cells += '<td><select class="form-select form-select-sm" data-x-field="category"' + disabled + '>'
                    + (self.typeToCategory[row.type] || []).map(function (category) {
                        return '<option' + (category === row.category ? ' selected' : '') + '>' + esc(category) + '</option>';
                    }).join('') + '</select></td>';
            } else if (tab === 'replacement') {
                cells += '<td>' + (row.attributes.length > 1
                    ? '<select class="form-select form-select-sm" data-x-field="chosen"' + disabled + '>'
                        + row.attributes.map(function (a) {
                            return '<option value="' + esc(a.uuid) + '"' + (a.uuid === row.chosen ? ' selected' : '') + '>'
                                + esc(a.type + ' · #' + a.id + (a.object_relation ? ' (' + a.object_relation + ')' : '')) + '</option>';
                        }).join('') + '</select>'
                    : '<span class="font-monospace">' + esc(row.attributes[0].type) + '</span> <span class="text-body-secondary">#' + esc(row.attributes[0].id) + '</span>') + '</td>';
            } else {
                cells += '<td>' + (row.tags.length > 1
                    ? '<select class="form-select form-select-sm" data-x-field="chosen"' + disabled + '>'
                        + row.tags.map(function (tag) { return '<option' + (tag.name === row.chosen ? ' selected' : '') + '>' + esc(tag.name) + '</option>'; }).join('') + '</select>'
                    : '<span class="badge text-bg-light border text-wrap text-start">' + esc(row.tags[0].name) + '</span>') + '</td>';
            }
            var count = occurrencesOf(self.original, row.needle).length;
            var skipped = picked ? self.occurrences.filter(function (o) { return !o.rendered; }).length : 0;
            cells += '<td class="text-nowrap"><div class="btn-group btn-group-sm" role="group">'
                + '<button type="button" class="btn btn-outline-secondary" data-x-step="-1" title="' + esc(t.previous) + '"' + disabled + '><i class="fas fa-caret-left"></i></button>'
                + '<span class="btn btn-outline-secondary disabled">' + count + '</span>'
                + '<button type="button" class="btn btn-outline-secondary" data-x-step="1" title="' + esc(t.next) + '"' + disabled + '><i class="fas fa-caret-right"></i></button>'
                + '</div>'
                + (skipped ? ' <i class="fas fa-triangle-exclamation text-warning" title="' + esc(t.notRendered.replace('%s', skipped)) + '"></i>' : '')
                + '</td>';
            cells += '<td class="text-end text-nowrap"><button type="button" class="btn btn-sm btn-report" data-x-apply' + disabled + '>'
                + '<i class="fas fa-' + (tab === 'extraction' ? 'wand-magic-sparkles' : 'right-left') + ' me-1"></i>'
                + esc(tab === 'extraction' ? t.extractSave : t.replaceSave) + '</button></td>';
            return '<tr data-x-row="' + i + '" class="' + (picked ? 'table-active' : '') + '" style="cursor:pointer;">' + cells + '</tr>';
        }).join('');
        box.innerHTML = '<table class="table table-sm table-hover align-middle small mb-0">'
            + '<thead><tr>' + head + '<th>' + esc(t.occurrences) + '</th><th></th></tr></thead><tbody>' + body + '</tbody></table>';
    };

    /* ── preview ───────────────────────────────────────────────── */

    Extraction.prototype.pickedRow = function () {
        return this.picked ? this.rows[this.picked.tab][this.picked.index] : null;
    };

    Extraction.prototype.pill = function (n) {
        var o = this.occurrences[n];
        var row = this.pickedRow();
        if (!o || !row) {
            return '';
        }
        var key;
        var shown = row.value;
        if (this.picked.tab === 'extraction') {
            key = row.type;
        } else if (this.picked.tab === 'replacement') {
            var attribute = this.o.renderer.attribute(row.chosen);
            key = attribute ? attribute.type : 'attribute';
        } else {
            key = 'tag';
            shown = row.chosen;
        }
        return '<span class="ov-md-el ov-md-suggestion' + (o.checked ? '' : ' is-off') + '" data-suggestion="' + n + '"'
            + ' role="checkbox" tabindex="0" aria-checked="' + o.checked + '" title="' + esc(this.t.toggle) + '">'
            + '<span class="ov-md-el-k"><input type="checkbox" class="form-check-input me-1" tabindex="-1"' + (o.checked ? ' checked' : '') + '>'
            + esc(key) + '</span><span class="ov-md-el-v">' + esc(shown) + '</span></span>';
    };

    /* The editor's text with each of the picked row's occurrences swapped for
       a marker, which the renderer draws through pill(). */
    Extraction.prototype.renderPreview = function () {
        var self = this;
        var preview = this.o.preview;
        var marked = function (keep) {
            var text = self.original;
            var out = '';
            var pos = 0;
            self.occurrences.forEach(function (o, n) {
                out += text.slice(pos, o.start) + (keep(o) ? '@[suggestion](' + n + ')' : text.substr(o.start, o.length));
                pos = o.start + o.length;
            });
            return out + text.slice(pos);
        };
        this.o.renderer.render(marked(function () { return true; }), preview);
        var missed = 0;
        this.occurrences.forEach(function (o, n) {
            o.rendered = !!preview.querySelector('[data-suggestion="' + n + '"]');
            missed += o.rendered ? 0 : 1;
        });
        // In code a marker is printed as typed: draw the original text there.
        if (missed) {
            this.o.renderer.render(marked(function (o) { return o.rendered; }), preview);
        }
    };

    Extraction.prototype.pick = function (tab, index) {
        if (this.picked && this.picked.tab === tab && this.picked.index === index) {
            return;
        }
        this.picked = { tab: tab, index: index };
        this.current = -1;
        this.occurrences = occurrencesOf(this.original, this.rows[tab][index].needle);
        this.renderPreview();
        this.drawTable();
        this.step(1);
    };

    Extraction.prototype.step = function (delta) {
        var pills = Array.prototype.slice.call(this.o.preview.querySelectorAll('.ov-md-suggestion'));
        if (!pills.length) {
            return;
        }
        this.current = Math.max(0, Math.min(pills.length - 1, this.current + delta));
        pills.forEach(function (pill, i) { pill.classList.toggle('is-current', i === this.current); }, this);
        pills[this.current].scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    };

    Extraction.prototype.previewClick = function (event) {
        var pill = event.target.closest('.ov-md-suggestion');
        if (!pill) {
            return;
        }
        var o = this.occurrences[parseInt(pill.getAttribute('data-suggestion'), 10)];
        if (!o) {
            return;
        }
        o.checked = !o.checked;
        pill.classList.toggle('is-off', !o.checked);
        pill.setAttribute('aria-checked', o.checked);
        pill.querySelector('input').checked = o.checked;
    };

    /* ── controls ──────────────────────────────────────────────── */

    Extraction.prototype.click = function (event) {
        var target = event.target;
        if (target.closest('[data-x-close]')) {
            this.close();
            return;
        }
        var tab = target.closest('[data-x-tab]');
        if (tab) {
            this.tab = tab.getAttribute('data-x-tab');
            this.picked = null;
            this.occurrences = [];
            this.drawTabs();
            this.drawTable();
            this.renderPreview();
            return;
        }
        var stepper = target.closest('[data-x-step]');
        if (stepper) {
            this.step(parseInt(stepper.getAttribute('data-x-step'), 10));
            return;
        }
        if (target.closest('[data-x-apply]')) {
            this.apply();
            return;
        }
        if (target.closest('select')) {
            return;
        }
        var row = target.closest('[data-x-row]');
        if (row) {
            this.pick(this.tab, parseInt(row.getAttribute('data-x-row'), 10));
        }
    };

    Extraction.prototype.change = function (event) {
        var field = event.target.getAttribute('data-x-field');
        var row = this.pickedRow();
        if (!field || !row) {
            return;
        }
        row[field] = event.target.value;
        if (field === 'type') {
            row.category = (this.typeToCategory[row.type] || [])[0] || '';
            this.drawTable();
        }
        this.renderPreview();
        this.step(0);
    };

    /* The editor's text with the ticked, drawn occurrences replaced. */
    Extraction.prototype.contentWith = function (replacement) {
        var text = this.original;
        var out = '';
        var pos = 0;
        var used = 0;
        this.occurrences.forEach(function (o) {
            out += text.slice(pos, o.start);
            if (o.checked && o.rendered) {
                out += replacement;
                used++;
            } else {
                out += text.substr(o.start, o.length);
            }
            pos = o.start + o.length;
        });
        return used ? out + text.slice(pos) : null;
    };

    Extraction.prototype.apply = function () {
        var row = this.pickedRow();
        if (!row) {
            return;
        }
        var self = this;
        if (this.picked.tab === 'extraction') {
            var content = this.contentWith('@[suggestion](' + row.value + ')');
            if (content === null) {
                toast(this.t.noneTicked, 'warning');
                return;
            }
            var mapping = {};
            mapping[row.value] = { type: row.type, category: row.category, to_ids: row.toIds };
            this.busy(true, this.t.applying);
            this.submitSuggestions(content, mapping).then(function (result) {
                var report = result.data.report.EventReport;
                self.o.onSaved(report.content);
                toast(result.message || self.t.applied);
                return self.o.renderer.reloadProxy().then(function () {
                    self.original = self.o.getContent();
                    self.build(result.data.complexTypeToolResult, result.data.replacementValues, result.data.replacementContext);
                });
            }).catch(function (error) {
                toast(self.t.applyFailed + ' ' + error.message, 'danger');
            }).then(function () {
                self.busy(false);
            });
            return;
        }
        var reference = this.picked.tab === 'replacement'
            ? '@[attribute](' + row.chosen + ')'
            : '@[tag](' + row.chosen + ')';
        var replaced = this.contentWith(reference);
        if (replaced === null) {
            toast(this.t.noneTicked, 'warning');
            return;
        }
        this.busy(true, this.t.saving);
        this.o.save(replaced).then(function (saved) {
            if (!saved) {
                self.busy(false);
                return;
            }
            return self.load();
        });
    };

    /* replaceSuggestionInReport's form carries the tokens: fetched, filled
       with {content, mapping} and posted as it came, like the stock editor. */
    Extraction.prototype.submitSuggestions = function (content, mapping) {
        var url = root() + '/eventReports/replaceSuggestionInReport/' + this.o.reportId;
        var headers = { 'X-Requested-With': 'XMLHttpRequest' };
        var t = this.t;
        return fetch(url, { credentials: 'same-origin', headers: headers }).then(function (r) {
            if (!r.ok) {
                throw new Error(r.status + ' ' + r.statusText);
            }
            return r.text();
        }).then(function (html) {
            var form = new DOMParser().parseFromString(html, 'text/html').querySelector('form');
            var field = form && form.querySelector('[name="data[EventReport][suggestions]"]');
            if (!field) {
                throw new Error(t.noForm);
            }
            field.value = JSON.stringify({ content: content, mapping: mapping });
            return fetch(form.getAttribute('action') || url, {
                method: 'POST',
                credentials: 'same-origin',
                headers: headers,
                body: new URLSearchParams(new FormData(form))
            });
        }).then(function (r) {
            return r.json();
        }).then(function (result) {
            if (!result.saved || !result.data || !result.data.report) {
                throw new Error(typeof result.errors === 'string' ? result.errors : (result.message || JSON.stringify(result.errors || result)));
            }
            return result;
        });
    };

    window.OvReportExtraction = {
        start: start,
        isActive: function () { return active !== null; },
        refresh: function () {
            if (active) {
                active.renderPreview();
            }
        }
    };
}());
