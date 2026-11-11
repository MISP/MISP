/**
 * misp-report-extraction.js — manual entity extraction for the Overmind
 * report editor (Edit Content tab), the counterpart of the stock theme's
 * "Extract entities > Manual extraction".
 *
 * /eventReports/extractFromReport/<id> lists what the saved report holds:
 *   - values the freetext tool recognises (new attributes),
 *   - values of the event's attributes the report does not reference yet,
 *   - tag and galaxy names (context).
 * Picking one marks its occurrences in the preview as ticked
 * `@[suggestion](n)` pills; applying replaces the ticked ones and saves.
 * A new attribute goes through /eventReports/replaceSuggestionInReport/<id>,
 * which creates it and writes its reference; the other two are plain saves.
 *
 * Usage:
 *   var x = MispReportExtraction.create({reportId, renderer, panel, preview,
 *       labels, getContent, save, onSaved, onClose});
 *   x.open();
 */
(function (window, document) {
    'use strict';

    if (window.MispReportExtraction) { return; }

    var ELEMENT_RE = /@!?\[(?:attribute|object|tag|galaxymatrix|suggestion)\]\([^)\n]*\)/g;
    var KINDS = ['new', 'existing', 'context'];

    function base() {
        return typeof window.baseurl === 'string' ? window.baseurl : '';
    }

    function esc(value) {
        return String(value === undefined || value === null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function format(template, values) {
        return String(template).replace(/%(\w+)/g, function (match, key) {
            return values[key] === undefined ? match : values[key];
        });
    }

    function toast(message, variant) {
        if (typeof window.showToast === 'function') { window.showToast(message, variant); }
    }

    /* Where the needle stands in the report, leaving out the places that are
       already a MISP element: `@[attribute](…)` must not be offered again. */
    function findOccurrences(content, needle) {
        var taken = [];
        var match;
        ELEMENT_RE.lastIndex = 0;
        while ((match = ELEMENT_RE.exec(content)) !== null) {
            taken.push([match.index, match.index + match[0].length]);
        }
        var found = [];
        if (!needle) { return found; }
        var from = 0;
        var index;
        while ((index = content.indexOf(needle, from)) !== -1) {
            var end = index + needle.length;
            var inside = taken.some(function (range) {
                return index < range[1] && end > range[0];
            });
            if (!inside) { found.push({start: index, end: end}); }
            from = end;
        }
        return found;
    }

    function errorText(data, fallback) {
        var reasons = [];
        (function walk(value) {
            if (Array.isArray(value)) { value.forEach(walk); }
            else if (value && typeof value === 'object') {
                Object.keys(value).forEach(function (key) { walk(value[key]); });
            } else if (value) { reasons.push(String(value)); }
        })(data && data.errors);
        return reasons.length ? reasons.join(' ') : ((data && data.message) || fallback);
    }

    function Extraction(options) {
        this.reportId = options.reportId;
        this.renderer = options.renderer;
        this.panel = options.panel;
        this.preview = options.preview;
        this.L = options.labels || {};
        this.getContent = options.getContent;
        this.save = options.save;
        this.onSaved = options.onSaved || function () {};
        this.onClose = options.onClose || function () {};

        this.list = this.panel.querySelector('[data-x-list]');
        this.tabs = this.panel.querySelectorAll('[data-x-tab]');
        this.active = null;
        this.rows = {new: [], existing: [], context: []};
        this.picked = null;
        this.busy = false;
        this.isOpen = false;
        this.typeToCategory = {};
        this.defaultCategories = {};

        this._bind();
    }

    Extraction.prototype._bind = function () {
        var self = this;
        Array.prototype.forEach.call(this.tabs, function (tab) {
            tab.addEventListener('click', function () {
                self._showTab(tab.getAttribute('data-x-tab'));
            });
        });

        this.list.addEventListener('click', function (event) {
            if (event.target.closest('select, button, label')) { return; }
            var row = event.target.closest('[data-x-row]');
            if (row) { self._pick(Number(row.getAttribute('data-x-row'))); }
        });
        this.list.addEventListener('keydown', function (event) {
            var row = event.target.closest('[data-x-row]');
            if (!row || event.target !== row) { return; }
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                self._pick(Number(row.getAttribute('data-x-row')));
            }
        });
        this.list.addEventListener('change', function (event) {
            var field = event.target.getAttribute('data-x-field');
            if (!field || !self.picked) { return; }
            self.picked[field] = event.target.value;
            if (field === 'type') {
                self.picked.category = self._defaultCategory(self.picked.type);
                self._drawList();
            }
            self._paint();
        });
        this.list.addEventListener('click', function (event) {
            var button = event.target.closest('[data-x-action]');
            if (!button || !self.picked) { return; }
            var action = button.getAttribute('data-x-action');
            if (action === 'prev') { self._step(-1); }
            else if (action === 'next') { self._step(1); }
            else if (action === 'apply') { self._apply(); }
        });

        var toggle = function (node) {
            if (!self.picked) { return; }
            var index = Number(node.getAttribute('data-suggestion'));
            self.picked.checked[index] = !self.picked.checked[index];
            self.picked.current = index;
            self._paint();
        };
        this.preview.addEventListener('click', function (event) {
            if (!self.isOpen) { return; }
            var node = event.target.closest('[data-suggestion]');
            if (node) { toggle(node); }
        });
        this.preview.addEventListener('keydown', function (event) {
            if (!self.isOpen || (event.key !== ' ' && event.key !== 'Enter')) { return; }
            var node = event.target.closest('[data-suggestion]');
            if (node) { event.preventDefault(); toggle(node); }
        });

        this.renderer.setSuggestionSource(function (index) {
            var row = self.picked;
            if (!row || !row.occ[index]) { return null; }
            return {
                key: self._pillKey(row),
                value: row.needle,
                checked: !!row.checked[index],
                current: row.current === index
            };
        });
    };

    /* ── loading ─────────────────────────────────────────────────────── */

    Extraction.prototype.open = function () {
        this.isOpen = true;
        this.picked = null;
        this.panel.hidden = false;
        return this._load();
    };

    Extraction.prototype.close = function () {
        this.isOpen = false;
        this.picked = null;
        this.panel.hidden = true;
        this.onClose();
    };

    Extraction.prototype._load = function () {
        var self = this;
        this._setLoading(this.L.loading);
        return fetch(base() + '/eventReports/extractFromReport/' + this.reportId, {
            credentials: 'same-origin',
            headers: {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'}
        }).then(function (response) {
            if (!response.ok) { throw new Error('HTTP ' + response.status); }
            return response.json();
        }).then(function (data) {
            return self.renderer.ready.then(function () { return data; });
        }).then(function (data) {
            self.typeToCategory = data.typeToCategoryMapping || {};
            self.defaultCategories = data.defaultCategories || {};
            self._build(data);
            var keep = self.active && self.rows[self.active].length ? self.active : null;
            self._showTab(keep || KINDS.filter(function (kind) {
                return self.rows[kind].length;
            })[0] || 'new');
        }).catch(function (err) {
            self._setLoading(null);
            self.list.innerHTML = '<div class="ov-md-x-empty text-danger">'
                + esc(self.L.loadFailed + ' ' + err.message) + '</div>';
        });
    };

    Extraction.prototype._setLoading = function (message) {
        this.busy = !!message;
        this.panel.classList.toggle('is-busy', this.busy);
        if (message) {
            this.list.innerHTML = '<div class="ov-md-x-empty"><span class="spinner-border spinner-border-sm me-2"'
                + ' role="status"></span>' + esc(message) + '</div>';
        }
    };

    Extraction.prototype._defaultCategory = function (type) {
        var categories = this.typeToCategory[type] || [];
        var preferred = this.defaultCategories[type];
        return categories.indexOf(preferred) !== -1 ? preferred : (categories[0] || '');
    };

    Extraction.prototype._build = function (data) {
        var content = this.getContent();
        var proxy = this.renderer.proxy || {};
        var attributes = proxy.attribute || {};
        var rows = {new: [], existing: [], context: []};
        var self = this;

        (data.complexTypeToolResult || []).forEach(function (entity) {
            var needle = entity.original_value || entity.value;
            rows.new.push({
                kind: 'new',
                value: entity.value,
                needle: needle,
                types: entity.types && entity.types.length ? entity.types : [entity.default_type],
                type: entity.default_type,
                category: self._defaultCategory(entity.default_type),
                occ: findOccurrences(content, needle)
            });
        });

        var values = data.replacementValues || {};
        Object.keys(values).forEach(function (key) {
            var entry = values[key];
            var options = (entry.attributeUUIDs || []).map(function (uuid) {
                return attributes[uuid];
            }).filter(Boolean);
            if (!options.length) { return; }
            rows.existing.push({
                kind: 'existing',
                needle: entry.valueInReport,
                options: options,
                choice: options[0].uuid,
                occ: findOccurrences(content, entry.valueInReport)
            });
        });

        var context = data.replacementContext || {};
        Object.keys(context).forEach(function (rawText) {
            var tags = context[rawText] || {};
            var options = Object.keys(tags).filter(function (name) {
                return name !== 'indices';
            }).map(function (name) {
                return {name: name, data: tags[name] || {}};
            });
            if (!options.length) { return; }
            rows.context.push({
                kind: 'context',
                needle: rawText,
                options: options,
                choice: options[0].name,
                occ: findOccurrences(content, rawText)
            });
        });

        KINDS.forEach(function (kind) {
            rows[kind] = rows[kind].filter(function (row) { return row.occ.length > 0; });
            rows[kind].forEach(function (row) {
                row.checked = row.occ.map(function () { return true; });
                row.current = null;
            });
        });
        this.rows = rows;

        Array.prototype.forEach.call(this.tabs, function (tab) {
            var count = tab.querySelector('[data-x-count]');
            if (count) { count.textContent = rows[tab.getAttribute('data-x-tab')].length; }
        });
    };

    /* ── drawing ─────────────────────────────────────────────────────── */

    Extraction.prototype._showTab = function (kind) {
        this.active = kind;
        Array.prototype.forEach.call(this.tabs, function (tab) {
            var on = tab.getAttribute('data-x-tab') === kind;
            tab.classList.toggle('active', on);
            tab.setAttribute('aria-selected', on ? 'true' : 'false');
        });
        if (this.picked && this.picked.kind !== kind) { this.picked = null; }
        this._setLoading(null);
        this._drawList();
        this._paint();
    };

    Extraction.prototype._pillKey = function (row) {
        if (row.kind === 'new') { return row.type; }
        if (row.kind === 'existing') {
            var attribute = this._chosenAttribute(row);
            return attribute ? (attribute.object_relation || attribute.type) : 'attribute';
        }
        var tag = this._chosenTag(row);
        return tag && tag.data && tag.data.type ? tag.data.type : 'tag';
    };

    Extraction.prototype._chosenAttribute = function (row) {
        for (var i = 0; i < row.options.length; i++) {
            if (row.options[i].uuid === row.choice) { return row.options[i]; }
        }
        return row.options[0];
    };

    Extraction.prototype._chosenTag = function (row) {
        for (var i = 0; i < row.options.length; i++) {
            if (row.options[i].name === row.choice) { return row.options[i]; }
        }
        return row.options[0];
    };

    Extraction.prototype._attributeLabel = function (attribute) {
        return '#' + attribute.id + ' · ' + (attribute.object_relation || attribute.type)
            + ' · ' + attribute.category;
    };

    Extraction.prototype._tagLabel = function (option) {
        var data = option.data || {};
        if (data.tag_name && data.value) {
            return data.value + ' (' + data.type + ')';
        }
        return option.name;
    };

    Extraction.prototype._tagChip = function (option) {
        var data = option.data || {};
        if (window.TagChips) {
            if (data.tag_name && data.value) {
                return window.TagChips.cluster({
                    value: data.value, galaxy: data.type, description: data.description
                }, {href: function () { return null; }});
            }
            return window.TagChips.chip({name: option.name, colour: data.colour}, {searchUrl: ''});
        }
        return '<span class="badge text-bg-secondary">' + esc(option.name) + '</span>';
    };

    Extraction.prototype._meta = function (row) {
        if (row.kind === 'new') {
            return '<span class="ov-md-x-type">' + esc(row.type) + '</span>'
                + (row.types.length > 1 ? '<span class="ov-md-x-more">'
                    + esc(format(this.L.otherTypes, {n: row.types.length - 1})) + '</span>' : '');
        }
        if (row.kind === 'existing') {
            if (row.options.length > 1) {
                return '<span class="ov-md-x-more">'
                    + esc(format(this.L.attributesMatch, {n: row.options.length})) + '</span>';
            }
            return '<span class="ov-md-x-type">' + esc(this._attributeLabel(row.options[0])) + '</span>';
        }
        if (row.options.length > 1) {
            return '<span class="ov-md-x-more">'
                + esc(format(this.L.tagsMatch, {n: row.options.length})) + '</span>';
        }
        return '<span class="ov-md-x-chip">' + this._tagChip(row.options[0]) + '</span>';
    };

    Extraction.prototype._select = function (field, label, options, value) {
        return '<label class="ov-md-x-field"><span>' + esc(label) + '</span>'
            + '<select class="form-select form-select-sm" data-x-field="' + field + '">'
            + options.map(function (option) {
                return '<option value="' + esc(option[0]) + '"'
                    + (option[0] === value ? ' selected' : '') + '>' + esc(option[1]) + '</option>';
            }).join('') + '</select></label>';
    };

    Extraction.prototype._detail = function (row) {
        var self = this;
        var fields = '';
        if (row.kind === 'new') {
            fields += this._select('type', this.L.type, row.types.map(function (type) {
                return [type, type];
            }), row.type);
            fields += this._select('category', this.L.category,
                (this.typeToCategory[row.type] || []).map(function (category) {
                    return [category, category];
                }), row.category);
        } else if (row.kind === 'existing') {
            if (row.options.length > 1) {
                fields += this._select('choice', this.L.attribute, row.options.map(function (attribute) {
                    return [attribute.uuid, self._attributeLabel(attribute)];
                }), row.choice);
            }
        } else if (row.options.length > 1) {
            fields += this._select('choice', this.L.tag, row.options.map(function (option) {
                return [option.name, self._tagLabel(option)];
            }), row.choice);
        }
        var applyLabel = {new: this.L.applyNew, existing: this.L.applyExisting, context: this.L.applyContext}[row.kind];
        return '<div class="ov-md-x-detail">'
            + (fields ? '<div class="ov-md-x-fields">' + fields + '</div>' : '')
            + '<div class="ov-md-x-bar">'
            + '<span class="ov-md-x-nav">'
            + '<button type="button" class="ov-md-tool" data-x-action="prev" title="' + esc(this.L.prev) + '"'
            + ' aria-label="' + esc(this.L.prev) + '"><i class="fas fa-chevron-left"></i></button>'
            + '<span data-x-position></span>'
            + '<button type="button" class="ov-md-tool" data-x-action="next" title="' + esc(this.L.next) + '"'
            + ' aria-label="' + esc(this.L.next) + '"><i class="fas fa-chevron-right"></i></button>'
            + '</span>'
            + '<span class="ov-md-x-ticked" data-x-ticked></span>'
            + '<button type="button" class="btn btn-sm btn-primary ms-auto" data-x-action="apply">'
            + '<span data-x-apply-label>' + esc(applyLabel) + '</span>'
            + ' <span class="ov-md-x-apply-n" data-x-apply-n></span></button>'
            + '</div>'
            + '<div class="ov-md-x-warn" data-x-warn hidden></div>'
            + '</div>';
    };

    Extraction.prototype._drawList = function () {
        var rows = this.rows[this.active] || [];
        if (!rows.length) {
            this.list.innerHTML = '<div class="ov-md-x-empty">'
                + esc({new: this.L.emptyNew, existing: this.L.emptyExisting, context: this.L.emptyContext}[this.active])
                + '</div>';
            return;
        }
        var self = this;
        this.list.innerHTML = rows.map(function (row, index) {
            var picked = row === self.picked;
            return '<div class="ov-md-x-row' + (picked ? ' is-picked' : '') + '" data-x-row="' + index + '"'
                + ' tabindex="0" role="option" aria-selected="' + (picked ? 'true' : 'false') + '">'
                + '<div class="ov-md-x-head">'
                + '<span class="ov-md-x-val">' + esc(row.needle) + '</span>'
                + '<span class="ov-md-x-occ" title="' + esc(self.L.occurrences) + '">×' + row.occ.length + '</span>'
                + '</div>'
                + '<div class="ov-md-x-meta">' + self._meta(row) + '</div>'
                + (picked ? self._detail(row) : '')
                + '</div>';
        }).join('');
    };

    /* ── picking and the preview ─────────────────────────────────────── */

    Extraction.prototype._pick = function (index) {
        var row = (this.rows[this.active] || [])[index];
        if (!row || this.busy) { return; }
        this.picked = this.picked === row ? null : row;
        if (this.picked) { this.picked.current = null; }
        this._drawList();
        this._paint();
        if (this.picked) { this._step(1); }
    };

    /* The base content with the picked row's occurrences marked, but for
       those listed in `skip`. */
    Extraction.prototype._markedContent = function (skip) {
        var content = this.getContent();
        var row = this.picked;
        if (!row) { return content; }
        var out = '';
        var pos = 0;
        row.occ.forEach(function (occurrence, index) {
            out += content.slice(pos, occurrence.start);
            out += skip && skip[index]
                ? content.slice(occurrence.start, occurrence.end)
                : '@[suggestion](' + index + ')';
            pos = occurrence.end;
        });
        return out + content.slice(pos);
    };

    /* A marker inside code or a link target is printed as is rather than
       drawn as a pill; those occurrences are drawn again as plain text. */
    Extraction.prototype._render = function () {
        this.renderer.render(this._markedContent(null), this.preview);
        var row = this.picked;
        if (!row) { return; }
        var shown = this._rendered();
        var skip = {};
        var missing = 0;
        row.occ.forEach(function (occurrence, index) {
            if (!shown[index]) { skip[index] = true; missing++; }
        });
        if (missing) { this.renderer.render(this._markedContent(skip), this.preview); }
    };

    Extraction.prototype._rendered = function () {
        var shown = {};
        Array.prototype.forEach.call(this.preview.querySelectorAll('[data-suggestion]'), function (node) {
            shown[Number(node.getAttribute('data-suggestion'))] = node;
        });
        return shown;
    };

    Extraction.prototype._paint = function () {
        if (!this.isOpen) { return; }
        this._render();
        var row = this.picked;
        if (!row) { return; }
        var shown = this._rendered();
        var total = Object.keys(shown).length;
        var ticked = row.occ.filter(function (occurrence, index) {
            return shown[index] && row.checked[index];
        }).length;
        var hidden = row.occ.length - total;
        var order = Object.keys(shown).map(Number).sort(function (a, b) { return a - b; });
        var position = row.current === null ? 0 : order.indexOf(row.current) + 1;

        var node = this.list.querySelector('.is-picked');
        if (!node) { return; }
        var setText = function (selector, text) {
            var target = node.querySelector(selector);
            if (target) { target.textContent = text; }
        };
        setText('[data-x-position]', format(this.L.position, {i: position || '–', n: total}));
        setText('[data-x-ticked]', format(this.L.ticked, {i: ticked, n: total}));
        setText('[data-x-apply-n]', ticked);
        var apply = node.querySelector('[data-x-action="apply"]');
        if (apply) { apply.disabled = ticked === 0 || this.busy; }
        node.querySelectorAll('[data-x-action="prev"], [data-x-action="next"]').forEach(function (button) {
            button.disabled = total === 0;
        });
        var warn = node.querySelector('[data-x-warn]');
        if (warn) {
            warn.hidden = hidden === 0;
            warn.innerHTML = hidden ? '<i class="fas fa-triangle-exclamation"></i>'
                + esc(format(this.L.notShown, {n: hidden})) : '';
        }
    };

    Extraction.prototype._step = function (direction) {
        var row = this.picked;
        if (!row) { return; }
        var shown = this._rendered();
        var order = Object.keys(shown).map(Number).sort(function (a, b) { return a - b; });
        if (!order.length) { this._paint(); return; }
        var at = row.current === null ? -1 : order.indexOf(row.current);
        var next = at === -1 ? 0 : Math.min(order.length - 1, Math.max(0, at + direction));
        row.current = order[next];
        this._paint();
        var node = this._rendered()[row.current];
        if (node) { node.scrollIntoView({behavior: 'smooth', block: 'center'}); }
    };

    /* ── applying ────────────────────────────────────────────────────── */

    Extraction.prototype._replacedContent = function (replacement) {
        var content = this.getContent();
        var row = this.picked;
        var shown = this._rendered();
        var out = '';
        var pos = 0;
        row.occ.forEach(function (occurrence, index) {
            out += content.slice(pos, occurrence.start);
            out += (shown[index] && row.checked[index])
                ? replacement
                : content.slice(occurrence.start, occurrence.end);
            pos = occurrence.end;
        });
        return out + content.slice(pos);
    };

    Extraction.prototype._apply = function () {
        var row = this.picked;
        if (!row || this.busy) { return; }
        var self = this;
        var done;
        this.busy = true;
        this.panel.classList.add('is-busy');
        var button = this.list.querySelector('[data-x-action="apply"]');
        if (button) {
            button.disabled = true;
            button.insertAdjacentHTML('afterbegin', '<span class="spinner-border spinner-border-sm me-1" role="status"></span>');
        }

        if (row.kind === 'new') {
            var mapping = {};
            mapping[row.value] = {type: row.type, category: row.category, to_ids: null};
            done = this._postSuggestion(this._replacedContent('@[suggestion](' + row.value + ')'), mapping);
        } else if (row.kind === 'existing') {
            var uuid = this._chosenAttribute(row).uuid;
            var content = this._replacedContent('@[attribute](' + uuid + ')');
            done = this.save(content).then(function (result) {
                return result.ok ? {content: content, message: self.L.linked} : Promise.reject(result.message);
            });
        } else {
            var name = this._chosenTag(row).name;
            var tagged = this._replacedContent('@[tag](' + name + ')');
            done = this.save(tagged).then(function (result) {
                return result.ok ? {content: tagged, message: self.L.tagged} : Promise.reject(result.message);
            });
        }

        return done.then(function (result) {
            toast(result.message, 'success');
            self.picked = null;
            self.onSaved(result.content);
            self._setLoading(self.L.loading);
            return self.renderer.reload().then(function () { return self._load(); });
        }).catch(function (message) {
            self.busy = false;
            self.panel.classList.remove('is-busy');
            toast((message && message.message) || message || self.L.failed, 'danger');
            self._drawList();
            self._paint();
        });
    };

    /* A new attribute: the server creates it and writes its reference over
       every `@[suggestion](value)` left in the content. */
    Extraction.prototype._postSuggestion = function (content, mapping) {
        var url = base() + '/eventReports/replaceSuggestionInReport/' + this.reportId;
        var L = this.L;
        return fetch(url, {
            credentials: 'same-origin',
            headers: {'X-Requested-With': 'XMLHttpRequest'}
        }).then(function (response) {
            return response.text();
        }).then(function (html) {
            var form = new DOMParser().parseFromString(html, 'text/html').querySelector('form');
            if (!form) { throw new Error(L.failed); }
            var data = new FormData(form);
            data.set('data[EventReport][suggestions]', JSON.stringify({content: content, mapping: mapping}));
            return fetch(form.getAttribute('action') || url, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'X-Requested-With': 'XMLHttpRequest'},
                body: new URLSearchParams(data)
            });
        }).then(function (response) {
            return response.json().catch(function () { return {}; }).then(function (data) {
                if (!response.ok || data.saved === false || !data.data || !data.data.report) {
                    throw new Error(errorText(data, L.failed));
                }
                return {content: data.data.report.EventReport.content, message: data.message || L.created};
            });
        });
    };

    window.MispReportExtraction = {
        create: function (options) { return new Extraction(options); },
        findOccurrences: findOccurrences
    };
})(window, document);
