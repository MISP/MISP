// The collection chooser: the collections the user may edit, Mine or
// Organisation, those used last first and the rest behind Show all, with
// New collection… under them. The dock lists them to pick the workspace;
// "Add to another collection…" and "New collection with this…" to pick where
// records go.
//
//   IntelGraphChooser.fill(into, options)     the list, then the form
//   IntelGraphChooser.form(options)           New collection… alone
//
// Needs intel-graph.js.

(function () {
    'use strict';

    function IG() { return window.IntelGraph; }
    function lower(s) { return String(s || '').toLowerCase(); }

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }
    function icon(cls) {
        var i = el('i', cls);
        i.setAttribute('aria-hidden', 'true');
        return i;
    }
    function ago(t) {
        var s = Math.round((Date.now() - t) / 1000);
        if (s < 45) return 'just now';
        var m = Math.round(s / 60);
        if (m < 60) return m + ' min ago';
        var h = Math.round(m / 60);
        if (h < 24) return h + ' h ago';
        return new Date(t).toLocaleDateString();
    }
    function members(n) { return n + (n === 1 ? ' member' : ' members'); }
    // A collection type as the collection form names it.
    function collectionType(type) {
        var hit = IG().collectionTypes().filter(function (t) { return t[0] === type; })[0];
        return hit ? hit[1] : (type || '');
    }

    function rowClass(asDropdown) {
        return asDropdown ? 'dropdown-item' : 'list-group-item list-group-item-action';
    }

    function collectionRow(c, isCurrent, asDropdown, onPick) {
        var b = el('button', rowClass(asDropdown) + ' ig-so-pick');
        b.type = 'button';
        if (isCurrent) b.setAttribute('aria-current', 'true');
        var mark = el('span', 'ig-so-pick-mark');
        if (isCurrent) mark.appendChild(icon('fas fa-check'));
        b.appendChild(mark);
        var bodyEl = el('span', 'ig-so-pick-body');
        bodyEl.appendChild(el('span', 'ig-so-pick-name', c.name));
        var sub = el('span', 'ig-so-pick-sub');
        sub.appendChild(icon('fas fa-folder'));
        sub.appendChild(el('span', null, collectionType(c.type) + (c.Orgc && c.Orgc.name ? ' · ' + c.Orgc.name : '')
            + (c.used ? ' · used ' + ago(c.used * 1000) : '')));
        bodyEl.appendChild(sub);
        b.appendChild(bodyEl);
        var n = c.element_count || 0;
        var badge = el('span', 'badge rounded-pill text-bg-secondary', String(n));
        badge.title = members(n);
        b.appendChild(badge);
        b.addEventListener('click', function () { onPick(c); });
        return b;
    }

    var SCOPES = [
        { key: 'mine', label: 'Mine', head: 'Your collections', empty: 'You have created no collection yet.' },
        { key: 'org', label: 'Organisation', head: 'Your organisation’s collections', empty: 'Your organisation has no collection you can change yet.' }
    ];
    function scopeOf(key) {
        return SCOPES.filter(function (s) { return s.key === key; })[0] || SCOPES[1];
    }

    // options:
    //   asDropdown  rows as dropdown items, else a list group
    //   scope       'mine' | 'org', the list first shown
    //   onScope     (scope) the reader switched it
    //   onPick      (collection) a row was chosen
    //   after       (holder, workspace) called once a list is drawn
    //   others      leave the workspace out: the list is of other collections
    //   form        New collection…'s options, see form(); false leaves it out
    var listSeq = 0;
    function fill(into, options) {
        options = options || {};
        var asDropdown = !!options.asDropdown;
        var scope = options.scope === 'mine' ? 'mine' : 'org';
        into.textContent = '';
        var head = el('div', 'ig-so-scope' + (asDropdown ? ' dropdown-header' : ''));
        var title = el(asDropdown ? 'h6' : 'p', asDropdown ? 'mb-0' : 'small text-body-secondary mb-0');
        head.appendChild(title);
        var toggle = el('div', 'btn-group btn-group-sm');
        toggle.setAttribute('role', 'group');
        toggle.setAttribute('aria-label', 'Whose collections');
        head.appendChild(toggle);
        into.appendChild(head);
        var holder = el('div', asDropdown ? 'ig-so-list' : 'list-group');
        into.appendChild(holder);
        var buttons = SCOPES.map(function (s) {
            var b = el('button', 'btn btn-outline-primary', s.label);
            b.type = 'button';
            b.addEventListener('click', function () {
                if (scope === s.key) return;
                scope = s.key;
                if (options.onScope) options.onScope(scope);
                load();
            });
            toggle.appendChild(b);
            return b;
        });
        function row(c, activeUuid) {
            return collectionRow(c, lower(c.uuid) === activeUuid, asDropdown, options.onPick);
        }
        function load() {
            var s = scopeOf(scope);
            title.textContent = s.head;
            SCOPES.forEach(function (x, i) {
                buttons[i].classList.toggle('active', x.key === s.key);
                buttons[i].setAttribute('aria-pressed', x.key === s.key ? 'true' : 'false');
            });
            var seq = ++listSeq;
            holder.textContent = '';
            holder.appendChild(el('div', 'px-3 py-2 text-body-secondary small', 'Loading…'));
            IG().list(s.key).then(function (out) {
                if (seq !== listSeq) return;
                holder.textContent = '';
                var a = IG().active();
                var activeUuid = lower(a && a.Collection.uuid);
                var collections = options.others
                    ? out.collections.filter(function (c) { return lower(c.uuid) !== activeUuid; })
                    : out.collections;
                var listed = options.others || collections.some(function (c) { return lower(c.uuid) === activeUuid; });
                if (a && !listed) holder.appendChild(row(a.Collection, activeUuid));
                // The ones used last; the rest wait behind Show all.
                var used = collections.filter(function (c) { return c.used; });
                var rest = collections.filter(function (c) { return !c.used; });
                (used.length ? used : rest).forEach(function (c) { holder.appendChild(row(c, activeUuid)); });
                if (used.length && rest.length) {
                    var more = el('button', rowClass(asDropdown) + ' ig-so-more');
                    more.type = 'button';
                    more.appendChild(icon('fas fa-ellipsis'));
                    more.appendChild(el('span', null, 'Show all · ' + rest.length + ' more'));
                    more.addEventListener('click', function (e) {
                        e.preventDefault();
                        var first = null;
                        rest.forEach(function (c) {
                            var r = row(c, activeUuid);
                            holder.insertBefore(r, more);
                            first = first || r;
                        });
                        more.remove();
                        if (first) first.focus();
                    });
                    holder.appendChild(more);
                }
                if (!collections.length && !(a && !listed)) holder.appendChild(el('div', 'px-3 py-2 text-body-secondary small', options.others ? 'No other collection you can change yet.' : s.empty));
                if (options.after) options.after(holder, a);
            }, function (err) {
                if (seq !== listSeq) return;
                holder.textContent = '';
                holder.appendChild(el('div', 'px-3 py-2 text-danger small', 'Could not list the collections: ' + ((err && err.message) || 'error')));
            });
        }
        load();
        if (options.form !== false) {
            if (asDropdown) into.appendChild(el('div', 'dropdown-divider'));
            into.appendChild(form(options.form || {}));
        }
    }

    // New collection…: a name, and what it starts as stated beside it.
    // options:
    //   label     the field's label (default "New collection")
    //   submit    the button's text (default "Create")
    //   create    (values, activate) → Promise<collection>; default
    //             IntelGraph.createCollection
    //   done      (collection, activate, name) once created
    //   activate  Make it my workspace ticked (default true)
    //   name      the name it starts with
    //   type      the type it starts as (default research)
    var formSeq = 0;
    function form(options) {
        options = options || {};
        var id = 'ig-so-new-' + (++formSeq);
        var f = el('form', 'ig-so-new');
        f.noValidate = true;
        var label = el('label', 'form-label', options.label || 'New collection');
        label.htmlFor = id;
        f.appendChild(label);
        var group = el('div', 'input-group input-group-sm');
        var input = el('input', 'form-control');
        input.id = id;
        input.name = 'name';
        input.placeholder = 'Name it';
        input.autocomplete = 'off';
        input.maxLength = 191;
        input.required = true;
        if (options.name) input.value = String(options.name).slice(0, 191);
        group.appendChild(input);
        var submit = el('button', 'btn btn-primary', options.submit || 'Create');
        submit.type = 'submit';
        group.appendChild(submit);
        f.appendChild(group);
        var feedback = el('div', 'invalid-feedback');
        f.appendChild(feedback);

        var levels = [0, 1, 2, 3].map(function (l) {
            var d = IG().distribution(l);
            return [l, d ? d.label : String(l)];
        });
        var typeField = field('Type', id + '-type', IG().collectionTypes(), options.type || 'research');
        var distField = field('Distribution', id + '-dist', levels, 0);
        var stated = el('div', 'form-text ig-so-new-defaults');
        var statedText = el('span');
        var change = el('button', 'btn btn-link p-0 align-baseline ig-so-new-change', 'change');
        change.type = 'button';
        change.setAttribute('aria-expanded', 'false');
        change.setAttribute('aria-controls', id + '-options');
        stated.appendChild(statedText);
        stated.appendChild(document.createTextNode(' · '));
        stated.appendChild(change);
        f.appendChild(stated);
        var more = el('div', 'ig-so-new-options');
        more.id = id + '-options';
        more.hidden = true;
        more.appendChild(typeField.wrap);
        more.appendChild(distField.wrap);
        f.appendChild(more);
        function state() {
            statedText.textContent = levels[+distField.select.value][1] + ' · ' + collectionType(typeField.select.value);
        }
        state();
        change.addEventListener('click', function () {
            more.hidden = false;
            stated.hidden = true;
            change.setAttribute('aria-expanded', 'true');
            typeField.select.focus();
        });

        var check = el('div', 'form-check ig-so-new-check');
        var box = el('input', 'form-check-input');
        box.type = 'checkbox';
        box.id = id + '-workspace';
        box.checked = options.activate !== false;
        var boxLabel = el('label', 'form-check-label', 'Make it my workspace');
        boxLabel.htmlFor = box.id;
        check.appendChild(box);
        check.appendChild(boxLabel);
        f.appendChild(check);

        var create = options.create || function (values, activate) {
            return IG().createCollection(values, { activate: activate });
        };
        f.addEventListener('submit', function (e) {
            e.preventDefault();
            var name = input.value.trim();
            input.classList.remove('is-invalid');
            if (!name) { input.classList.add('is-invalid'); feedback.textContent = 'A collection needs a name.'; input.focus(); return; }
            submit.disabled = true;
            var activate = box.checked;
            create({ name: name, type: typeField.select.value, distribution: +distField.select.value }, activate).then(function (created) {
                submit.disabled = false;
                input.value = '';
                if (options.done) options.done(created, activate, name);
            }).catch(function (err) {
                submit.disabled = false;
                input.classList.add('is-invalid');
                var errs = err && err.body && err.body.errors;
                feedback.textContent = (errs && errs.name && errs.name[0]) || (err && err.message) || 'Could not create the collection.';
            });
        });
        f.focusName = function () { input.focus(); input.select(); };
        return f;
    }

    function field(text, id, choices, value) {
        var wrap = el('div', 'ig-so-new-field');
        var lab = el('label', 'form-label', text);
        lab.htmlFor = id;
        var select = el('select', 'form-select form-select-sm');
        select.id = id;
        choices.forEach(function (c) {
            var o = el('option', null, c[1]);
            o.value = String(c[0]);
            o.selected = String(c[0]) === String(value);
            select.appendChild(o);
        });
        wrap.appendChild(lab);
        wrap.appendChild(select);
        return { wrap: wrap, select: select };
    }

    window.IntelGraphChooser = { fill: fill, form: form, row: collectionRow };
}());
