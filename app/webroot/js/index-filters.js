/*
 * Picker filter bars (genericElementsBS5/IndexTable/filter_bar.ctp with
 * `picker` children).
 *
 * The URL is the state: the page's, or inside an ajax tab the tab's own
 * `data-url`. Pickers edit one filter and apply when they close; chips,
 * toggles, stat cards, the pager and the sort links are links the server
 * already built. On a page, applying fetches the page at the new URL and
 * swaps in the results and every `[data-ifp-swap]` node of that bar's index;
 * in a tab, the tab reloads its fragment and the browser URL is left alone.
 * Every lookup is scoped to the bar's index (`[data-ifp-scope]`), so a page
 * can hold several bars, and all wiring is delegated so swaps need no
 * rebinding.
 */
(function () {
    'use strict';

    // A tab reload brings this script along again.
    if (window.IndexFilters) { return; }

    var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    var MIN_TERM = 2;
    var THROTTLE = 300;
    // A fixed list longer than this gets a search box and shows LIST_MAX rows.
    var LOCAL_MAX = 12;
    var LIST_MAX = 20;

    var open = null;
    var inFlight = null;

    /* ── the bar a node belongs to ────────────────────────────────────── */

    function scopeOf(node) { return node && node.closest ? node.closest('[data-ifp-scope]') : null; }

    function barOf(node) {
        var scope = scopeOf(node);
        return scope ? scope.querySelector('[data-ifp-bar]') : null;
    }

    function cfg(bar) {
        if (!bar.__ifp) { bar.__ifp = JSON.parse(bar.getAttribute('data-ifp-bar')); }
        return bar.__ifp;
    }

    function tabOf(bar) { return bar.closest('.ajax-tab-content'); }

    function resultsOf(bar) { return scopeOf(bar).querySelector('[data-ifp-results]'); }

    function S(bar, key) { var c = cfg(bar); return (c.strings && c.strings[key]) || ''; }

    function swapKey(el) { return el.getAttribute('data-ifp-swap') || el.id; }

    function swapNode(scope, key) {
        var hit = null;
        scope.querySelectorAll('[data-ifp-swap]').forEach(function (el) {
            if (!hit && swapKey(el) === key && scopeOf(el) === scope) { hit = el; }
        });
        return hit;
    }

    function pathOf(url) { return (url || '').replace(/^[a-z]+:\/\/[^/]+/i, ''); }

    // Text and attribute values alike: cluster tag names carry double quotes.
    function esc(text) {
        return String(text == null ? '' : text).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    /* ── URLs ─────────────────────────────────────────────────────────── */

    function currentUrl(bar) {
        var tab = tabOf(bar);
        return tab ? (tab.dataset.url || '') : window.location.pathname + window.location.search;
    }

    /*
     * The URL as base + positional segments, its named segments and its query.
     * The base is the URL's own path when it is the bar's base spelled another
     * way (`/sharing_groups/index` for `/SharingGroups/index`), else the bar's.
     */
    function splitUrl(bar, url) {
        var c = cfg(bar);
        var cut = url.indexOf('?');
        var path = pathOf(cut === -1 ? url : url.slice(0, cut));
        var named = {};
        var plain = path.split('/').filter(function (segment) {
            var colon = segment.indexOf(':');
            if (colon <= 0) { return true; }
            named[decodeURIComponent(segment.slice(0, colon))] = decodeURIComponent(segment.slice(colon + 1));
            return false;
        }).join('/');
        var norm = function (s) { return s.toLowerCase().replace(/_/g, '').replace(/\/+$/, ''); };
        var base = norm(plain).indexOf(norm(pathOf(c.base))) === 0 ? plain : c.base;
        return { base: base, named: named, query: new URLSearchParams(cut === -1 ? '' : url.slice(cut + 1)) };
    }

    // changes: unprefixed name => value or list, null removes it. A list
    // goes in the path as `key[0]:a/key[1]:b`. Paging restarts.
    function urlWith(bar, changes) {
        var c = cfg(bar);
        var parts = splitUrl(bar, currentUrl(bar));
        var named = parts.named;
        delete named.page;
        parts.query.delete('page');
        Object.keys(changes).forEach(function (name) {
            var key = c.prefix + name;
            var value = changes[name];
            Object.keys(named).forEach(function (k) {
                if (k.indexOf(key + '[') === 0) { delete named[k]; }
            });
            var gone = value === null || value === undefined || value === ''
                || (Array.isArray(value) && !value.length);
            if (c.transport === 'query') {
                if (gone) { parts.query.delete(key); } else { parts.query.set(key, [].concat(value).join('|')); }
            } else if (gone) {
                delete named[key];
            } else if (Array.isArray(value)) {
                delete named[key];
                value.forEach(function (v, i) { named[key + '[' + i + ']'] = v; });
            } else {
                named[key] = value;
            }
        });
        return formatIndexUrl(parts.base, { named: named, query: parts.query });
    }

    function searchUrl(bar) {
        var c = cfg(bar);
        var field = bar.querySelector('.ifp-query input');
        var term = field ? field.value.trim() : '';
        var changes = {};
        if (c.searchField) { changes[c.searchField] = null; }
        if (c.idField) { changes[c.idField] = null; }
        if (term !== '') {
            var key = (c.idField && (UUID_RE.test(term) || /^[0-9]+$/.test(term))) ? c.idField : c.searchField;
            changes[key] = term;
        }
        return urlWith(bar, changes);
    }

    /* ── a tab's own scope ────────────────────────────────────────────── */

    /*
     * The filters a tab was opened with (`searchorg:` on an organisation's
     * Events tab) are what the tab is about: no chip, no picker, and Clear all
     * returns to them.
     */
    function originKeys(tab) {
        if (!tab.dataset.ifpOrigin) { tab.dataset.ifpOrigin = tab.dataset.url || ''; }
        return pathOf(tab.dataset.ifpOrigin).split('?')[0].split('/').filter(function (segment) {
            return segment.indexOf(':') > 0;
        }).map(function (segment) { return segment.slice(0, segment.indexOf(':')); });
    }

    function applyTabScope(bar) {
        var tab = tabOf(bar);
        if (!tab) { return; }
        var keys = originKeys(tab);
        var prefix = cfg(bar).prefix;
        var scope = scopeOf(bar);
        scope.querySelectorAll('[data-ifp-key]').forEach(function (el) {
            if (keys.indexOf(el.getAttribute('data-ifp-key')) !== -1) { el.hidden = true; }
        });
        scope.querySelectorAll('[data-ifp-picker]').forEach(function (el) {
            var name = JSON.parse(el.getAttribute('data-ifp-picker')).name;
            if (keys.indexOf(prefix + name) !== -1) { el.hidden = true; }
        });
        var chips = swapNode(scope, 'chips');
        if (chips && !chips.querySelector('.ifp-chip:not([hidden])')) { chips.hidden = true; }
        var clear = scope.querySelector('.ifp-clear');
        if (clear) {
            var origin = splitUrl(bar, tab.dataset.ifpOrigin);
            var sort = splitUrl(bar, currentUrl(bar)).named;
            ['sort', 'direction', 'limit'].forEach(function (k) { if (sort[k]) { origin.named[k] = sort[k]; } });
            clear.setAttribute('href', formatIndexUrl(origin.base, origin));
        }
    }

    function applyAllTabScopes(root) {
        (root || document).querySelectorAll('[data-ifp-bar]').forEach(applyTabScope);
    }

    /* ── loading ──────────────────────────────────────────────────────── */

    function setBusy(bar, busy) {
        var results = resultsOf(bar);
        if (!results) { return; }
        results.classList.toggle('is-busy', busy);
        var overlay = results.querySelector(':scope > .index-results-overlay');
        if (busy && !overlay) {
            overlay = document.createElement('div');
            overlay.className = 'index-results-overlay';
            overlay.innerHTML = '<div class="misp-loader" role="status"></div>';
            results.appendChild(overlay);
        } else if (!busy && overlay) {
            overlay.remove();
        }
    }

    function clearError(bar) {
        var old = scopeOf(bar).querySelector('.ifp-error');
        if (old) { old.remove(); }
    }

    function showError(bar) {
        clearError(bar);
        var alert = document.createElement('div');
        alert.className = 'alert alert-danger alert-dismissible fade show mb-3 ifp-error';
        alert.innerHTML = '<i class="fas fa-exclamation-triangle me-1"></i>' + esc(S(bar, 'loadError'))
            + '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';
        var row = scopeOf(bar).querySelector('.ifp-row');
        (row || bar).insertAdjacentElement('afterend', alert);
    }

    function swapIn(bar, doc) {
        var scope = scopeOf(bar);
        var key = scope.getAttribute('data-ifp-scope');
        var fresh = null;
        doc.querySelectorAll('[data-ifp-scope]').forEach(function (el) {
            if (!fresh && el.getAttribute('data-ifp-scope') === key && el.querySelector('[data-ifp-bar]')) { fresh = el; }
        });
        var results = resultsOf(bar);
        var freshResults = fresh && fresh.querySelector('[data-ifp-results]');
        if (!results || !freshResults) { throw new Error('no results container'); }
        results.innerHTML = freshResults.innerHTML;

        // A picker opened while this page was loading reopens on its new node,
        // and a focused toggle or picker button keeps the focus.
        var reopen = null;
        var refocus = null;
        scope.querySelectorAll('[data-ifp-swap]').forEach(function (el) {
            if (scopeOf(el) !== scope) { return; }
            var k = swapKey(el);
            var next = swapNode(fresh, k);
            if (!next) { return; }
            if (open && open.picker === el) {
                reopen = k;
                closePicker(false);
            }
            if (el.contains(document.activeElement)) { refocus = k; }
            el.replaceWith(document.importNode(next, true));
        });
        if (reopen) {
            openPicker(swapNode(scope, reopen));
        } else if (refocus) {
            var node = swapNode(scope, refocus);
            var target = node.matches('a, button') ? node : node.querySelector('.ifp-btn, a, button');
            if (target) { target.focus(); }
        }
        var pager = scope.querySelector('.index-filter-pager');
        var nextPager = fresh.querySelector('.index-filter-pager');
        if (pager && nextPager) { pager.innerHTML = nextPager.innerHTML; }
        var badge = document.getElementById('headerCountBadge');
        var nextBadge = doc.getElementById('headerCountBadge');
        if (badge && nextBadge) { badge.innerHTML = nextBadge.innerHTML; }
        var field = bar.querySelector('.ifp-query input');
        var nextField = fresh.querySelector('[data-ifp-bar] .ifp-query input');
        if (field && nextField && document.activeElement !== field) { field.value = nextField.value; }
    }

    function afterSwap(bar) {
        if (window.selectedItems && typeof selectedItems.clear === 'function') {
            selectedItems.clear();
            if (typeof updateMultiSelectToolbar === 'function') { updateMultiSelectToolbar(); }
        }
        var scope = scopeOf(bar);
        if (scope.querySelector('#viewCard') && typeof setView === 'function') {
            var mobile = typeof isMobile === 'function' && isMobile();
            setView(mobile ? 'card' : (localStorage.getItem('indexViewMode') || 'table'), false, scope);
        }
        clearError(bar);
    }

    function revealTop(bar) {
        var results = resultsOf(bar);
        if (!results) { return; }
        var navHeight = 56;
        var top = results.getBoundingClientRect().top;
        if (top >= navHeight) { return; }
        window.scrollTo({ top: Math.max(0, top + window.pageYOffset - navHeight - 8), behavior: 'smooth' });
    }

    function load(bar, url, push) {
        var tab = tabOf(bar);
        if (tab) {
            originKeys(tab);
            var over = tab.__indexFilterOverride;
            if (over && over.reload && over.reload(url)) { return; }
            if (typeof reloadAjaxTabIndex === 'function') { reloadAjaxTabIndex(tab, url); return; }
        }
        if (inFlight) { inFlight.abort(); }
        var controller = new AbortController();
        inFlight = controller;
        setBusy(bar, true);
        fetch(url, { credentials: 'same-origin', signal: controller.signal })
            .then(function (response) {
                if (!response.ok) { throw new Error('HTTP ' + response.status); }
                return response.text();
            })
            .then(function (html) {
                var doc = new DOMParser().parseFromString(html, 'text/html');
                swapIn(bar, doc);
                if (push) { history.pushState({ ifp: true }, '', url); }
                afterSwap(bar);
                revealTop(bar);
            })
            .catch(function (error) {
                if (error.name !== 'AbortError') { showError(bar); }
            })
            .finally(function () {
                if (inFlight === controller) { inFlight = null; setBusy(bar, false); }
            });
    }

    /* ── pickers ──────────────────────────────────────────────────────── */

    function pickerCfg(picker) {
        if (!picker.__ifp) { picker.__ifp = JSON.parse(picker.getAttribute('data-ifp-picker')); }
        return picker.__ifp;
    }

    function serialize(pc, selection) {
        if (!selection.length) { return null; }
        var included = selection.filter(function (s) { return !s.exclude; });
        // Every fixed option ticked is the same as no filter. A single pick is
        // a choice, even from a list of one (warninglist: No).
        if (!pc.single && pc.options && !pc.exclude && included.length === pc.options.length) { return null; }
        return selection.map(function (s) { return (s.exclude ? '!' : '') + s.value; }).join(pc.sep || '|');
    }

    function swatch(style) {
        if (!style) { return ''; }
        if (style.colour) {
            return '<span class="ifp-swatch" style="--ifp-swatch:' + esc(style.colour) + '"></span>';
        }
        if (style.icon) {
            return '<i class="' + esc(style.icon) + ' ifp-gicon" aria-hidden="true"></i>';
        }
        if (style.logo) {
            return '<span class="dk-logo" aria-hidden="true"><img src="' + esc(style.logo) + '" alt="" loading="lazy"></span>';
        }
        if (style.mono) {
            return '<span class="dk-logo is-mono m' + (parseInt(style.tint, 10) || 0) + '" aria-hidden="true">' + esc(style.mono) + '</span>';
        }
        if (style.badge) {
            return '<span class="ifp-badge" style="' + esc(style.css || '') + '" aria-hidden="true"><i class="' + esc(style.badge) + '"></i></span>';
        }
        return '';
    }

    function stateOf(value) {
        var hit = open.selection.find(function (s) { return s.value === value; });
        return hit ? (hit.exclude ? 'exclude' : 'include') : 'none';
    }

    function rowHtml(item) {
        var state = stateOf(item.value);
        var pc = open.pc;
        var bar = open.bar;
        var subText = (item.style && item.style.galaxy) || item.note;
        var drill = open.view === 'main' && pc.sub && String(item.value) === pc.sub.option;
        var label = item.label;
        if (drill && open.subSelection.some(function (s) { return !s.exclude; })) { label = pc.sub.label; }
        if (drill && open.subSelection.length) {
            var picked = open.subSelection.map(function (s) { return (s.exclude ? '≠ ' : '') + s.label; });
            subText = picked.slice(0, 2).join(', ') + (picked.length > 2 ? ' +' + (picked.length - 2) : '');
        }
        var sub = subText ? ' <small>' + esc(subText) + '</small>' : '';
        var title = item.unresolved ? ' title="' + esc(S(bar, 'unresolved')) + '"' : '';
        var html = '<li class="ifp-opt" role="option" tabindex="-1" data-state="' + state + '"'
            + ' aria-selected="' + (state === 'include') + '" data-value="' + esc(item.value) + '"' + title + '>'
            + '<span class="ifp-opt-check" aria-hidden="true"><i class="fas ' + (state === 'exclude' ? 'fa-ban' : 'fa-check') + '"></i></span>'
            + swatch(item.style)
            + '<span class="ifp-opt-name' + (item.unresolved ? ' is-unresolved' : '') + '">' + esc(label) + sub + '</span>';
        if (pc.exclude) {
            html += '<button type="button" class="ifp-opt-ex" data-ifp-exclude aria-pressed="' + (state === 'exclude') + '"'
                + ' title="' + esc(state === 'exclude' ? S(bar, 'include') : S(bar, 'exclude')) + '"'
                + ' aria-label="' + esc((state === 'exclude' ? S(bar, 'include') : S(bar, 'exclude')) + ' ' + item.label) + '">'
                + '<i class="fas fa-ban" aria-hidden="true"></i></button>';
        }
        if (drill) {
            var drillLabel = S(bar, 'drill').replace('%s', pc.sub.label);
            html += '<button type="button" class="ifp-opt-drill" data-ifp-drill title="' + esc(drillLabel) + '"'
                + ' aria-label="' + esc(drillLabel) + '"><i class="fas fa-chevron-right" aria-hidden="true"></i></button>';
        }
        return html + '</li>';
    }

    // Before anything is typed: each group's rows not already selected.
    function suggestHtml() {
        var multi = open.pc.single ? 'false' : 'true';
        return open.pc.suggest.map(function (group) {
            var rows = group.rows.filter(function (r) {
                return !open.selection.some(function (s) { return s.value === r.value; });
            });
            if (!rows.length) { return ''; }
            return (group.label ? '<div class="ifp-head">' + esc(group.label) + '</div>' : '')
                + '<ul class="ifp-opts" role="listbox" aria-multiselectable="' + multi + '">' + rows.map(rowHtml).join('') + '</ul>'
                + (group.more ? '<div class="ifp-more">' + esc(S(open.bar, 'more').replace('%s', group.more)) + '</div>' : '');
        }).join('');
    }

    function itemFor(value) {
        var pools = [open.selection, open.results || [], open.pc.options || []].concat(
            (open.pc.suggest || []).map(function (group) { return group.rows; }));
        for (var i = 0; i < pools.length; i++) {
            var hit = pools[i].find(function (s) { return String(s.value) === value; });
            if (hit) { return hit; }
        }
        return null;
    }

    function renderLists() {
        var pc = open.pc;
        var bar = open.bar;
        var pop = open.pop;
        var sel = pop.querySelector('.ifp-sel');
        var res = pop.querySelector('.ifp-res');
        var status = pop.querySelector('.ifp-status');
        var activeValue = open.active ? open.active.getAttribute('data-value') : null;
        var focused = document.activeElement && pop.contains(document.activeElement)
            ? document.activeElement.closest('.ifp-opt') : null;
        var focusValue = focused ? focused.getAttribute('data-value') : null;

        if (pc.options && !open.local) {
            res.innerHTML = pc.options.map(rowHtml).join('');
        } else if (open.local) {
            sel.innerHTML = open.selection.map(rowHtml).join('');
            sel.previousElementSibling.hidden = !open.selection.length;
            var term = open.term.toLowerCase();
            var matches = pc.options.filter(function (o) {
                return !open.selection.some(function (s) { return s.value === o.value; })
                    && (term === '' || o.label.toLowerCase().indexOf(term) !== -1);
            });
            res.innerHTML = matches.slice(0, LIST_MAX).map(rowHtml).join('');
            status.hidden = matches.length > 0 && matches.length <= LIST_MAX;
            status.textContent = matches.length > LIST_MAX
                ? S(bar, 'more').replace('%s', matches.length - LIST_MAX) : S(bar, 'noMatch');
        } else {
            sel.innerHTML = open.selection.map(rowHtml).join('');
            sel.previousElementSibling.hidden = !open.selection.length;
            var shown = (open.results || []).filter(function (r) {
                return !open.selection.some(function (s) { return s.value === r.value; });
            });
            res.innerHTML = shown.map(rowHtml).join('');
            var sug = pop.querySelector('.ifp-sug');
            if (sug) { sug.innerHTML = open.status === 'idle' ? suggestHtml() : ''; }
            status.hidden = false;
            if (open.status === 'idle') {
                status.textContent = S(bar, 'typeToSearch');
            } else if (open.status === 'loading') {
                status.textContent = S(bar, 'searching');
            } else if (open.status === 'error') {
                status.textContent = S(bar, 'searchFailed');
            } else if (!open.results.length) {
                status.textContent = S(bar, 'noMatch');
            } else {
                status.hidden = true;
            }
        }
        var rowFor = function (value) {
            return value === null ? null : pop.querySelector('.ifp-opt[data-value="' + CSS.escape(value) + '"]');
        };
        open.active = rowFor(activeValue);
        if (open.active) { open.active.classList.add('is-active'); }
        // Rebuilding the list drops the focused row; keep focus in the picker.
        if (focusValue !== null) {
            var again = rowFor(focusValue) || pop.querySelector('input') || pop;
            again.focus();
        }
    }

    function toggle(value, exclude) {
        var item = itemFor(value);
        if (!item) { return; }
        var i = open.selection.findIndex(function (s) { return s.value === value; });
        var current = i === -1 ? 'none' : (open.selection[i].exclude ? 'exclude' : 'include');
        var next = exclude
            ? (current === 'exclude' ? 'none' : 'exclude')
            : (current === 'none' ? 'include' : 'none');
        if (i !== -1) { open.selection.splice(i, 1); }
        if (open.pc.single) { open.selection = []; }
        if (next !== 'none') {
            open.selection.push({ value: item.value, label: item.label, style: item.style || null, note: item.note || null,
                exclude: next === 'exclude', unresolved: !!item.unresolved });
        }
        if (open.view === 'sub') { open.subSelection = open.selection; } else { open.mainSelection = open.selection; }
        reconcile(open.view === 'sub');
        open.dirty = true;
        if (open.pc.single) {
            var btn = open.picker.querySelector('.ifp-btn');
            closePicker('draft');
            btn.focus();
            return;
        }
        renderLists();
    }

    function search(term) {
        var pc = open.pc;
        if (open.local) {
            open.term = term;
            renderLists();
            return;
        }
        if (open.timer) { clearTimeout(open.timer); open.timer = null; }
        if (open.request) { open.request.abort(); open.request = null; }
        if (term.length < MIN_TERM) {
            open.status = 'idle';
            open.results = [];
            renderLists();
            return;
        }
        open.status = 'loading';
        renderLists();
        var state = open;
        state.timer = setTimeout(function () {
            var controller = new AbortController();
            state.request = controller;
            var sep = pc.source.indexOf('?') === -1 ? '?' : '&';
            fetch(pc.source + sep + 'q=' + encodeURIComponent(term), {
                credentials: 'same-origin',
                headers: { Accept: 'application/json' },
                signal: controller.signal
            })
                .then(function (r) {
                    if (!r.ok) { throw new Error('HTTP ' + r.status); }
                    return r.json();
                })
                .then(function (rows) {
                    if (open !== state) { return; }
                    state.results = Array.isArray(rows) ? rows : [];
                    state.status = 'done';
                    renderLists();
                })
                .catch(function (error) {
                    if (error.name === 'AbortError' || open !== state) { return; }
                    state.status = 'error';
                    renderLists();
                });
        }, THROTTLE);
    }

    /*
     * The index ANDs the sub filter with its parent, so a sub value included
     * narrows the parent to the option it hangs from. Picking another option
     * widens back to the whole option: the included sub values go.
     */
    function reconcile(fromSub) {
        var sub = open.root.sub;
        if (!sub || !open.subSelection.some(function (s) { return !s.exclude; })) { return; }
        var main = open.mainSelection;
        if (main.length === 1 && main[0].value === sub.option && !main[0].exclude) { return; }
        if (fromSub) {
            var option = (open.root.options || []).find(function (o) { return String(o.value) === sub.option; });
            main.splice(0, main.length, { value: sub.option, label: option ? option.label : sub.option,
                style: (option && option.style) || null, note: null, exclude: false, unresolved: false });
        } else {
            open.subSelection = open.subSelection.filter(function (s) { return s.exclude; });
        }
    }

    function changesOf(state) {
        var root = state.root;
        var changes = {};
        if (root.kind === 'time') {
            state.fields.forEach(function (f) {
                changes[f.name] = timeValue(f);
                f.aliases.forEach(function (alias) { changes[alias] = null; });
            });
            return changes;
        }
        changes[root.name] = serialize(root, state.mainSelection);
        if (root.sub) { changes[root.sub.name] = serialize(root.sub, state.subSelection); }
        return changes;
    }

    // The sub list comes whole, once, the first time it is opened.
    function loadSub() {
        var state = open;
        var controller = new AbortController();
        state.request = controller;
        fetch(state.root.sub.source, {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' },
            signal: controller.signal
        })
            .then(function (r) {
                if (!r.ok) { throw new Error('HTTP ' + r.status); }
                return r.json();
            })
            .then(function (rows) {
                state.request = null;
                state.subPc = Object.assign({}, state.root.sub, { options: Array.isArray(rows) ? rows : [], source: null });
                if (open === state && state.view === 'sub') { showView(); }
            })
            .catch(function (error) {
                if (error.name === 'AbortError' || open !== state) { return; }
                state.request = null;
                state.subFailed = true;
                if (state.view === 'sub') { showView(); }
            });
    }

    // Draw the open picker's current level: its own list, or the sub list.
    function showView() {
        var bar = open.bar;
        var pop = open.pop;
        var head = '';
        open.term = '';
        open.results = [];
        open.status = 'idle';
        open.active = null;
        if (open.view === 'sub') {
            var sub = open.root.sub;
            open.selection = open.subSelection;
            var back = S(bar, 'back').replace('%s', open.root.label);
            head = '<div class="ifp-subhead"><button type="button" class="ifp-back" data-ifp-back title="' + esc(back) + '"'
                + ' aria-label="' + esc(back) + '"><i class="fas fa-chevron-left" aria-hidden="true"></i></button>'
                + '<span>' + esc(sub.label) + '</span></div>';
            if (!open.subPc) {
                open.pc = Object.assign({}, sub, { options: [], source: null });
                open.local = false;
                pop.innerHTML = head + '<div class="ifp-status" role="status">'
                    + esc(open.subFailed ? S(bar, 'listFailed') : S(bar, 'loading')) + '</div>';
                pop.querySelector('.ifp-back').focus();
                return;
            }
            open.pc = open.subPc;
            open.local = open.pc.options.length > LOCAL_MAX;
        } else {
            open.selection = open.mainSelection;
            open.pc = open.root;
            open.local = !!open.pc.options && open.pc.options.length > LOCAL_MAX;
        }
        build(bar, pop, open.pc, open.local, head);
        renderLists();
        var input = pop.querySelector('.ifp-search input');
        if (input) {
            input.focus();
            return;
        }
        var first = open.view === 'main' && open.root.sub
            ? pop.querySelector('.ifp-opt[data-value="' + CSS.escape(open.root.sub.option) + '"]') : null;
        first = first && open.cameBack ? first : pop.querySelector('.ifp-opt');
        open.cameBack = false;
        if (first) { setActive(first); first.focus(); }
    }

    function drill(into) {
        open.view = into ? 'sub' : 'main';
        open.cameBack = !into;
        showView();
        if (into && !open.subPc && !open.request) { loadSub(); }
    }

    /* ── time pickers ─────────────────────────────────────────────────── */

    var timeIds = 0;

    function pad(n) { return (n < 10 ? '0' : '') + n; }

    function isoDay(date) { return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate()); }

    // The calendar day a filter value points at: a timestamp, a delta, a date.
    function dayOf(value) {
        value = String(value == null ? '' : value).trim();
        if (value === '' || value === '0') { return ''; }
        if (/^[0-9]+$/.test(value)) { return isoDay(new Date(parseInt(value, 10) * 1000)); }
        var delta = value.match(/^([0-9]+)([dhms])$/i);
        if (delta) {
            var unit = { d: 86400, h: 3600, m: 60, s: 1 }[delta[2].toLowerCase()];
            return isoDay(new Date(Date.now() - delta[1] * unit * 1000));
        }
        var day = value.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}/);
        return day ? day[0] : '';
    }

    function timeField(field, presets) {
        var value = field.value;
        var f = { name: field.name, label: field.label, aliases: field.aliases || [], raw: value,
            touched: false, mode: 'any', from: '', to: '' };
        if (value === null || value === undefined || value === '') { return f; }
        if (!Array.isArray(value) && presets.some(function (p) { return p.value === value; })) {
            f.mode = value;
            return f;
        }
        f.mode = 'custom';
        if (Array.isArray(value)) {
            f.from = dayOf(value[0]);
            f.to = dayOf(value[1]);
        } else {
            f.from = dayOf(value);
        }
        return f;
    }

    // Untouched, a field keeps the URL's value as it was spelled.
    function timeValue(f) {
        if (!f.touched) { return f.raw === null || f.raw === undefined || f.raw === '' ? null : f.raw; }
        if (f.mode === 'any') { return null; }
        if (f.mode !== 'custom') { return f.mode; }
        var to = f.to ? f.to + 'T23:59:59' : '';
        if (f.from && to) { return [f.from, to]; }
        if (f.from) { return f.from; }
        if (to) { return ['0', to]; }
        return null;
    }

    function timeHtml() {
        var pc = open.root;
        var s = pc.strings;
        var today = isoDay(new Date());
        var segments = [{ value: 'any', label: s.any, title: s.anyTitle }]
            .concat(pc.presets)
            .concat([{ value: 'custom', label: s.custom, title: s.customTitle }]);
        return open.fields.map(function (f, i) {
            var id = 'ifp-time-' + open.timeId + '-' + i;
            var html = '<section class="ifp-tf" data-ifp-field="' + i + '">'
                + '<div class="ifp-head" id="' + id + '">' + esc(f.label) + '</div>'
                + '<div class="ifp-seg" role="group" aria-labelledby="' + id + '">'
                + segments.map(function (p) {
                    return '<button type="button" class="ifp-seg-btn" data-ifp-preset="' + esc(p.value) + '"'
                        + ' aria-pressed="' + (f.mode === p.value) + '"' + (p.title ? ' title="' + esc(p.title) + '"' : '') + '>'
                        + esc(p.label) + '</button>';
                }).join('')
                + '</div>';
            if (f.mode === 'custom') {
                html += '<div class="ifp-range">'
                    + '<label><span>' + esc(s.from) + '</span><input type="date" class="form-control form-control-sm" data-ifp-from'
                    + ' value="' + esc(f.from) + '" max="' + esc(f.to || today) + '"></label>'
                    + '<span class="ifp-range-dash" aria-hidden="true">–</span>'
                    + '<label><span>' + esc(s.to) + '</span><input type="date" class="form-control form-control-sm" data-ifp-to'
                    + ' value="' + esc(f.to) + '" min="' + esc(f.from) + '" max="' + esc(today) + '"></label>'
                    + '</div>';
            }
            return html + '</section>';
        }).join('') + '<div class="ifp-foot"><span>' + esc(s.hint) + '</span></div>';
    }

    function setPreset(button) {
        var section = button.closest('[data-ifp-field]');
        var index = parseInt(section.getAttribute('data-ifp-field'), 10);
        var f = open.fields[index];
        var mode = button.getAttribute('data-ifp-preset');
        if (mode === 'custom' && f.mode !== 'custom' && !f.from && !f.to && f.mode !== 'any') {
            f.from = dayOf(f.mode);
        }
        f.mode = mode;
        f.touched = true;
        open.dirty = true;
        open.pop.innerHTML = timeHtml();
        var again = open.pop.querySelector('[data-ifp-field="' + index + '"] '
            + (mode === 'custom' ? '[data-ifp-from]' : '[data-ifp-preset="' + CSS.escape(mode) + '"]'));
        if (again) { again.focus(); }
    }

    function setDay(input) {
        var section = input.closest('[data-ifp-field]');
        var f = open.fields[parseInt(section.getAttribute('data-ifp-field'), 10)];
        var isFrom = input.hasAttribute('data-ifp-from');
        f[isFrom ? 'from' : 'to'] = input.value;
        f.touched = true;
        open.dirty = true;
        var other = section.querySelector(isFrom ? '[data-ifp-to]' : '[data-ifp-from]');
        if (isFrom) { other.min = input.value; } else { other.max = input.value || isoDay(new Date()); }
    }

    function build(bar, pop, pc, local, head) {
        var draft = cfg(bar).apply === 'draft';
        var html = head || '';
        if (pc.source || local) {
            html += '<div class="ifp-search"><i class="fas fa-search" aria-hidden="true"></i>'
                + '<input type="search" class="form-control form-control-sm" autocomplete="off" spellcheck="false"'
                + ' placeholder="' + esc(S(bar, 'search')) + '" aria-label="' + esc(S(bar, 'search') + ' ' + pc.label) + '"></div>';
        }
        if (pc.allOf) {
            html += '<p class="ifp-note"><i class="fas fa-circle-info" aria-hidden="true"></i> ' + esc(S(bar, 'allOf')) + '</p>';
        }
        var multi = pc.single ? 'false' : 'true';
        if (!pc.options || local) {
            html += '<div class="ifp-head" hidden>' + esc(S(bar, 'selected')) + '</div>'
                + '<ul class="ifp-opts ifp-sel" role="listbox" aria-multiselectable="' + multi + '"></ul>';
        }
        if (pc.suggest && pc.suggest.length && !pc.options) { html += '<div class="ifp-sug"></div>'; }
        html += '<ul class="ifp-opts ifp-res" role="listbox" aria-multiselectable="' + multi + '"></ul>';
        if (!pc.options || local) { html += '<div class="ifp-status" role="status"></div>'; }
        var foot = draft ? S(bar, 'applyDraft') : S(bar, 'applyOnClose');
        if (pc.single) { foot = ''; }
        if (pc.hint) { foot = pc.hint + (foot ? ' ' + foot : ''); }
        html += '<div class="ifp-foot"' + (foot || draft ? '' : ' hidden') + '><span>' + esc(foot) + '</span>';
        if (draft) {
            html += '<button type="button" class="btn btn-sm btn-primary" data-ifp-apply>' + esc(S(bar, 'apply')) + '</button>';
        }
        html += '</div>';
        pop.innerHTML = html;
        return pop;
    }

    function browses(picker) {
        return !!(picker && pickerCfg(picker).browser && window.IndexFilterBrowser);
    }

    function openPicker(picker) {
        if (!picker || (open && open.picker === picker)) { return; }
        closePicker(true);
        if (browses(picker)) {
            window.IndexFilterBrowser.open(picker);
            return;
        }
        var bar = barOf(picker);
        var pc = pickerCfg(picker);
        var pop = picker.querySelector('.ifp-pop');
        var copy = function (s) { return Object.assign({}, s); };
        open = {
            bar: bar,
            local: false,
            term: '',
            picker: picker,
            root: pc,
            pc: pc,
            pop: pop,
            view: 'main',
            selection: (pc.selected || []).map(copy),
            subSelection: pc.sub ? pc.sub.selected.map(copy) : [],
            subPc: null,
            dirty: false,
            results: [],
            status: 'idle',
            active: null,
            timer: null,
            request: null,
        };
        open.mainSelection = open.selection;
        pop.hidden = false;
        picker.querySelector('.ifp-btn').setAttribute('aria-expanded', 'true');
        if (pc.kind === 'time') {
            open.timeId = ++timeIds;
            open.fields = pc.fields.map(function (f) { return timeField(f, pc.presets); });
            open.initial = JSON.stringify(changesOf(open));
            pop.innerHTML = timeHtml();
            placePop(pop);
            var pressed = pop.querySelector('.ifp-seg-btn[aria-pressed="true"]');
            if (pressed) { pressed.focus(); }
            return;
        }
        reconcile(true);
        open.initial = pc.allOf ? null : JSON.stringify(changesOf(open));
        showView();
        placePop(pop);
    }

    // Open to the right of the button unless that runs off the viewport.
    function placePop(pop) {
        pop.classList.remove('is-end');
        var rect = pop.getBoundingClientRect();
        if (rect.right > document.documentElement.clientWidth - 8) { pop.classList.add('is-end'); }
    }

    function closePicker(apply) {
        if (!open) { return; }
        var state = open;
        open = null;
        if (state.timer) { clearTimeout(state.timer); }
        if (state.request) { state.request.abort(); }
        state.pop.hidden = true;
        state.pop.innerHTML = '';
        state.picker.querySelector('.ifp-btn').setAttribute('aria-expanded', 'false');
        if (!apply || !state.dirty) { return; }
        if (cfg(state.bar).apply === 'draft' && apply !== 'draft') { return; }
        var changes = changesOf(state);
        if (JSON.stringify(changes) === state.initial) { return; }
        load(state.bar, urlWith(state.bar, changes), true);
    }

    function setActive(row) {
        if (open.active) { open.active.classList.remove('is-active'); }
        open.active = row;
        if (row) { row.classList.add('is-active'); }
    }

    function move(delta) {
        var rows = Array.prototype.slice.call(open.pop.querySelectorAll('.ifp-opt'));
        if (!rows.length) { return; }
        var at = rows.indexOf(open.active);
        var next = rows[Math.max(0, Math.min(rows.length - 1, at === -1 ? 0 : at + delta))];
        setActive(next);
        next.scrollIntoView({ block: 'nearest' });
    }

    /* ── wiring ───────────────────────────────────────────────────────── */

    function applyValueMatch(bar, input, clear) {
        if (!input) { return; }
        var changes = {};
        changes[input.getAttribute('name')] = clear ? null : input.value.trim();
        load(bar, urlWith(bar, changes), true);
    }

    function isPlainClick(event) {
        return !(event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0);
    }

    // A link this bar loads in place. In a tab the pager and the sort links
    // are the tab's own (bindAjaxTabIndexNav), so only the bar's are taken.
    function navLink(bar, target) {
        var link = target.closest('a[href]');
        if (!link || scopeOf(link) !== scopeOf(bar)) { return null; }
        if (link.hasAttribute('data-ifp-nav')) { return link; }
        if (tabOf(bar)) { return null; }
        if (link.closest('.index-filter-pager')) { return link; }
        var results = link.closest('[data-ifp-results]');
        if (results && (link.closest('.pagination') || link.closest('thead'))) { return link; }
        return null;
    }

    document.addEventListener('click', function (event) {
        var target = event.target;

        // A click elsewhere closes the open picker, then still does its own job.
        if (open && !open.picker.contains(target)) { closePicker(true); }

        var bar = barOf(target);
        if (!bar) { return; }

        var btn = target.closest('.ifp-btn');
        if (btn) {
            var picker = btn.closest('.ifp-picker');
            if (browses(picker)) {
                closePicker(true);
                window.IndexFilterBrowser.toggle(picker);
            } else if (open && open.picker === picker) {
                closePicker(true);
            } else {
                openPicker(picker);
            }
            return;
        }

        var opener = target.closest('[data-ifp-open]');
        if (opener) {
            var named = swapNode(scopeOf(bar), 'picker-' + opener.getAttribute('data-ifp-open'));
            if (named) {
                event.preventDefault();
                named.scrollIntoView({ block: 'nearest' });
                openPicker(named);
            }
            return;
        }

        if (open && open.picker.contains(target)) {
            if (target.closest('[data-ifp-apply]')) { closePicker('draft'); return; }
            if (target.closest('[data-ifp-drill]')) { drill(true); return; }
            if (target.closest('[data-ifp-back]')) { drill(false); return; }
            var preset = target.closest('[data-ifp-preset]');
            if (preset) { setPreset(preset); return; }
            var row = target.closest('.ifp-opt');
            if (row) {
                toggle(row.getAttribute('data-value'), !!target.closest('[data-ifp-exclude]'));
                var input = open && open.pop.querySelector('input');
                if (input) { input.focus(); }
            }
            return;
        }

        var vm = target.closest('.value-match-apply, .value-match-clear');
        if (vm) {
            applyValueMatch(bar, vm.closest('.input-group').querySelector('.value-match-input'),
                vm.classList.contains('value-match-clear'));
            return;
        }

        var link = event.defaultPrevented ? null : navLink(bar, target);
        if (link && isPlainClick(event)) {
            event.preventDefault();
            load(bar, link.getAttribute('href'), true);
        }
    });

    document.addEventListener('input', function (event) {
        if (open && event.target.matches('.ifp-search input')) {
            search(event.target.value.trim());
        } else if (open && event.target.matches('[data-ifp-from], [data-ifp-to]')) {
            setDay(event.target);
        }
    });

    document.addEventListener('keydown', function (event) {
        if (open && event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            if (open.view === 'sub') {
                drill(false);
                return;
            }
            var btn = open.picker.querySelector('.ifp-btn');
            closePicker(true);
            btn.focus();
            return;
        }
        if (open && open.picker.contains(event.target)) {
            var typing = event.target.matches('input');
            if (event.key === 'ArrowRight' && !typing && open.active && open.active.querySelector('[data-ifp-drill]')) {
                event.preventDefault();
                drill(true);
            } else if (event.key === 'ArrowLeft' && !typing && open.view === 'sub') {
                event.preventDefault();
                drill(false);
            } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                move(event.key === 'ArrowDown' ? 1 : -1);
            } else if (event.key === 'Enter' && open.active && !event.target.closest('[data-ifp-exclude]')) {
                event.preventDefault();
                toggle(open.active.getAttribute('data-value'), false);
            }
            return;
        }
        if (event.key === 'Enter' && event.target.matches('.value-match-input')) {
            var vmBar = barOf(event.target);
            if (!vmBar) { return; }
            event.preventDefault();
            applyValueMatch(vmBar, event.target, false);
            return;
        }
        if (event.key === 'Enter' && event.target.closest('.ifp-query')) {
            var bar = barOf(event.target);
            if (!bar) { return; }
            event.preventDefault();
            load(bar, searchUrl(bar), true);
        }
    }, true);

    // Tabbing out of a picker closes it; a click on its own padding does not.
    document.addEventListener('focusout', function (event) {
        if (!open || !open.picker.contains(event.target)) { return; }
        var next = event.relatedTarget;
        if (next && !open.picker.contains(next)) { closePicker(true); }
    });

    // Only a bar on the page itself follows Back / Forward.
    window.addEventListener('popstate', function () {
        document.querySelectorAll('[data-ifp-bar]').forEach(function (bar) {
            if (tabOf(bar) || window.location.pathname.indexOf(pathOf(cfg(bar).base)) !== 0) { return; }
            closePicker(false);
            load(bar, window.location.pathname + window.location.search, false);
        });
    });

    document.addEventListener('misp:container-loaded', function (event) { applyAllTabScopes(event.target); });
    applyAllTabScopes(document);

    window.IndexFilters = {
        load: function (node, url, push) { var bar = barOf(node); if (bar) { load(bar, url, push); } },
        urlWith: function (node, changes) { var bar = barOf(node); return bar ? urlWith(bar, changes) : null; },
        applyTabScope: applyAllTabScopes,
    };
}());
