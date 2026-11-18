/*
 * REST client (api/rest) for the Overmind theme.
 *
 * The page is three parts: the library (templates, history, bookmarks), the
 * request form that posts to api/rest, and the response the server renders
 * back. Everything here is wired from data attributes, so the templates carry
 * no inline handlers.
 */
(function () {
    'use strict';

    const METHOD_TONES = { GET: 'success', POST: 'primary', PUT: 'warning', DELETE: 'danger' };
    const LIBRARY_TAB_KEY = 'restClientLibraryTab';

    let allValidApis = {};
    let form = null;
    let tooltipTimeout = null;
    let pointerOnTooltip = false;

    document.addEventListener('DOMContentLoaded', function () {
        form = document.getElementById('restClientForm');
        if (!form) {
            return;
        }
        fetch(baseurl + '/api/getAllApis')
            .then(res => res.json())
            .then(data => { allValidApis = data.allValidApis || {}; })
            .catch(() => {});

        initRequest();
        initHeaders();
        initLibrary();
        initResponse();
        initBookmarkModal();
        initShortcuts();
    });


    /* ── Request bar ── */

    function initRequest() {
        const method = document.getElementById('server-method');
        method.addEventListener('change', paintMethod);
        paintMethod();

        const fullPath = document.getElementById('use-full-path');
        if (fullPath) {
            fullPath.addEventListener('change', paintBaseUrl);
            paintBaseUrl();
        }

        const body = document.getElementById('server-body');
        body.addEventListener('misp:json-change', function (e) {
            paintBodyBadge(e.detail);
            if (e.detail.empty) {
                showTemplateCallout(null);
            }
        });
        if (body.jsonField) {
            paintBodyBadge({ empty: body.jsonField.isEmpty(), valid: body.jsonField.isValid() });
        }
        document.getElementById('rest-template-close').addEventListener('click', () => showTemplateCallout(null));

        form.addEventListener('submit', syncHeaders);
    }

    function paintMethod() {
        const select = document.getElementById('server-method');
        Object.values(METHOD_TONES).concat('secondary').forEach(function (tone) {
            select.classList.remove('bg-' + tone + '-subtle', 'text-' + tone + '-emphasis');
        });
        const tone = METHOD_TONES[select.value] || 'secondary';
        select.classList.add('bg-' + tone + '-subtle', 'text-' + tone + '-emphasis');
    }

    /* The base URL is what the server prefixes to a relative endpoint; with
       "Use full path" the endpoint is the whole URL, so the prefix would lie. */
    function paintBaseUrl() {
        const fullPath = document.getElementById('use-full-path');
        const base = document.getElementById('rest-base-url');
        base.classList.toggle('d-md-flex', !(fullPath && fullPath.checked));
    }

    function paintBodyBadge(detail) {
        const badge = document.getElementById('rest-body-badge');
        let tone = 'secondary';
        let label = badge.dataset.lEmpty;
        if (!detail.empty) {
            tone = detail.valid ? 'success' : 'danger';
            label = detail.valid ? badge.dataset.lValid : badge.dataset.lInvalid;
        }
        badge.className = 'badge bg-' + tone + '-subtle text-' + tone + '-emphasis';
        if (tone === 'secondary') {
            badge.className = 'badge bg-body-secondary text-body-secondary';
        }
        badge.textContent = label;
    }

    function setBody(text) {
        const body = document.getElementById('server-body');
        body.value = text;
        // json_field reads the box on `input`, and an assignment fires none.
        body.dispatchEvent(new Event('input', { bubbles: true }));
    }

    function showTemplateCallout(name, required) {
        const callout = document.getElementById('rest-template-callout');
        callout.classList.toggle('d-none', !name);
        callout.classList.toggle('d-flex', !!name);
        if (!name) {
            return;
        }
        document.getElementById('rest-template-name').textContent = name;

        const list = document.getElementById('rest-template-required');
        list.querySelectorAll('code').forEach(el => el.remove());
        (required || []).forEach(function (field) {
            const chip = document.createElement('code');
            chip.className = 'px-1 bg-body border rounded text-body';
            chip.textContent = field;
            list.appendChild(chip);
        });
        list.classList.toggle('d-none', !(required && required.length));
        list.classList.toggle('d-flex', !!(required && required.length));
    }

    function showRequestTab(name) {
        const tab = document.getElementById('rest-tab-' + name);
        if (tab) {
            bootstrap.Tab.getOrCreateInstance(tab).show();
        }
    }


    /* ── Headers ── */

    function initHeaders() {
        const list = document.getElementById('rest-headers');
        parseHeaders(document.getElementById('hidden-header-payload').value).forEach(h => addHeaderRow(h[0], h[1]));

        document.getElementById('rest-header-add').addEventListener('click', function () {
            addHeaderRow('', '').querySelector('.header-key').focus();
            paintHeaders();
        });
        list.addEventListener('click', function (e) {
            const remove = e.target.closest('[data-rest-header-remove]');
            if (remove) {
                remove.closest('[data-rest-header]').remove();
                paintHeaders();
            }
        });
        list.addEventListener('input', paintHeaders);
        paintHeaders();
    }

    function parseHeaders(text) {
        return String(text || '').replace(/\r/g, '').split('\n')
            .map(line => {
                const at = line.indexOf(':');
                return at < 0 ? null : [line.slice(0, at).trim(), line.slice(at + 1).trim()];
            })
            .filter(h => h && h[0] !== '');
    }

    function addHeaderRow(key, value) {
        const row = document.getElementById('rest-header-row').content.firstElementChild.cloneNode(true);
        row.querySelector('.header-key').value = key;
        row.querySelector('.header-value').value = value;
        document.getElementById('rest-headers').appendChild(row);
        return row;
    }

    function readHeaders() {
        return Array.from(document.querySelectorAll('#rest-headers [data-rest-header]'))
            .map(row => [row.querySelector('.header-key').value.trim(), row.querySelector('.header-value').value.trim()])
            .filter(h => h[0] !== '');
    }

    function isPlaceholderKey(value) {
        const placeholder = document.getElementById('rest-headers').dataset.placeholder;
        return value.trim() === '' || value.trim() === placeholder;
    }

    /* Count, and flag an Authorization header still holding the placeholder:
       it is the first thing a request sent from here gets wrong. */
    function paintHeaders() {
        let placeholder = false;
        document.querySelectorAll('#rest-headers [data-rest-header]').forEach(function (row) {
            const isAuth = row.querySelector('.header-key').value.trim().toLowerCase() === 'authorization';
            const value = row.querySelector('.header-value');
            const flagged = isAuth && isPlaceholderKey(value.value);
            value.classList.toggle('border-warning', flagged);
            value.classList.toggle('bg-warning-subtle', flagged);
            placeholder = placeholder || flagged;
        });
        document.getElementById('rest-header-count').textContent = readHeaders().length;
        document.getElementById('rest-header-warning').classList.toggle('d-none', !placeholder);
        document.getElementById('rest-header-warning-dot').classList.toggle('d-none', !placeholder);
    }

    function syncHeaders() {
        document.getElementById('hidden-header-payload').value =
            readHeaders().map(h => h[0] + ': ' + h[1]).join('\n');
    }


    /* ── Library ── */

    function initLibrary() {
        const library = document.getElementById('rest-library');

        library.addEventListener('shown.bs.tab', function (e) {
            const key = e.target.dataset.restLibraryTab;
            document.getElementById('rest-library-hint').textContent = e.target.dataset.restHint;
            try { localStorage.setItem(LIBRARY_TAB_KEY, key); } catch (err) { /* per-viewer nicety */ }
        });
        try {
            const saved = localStorage.getItem(LIBRARY_TAB_KEY);
            const tab = saved && library.querySelector('[data-rest-library-tab="' + saved + '"]');
            if (tab) {
                bootstrap.Tab.getOrCreateInstance(tab).show();
            }
        } catch (err) { /* per-viewer nicety */ }

        library.addEventListener('show.bs.collapse', e => paintChevron(e.target, true));
        library.addEventListener('hide.bs.collapse', e => paintChevron(e.target, false));

        document.getElementById('rest-library-filter').addEventListener('input', filterLibrary);

        library.addEventListener('click', function (e) {
            const info = e.target.closest('[data-rest-info]');
            if (info) {
                e.stopPropagation();
                fetchApiInfo(info.closest('[data-rest-row]').dataset.url, info);
                return;
            }
            const del = e.target.closest('[data-rest-delete]');
            if (del) {
                e.stopPropagation();
                confirmDelete(del.dataset.restDelete, del.closest('[data-rest-row]'));
                return;
            }
            const row = e.target.closest('[data-rest-row]');
            if (row) {
                loadRow(row);
            }
        });
        library.addEventListener('keydown', function (e) {
            const row = e.target.closest('[data-rest-row]');
            if (row && e.target === row && (e.key === 'Enter' || e.key === ' ')) {
                e.preventDefault();
                loadRow(row);
            }
        });

        library.addEventListener('mouseover', function (e) {
            const info = e.target.closest('[data-rest-info]');
            if (info && !info.contains(e.relatedTarget)) {
                clearTimeout(tooltipTimeout);
                tooltipTimeout = setTimeout(() => fetchApiInfo(info.closest('[data-rest-row]').dataset.url, info), 200);
            }
        });
        library.addEventListener('mouseout', function (e) {
            const info = e.target.closest('[data-rest-info]');
            if (info && !info.contains(e.relatedTarget)) {
                scheduleHideTooltip();
            }
        });

        const tooltip = document.getElementById('api-tooltip');
        if (tooltip) {
            // Keep it open while the pointer is inside, so a long description
            // can be read (and selected) without it slipping away.
            tooltip.addEventListener('mouseenter', () => { pointerOnTooltip = true; clearTimeout(tooltipTimeout); });
            tooltip.addEventListener('mouseleave', () => { pointerOnTooltip = false; scheduleHideTooltip(); });
            document.addEventListener('click', function (e) {
                if (!tooltip.contains(e.target) && !e.target.closest('[data-rest-info]')) {
                    hideApiTooltip();
                }
            });
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape') {
                    hideApiTooltip();
                }
            });
        }

        populateRestHistory('history');
        populateRestHistory('bookmark');
    }

    function paintChevron(collapse, open) {
        const group = collapse.closest('[data-rest-group]');
        const chevron = group && group.querySelector('[data-rest-chevron]');
        if (chevron) {
            chevron.classList.toggle('fa-chevron-down', open);
            chevron.classList.toggle('fa-chevron-right', !open);
        }
    }

    /* Opens or closes a group without Bootstrap's animation, for the filter,
       keeping its toggle's state in step as Collapse itself would. */
    function setGroupOpen(collapse, open) {
        collapse.classList.toggle('show', open);
        const toggle = collapse.closest('[data-rest-group]').querySelector('[data-bs-toggle="collapse"]');
        toggle.classList.toggle('collapsed', !open);
        toggle.setAttribute('aria-expanded', String(open));
        paintChevron(collapse, open);
    }

    function loadRow(row) {
        if (row.dataset.restRow === 'template') {
            applyTemplate(row);
        } else {
            applyQuery(row);
        }
        document.querySelectorAll('#rest-library [data-rest-row].active').forEach(r => r.classList.remove('active'));
        row.classList.add('active');
        form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    async function populateRestHistory(scopeType) {
        const isHistory = scopeType === 'history';
        const container = document.getElementById(isHistory ? 'history-container' : 'bookmarks-container');
        if (!container) {
            return;
        }
        try {
            const response = await fetch(baseurl + '/rest_client_history/index/' + (isHistory ? '' : '1'), {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            if (response.ok) {
                container.innerHTML = await response.text();
                paintTimes(container);
                setLibraryCount(isHistory ? 'history' : 'bookmarks', container.querySelectorAll('[data-rest-row]').length);
                filterLibrary();
            }
        } catch (error) {
            console.error('Error loading ' + scopeType + ':', error);
        }
    }

    function setLibraryCount(key, count) {
        const badge = document.querySelector('[data-rest-count="' + key + '"]');
        if (badge) {
            badge.textContent = count;
        }
    }

    function paintTimes(container) {
        const format = typeof Intl !== 'undefined' && Intl.RelativeTimeFormat
            ? new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'short' })
            : null;
        if (!format) {
            return;
        }
        const steps = [[60, 'second'], [3600, 'minute'], [86400, 'hour'], [604800, 'day'], [2629800, 'week'], [31557600, 'month'], [Infinity, 'year']];
        const sizes = { second: 1, minute: 60, hour: 3600, day: 86400, week: 604800, month: 2629800, year: 31557600 };
        container.querySelectorAll('[data-rest-ago]').forEach(function (el) {
            const delta = Number(el.dataset.restAgo) - Date.now() / 1000;
            const unit = steps.find(s => Math.abs(delta) < s[0])[1];
            el.textContent = format.format(Math.round(delta / sizes[unit]), unit);
        });
    }

    function filterLibrary() {
        const query = document.getElementById('rest-library-filter').value.trim().toLowerCase();
        document.querySelectorAll('#rest-library .tab-pane').forEach(function (pane) {
            let shown = 0;
            pane.querySelectorAll('[data-rest-row]').forEach(function (row) {
                const match = query === '' || row.dataset.filter.includes(query);
                row.classList.toggle('d-none', !match);
                shown += match ? 1 : 0;
            });
            pane.querySelectorAll('[data-rest-group]').forEach(filterGroup.bind(null, query));
            const noMatch = pane.querySelector('[data-rest-no-match]');
            if (noMatch) {
                noMatch.classList.toggle('d-none', query === '' || shown > 0);
            }
        });
    }

    /* While filtering, every group with a match is open and the others are
       gone; clearing the filter puts back the groups the user had opened. */
    function filterGroup(query, group) {
        const rows = group.querySelectorAll('[data-rest-row]');
        const shown = group.querySelectorAll('[data-rest-row]:not(.d-none)').length;
        const collapse = group.querySelector('.collapse');
        const count = group.querySelector('[data-rest-group-count]');

        group.classList.toggle('d-none', shown === 0);
        count.textContent = query === '' ? rows.length : shown;

        if (query !== '') {
            if (!('restWasOpen' in group.dataset)) {
                group.dataset.restWasOpen = collapse.classList.contains('show') ? '1' : '0';
            }
            setGroupOpen(collapse, true);
        } else if ('restWasOpen' in group.dataset) {
            setGroupOpen(collapse, group.dataset.restWasOpen === '1');
            delete group.dataset.restWasOpen;
        }
    }

    function confirmDelete(id, row) {
        showConfirmModal({
            title: 'Delete this request?',
            body: '<p class="mb-0 small text-body-secondary">It is removed from the history, and from the bookmarks if it was saved there.</p>',
            confirmLabel: 'Delete',
            confirmClass: 'btn-danger',
            onConfirm: () => deleteHistoryItem(id, row)
        });
    }

    async function deleteHistoryItem(id, row) {
        try {
            const response = await fetch(baseurl + '/rest_client_history/delete/' + encodeURIComponent(id), {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: '[]'
            });
            if (!response.ok) {
                throw new Error('Server returned ' + response.status);
            }
            if (row) {
                row.remove();
            }
            populateRestHistory('history');
            populateRestHistory('bookmark');
            showToast('Request deleted');
        } catch (error) {
            console.error('Delete failed:', error);
            showToast('The request could not be deleted.', 'danger');
        }
    }


    /* ── Loading a template or a past query ── */

    function setMethod(method) {
        const select = document.getElementById('server-method');
        select.value = method || 'GET';
        paintMethod();
    }

    function applyTemplate(row) {
        const url = row.dataset.url;
        const api = allValidApis[url];
        const urlInput = document.getElementById('server-url');
        const body = document.getElementById('server-body');

        setMethod(row.dataset.method);
        urlInput.value = api ? api.url : url;
        urlInput.dispatchEvent(new Event('input', { bubbles: true }));

        const template = api && api.body && Object.keys(api.body).length ? api.body : null;
        if (template) {
            // A template only replaces a body the user typed when it is a
            // different template's, so going back to the same one keeps edits.
            if (body.value.trim() === '' || body.dataset.lastTemplate !== url) {
                setBody(JSON.stringify(template, null, 4));
                body.dataset.lastTemplate = url;
            }
        } else if (body.dataset.lastTemplate) {
            setBody('');
            delete body.dataset.lastTemplate;
        }

        const hasPlaceholders = !!template || /\[[^\]]+\]/.test(urlInput.value);
        showTemplateCallout(hasPlaceholders ? row.dataset.method + ' ' + url : null, api ? api.mandatory : []);
        showRequestTab('body');
    }

    function applyQuery(row) {
        let data;
        try {
            data = JSON.parse(row.dataset.payload || '{}');
        } catch (e) {
            console.error('Unreadable stored query', e);
            return;
        }

        setMethod(data.http_method);
        const urlInput = document.getElementById('server-url');
        urlInput.value = data.url || '';
        urlInput.dispatchEvent(new Event('input', { bubbles: true }));

        const body = document.getElementById('server-body');
        delete body.dataset.lastTemplate;
        setBody(data.body || '');
        showTemplateCallout(null);

        // With advanced auth keys the history stores the placeholder instead
        // of the key, so a replay keeps the key the user has already typed.
        const currentAuth = readHeaders().find(h => h[0].toLowerCase() === 'authorization');
        const stored = parseHeaders(data.headers);
        if (stored.length) {
            document.getElementById('rest-headers').innerHTML = '';
            stored.forEach(function (h) {
                const keep = h[0].toLowerCase() === 'authorization' && isPlaceholderKey(h[1])
                    && currentAuth && !isPlaceholderKey(currentAuth[1]);
                addHeaderRow(h[0], keep ? currentAuth[1] : h[1]);
            });
            paintHeaders();
        }

        const checks = { 'skip-ssl': data.skip_ssl, 'show-result': data.show_result, 'use-full-path': data.use_full_path };
        Object.keys(checks).forEach(function (id) {
            const box = document.getElementById(id);
            if (box) {
                box.checked = checks[id] == 1 || checks[id] === true;
            }
        });
        paintBaseUrl();
        showRequestTab('body');
    }


    /* ── OpenAPI description tooltip ── */

    function extractPathFromUrl(url) {
        const el = document.createElement('a');
        el.href = url;
        return el.pathname;
    }

    function fetchApiInfo(url, anchor) {
        fetch(baseurl + '/api/getApiInfo', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ url: extractPathFromUrl(url) })
        })
            .then(response => response.text())
            .then(html => showApiTooltip(html, anchor))
            .catch(hideApiTooltip);
    }

    function showApiTooltip(content, anchor) {
        const tooltip = document.getElementById('api-tooltip');
        if (!tooltip) {
            return;
        }
        tooltip.innerHTML = content;
        tooltip.style.display = 'block';

        // Beside the row rather than over it: the library is the left column,
        // so the right-hand side is where the room is.
        const rect = anchor.getBoundingClientRect();
        const box = tooltip.getBoundingClientRect();
        const margin = 8;
        const viewport = document.documentElement.clientWidth;
        let left = rect.right + margin;
        if (left + box.width > viewport - margin) {
            left = Math.max(margin, rect.left - box.width - margin);
        }
        tooltip.style.left = (left + window.scrollX) + 'px';
        tooltip.style.top = (Math.max(margin, rect.top - margin) + window.scrollY) + 'px';
    }

    function hideApiTooltip() {
        const tooltip = document.getElementById('api-tooltip');
        if (tooltip) {
            tooltip.style.display = 'none';
        }
    }

    function scheduleHideTooltip() {
        clearTimeout(tooltipTimeout);
        tooltipTimeout = setTimeout(function () {
            if (!pointerOnTooltip) {
                hideApiTooltip();
            }
        }, 150);
    }


    /* ── Response ── */

    function initResponse() {
        const response = document.getElementById('rest-response');

        response.querySelectorAll('[data-rest-code]').forEach(paintCode);

        response.addEventListener('click', function (e) {
            const copy = e.target.closest('[data-rest-copy]');
            if (copy) {
                const source = document.querySelector(copy.dataset.restCopy);
                copyValueToClipboard(source ? source.textContent : '', copy.dataset.restCopied);
            }
        });

        const wrap = document.getElementById('rest-response-wrap');
        if (wrap) {
            wrap.addEventListener('click', function () {
                const on = wrap.getAttribute('aria-pressed') !== 'true';
                wrap.setAttribute('aria-pressed', String(on));
                wrap.classList.toggle('active', on);
                response.querySelectorAll('[data-rest-code]').forEach(function (code) {
                    code.classList.toggle('is-wrapped', on);
                    paintLineNumbers(code);
                });
            });
        }

        const download = document.getElementById('rest-response-download');
        if (download) {
            download.addEventListener('click', () => downloadResponse(download));
        }

        // The page comes back from a send scrolled to the top, with the answer
        // below the form: bring it into view.
        if (response.hasAttribute('data-rest-response')) {
            const top = response.getBoundingClientRect().top;
            if (top > window.innerHeight * 0.5) {
                window.scrollTo({ top: top + window.scrollY - 16, behavior: 'smooth' });
            }
        }
    }

    function paintCode(code) {
        const text = code.querySelector('.rest-code-text');
        if (text.hasAttribute('data-rest-json')) {
            text.innerHTML = highlightJson(text.textContent);
        }
        paintLineNumbers(code);
    }

    /* Wrapped lines take several rows, so their numbers would drift from the
       text; the gutter only shows while each line is one row. */
    function paintLineNumbers(code) {
        const gutter = code.querySelector('[data-rest-lines]');
        const wrapped = code.classList.contains('is-wrapped');
        gutter.classList.toggle('d-none', wrapped);
        if (!wrapped && gutter.textContent === '') {
            const count = code.querySelector('.rest-code-text').textContent.split('\n').length;
            gutter.textContent = Array.from({ length: count }, (_, i) => i + 1).join('\n');
        }
    }

    function highlightJson(json) {
        const escaped = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const token = /("(?:\\.|[^\\"])*")(\s*:)?|\b(true|false)\b|\bnull\b|-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g;
        return escaped.replace(token, function (match, string, colon, bool) {
            let tone = 'text-warning-emphasis';
            if (string) {
                tone = colon ? 'text-primary-emphasis' : 'text-success-emphasis';
            } else if (bool) {
                tone = 'text-info-emphasis';
            } else if (match === 'null') {
                tone = 'text-body-tertiary';
            }
            return '<span class="' + tone + '">' + match + '</span>';
        });
    }

    function downloadResponse(btn) {
        const source = document.getElementById('response-body-code');
        const name = btn.dataset.filename || 'response.json';
        const blob = new Blob([source ? source.textContent : ''], {
            type: name.endsWith('.json') ? 'application/json' : 'text/plain'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Response downloaded');
    }


    /* ── Bookmark ── */

    function initBookmarkModal() {
        const modalEl = document.getElementById('rest-bookmark-modal');
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        const nameInput = document.getElementById('rest-bookmark-name');

        document.getElementById('rest-bookmark-open').addEventListener('click', function () {
            const method = document.getElementById('server-method').value || 'GET';
            const tone = METHOD_TONES[method] || 'secondary';
            const preview = document.getElementById('rest-bookmark-preview');
            const badge = document.createElement('span');
            badge.className = 'badge bg-' + tone + '-subtle text-' + tone + '-emphasis';
            badge.textContent = method;
            preview.replaceChildren(badge, document.createTextNode(document.getElementById('server-url').value || '/'));

            nameInput.value = '';
            nameInput.classList.remove('is-invalid');
            modal.show();
        });
        modalEl.addEventListener('shown.bs.modal', () => nameInput.focus());
        nameInput.addEventListener('input', () => nameInput.classList.remove('is-invalid'));
        nameInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                saveBookmark(modal);
            }
        });
        document.getElementById('rest-bookmark-save').addEventListener('click', () => saveBookmark(modal));
    }

    /* A bookmark is saved by the request itself: the form posts with the
       bookmark flag and the name, and the server stores it as it runs it. */
    function saveBookmark(modal) {
        const nameInput = document.getElementById('rest-bookmark-name');
        const name = nameInput.value.trim();
        if (!name) {
            nameInput.classList.add('is-invalid');
            nameInput.focus();
            return;
        }
        document.getElementById('hidden-bookmark-name').value = name;
        document.getElementById('hidden-bookmark-checkbox').checked = true;
        modal.hide();
        form.requestSubmit();
    }


    /* ── Keyboard ── */

    function initShortcuts() {
        document.addEventListener('keydown', function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (document.querySelector('.modal.show')) {
                    return;
                }
                e.preventDefault();
                form.requestSubmit();
                return;
            }
            const typing = e.target.closest('input, textarea, select, [contenteditable="true"]');
            if (e.key === '/' && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
                e.preventDefault();
                document.getElementById('rest-library-filter').focus();
            }
        });
    }
})();
