/* Overmind theme JS namespace — shared mutable handle for the event-view tabs. */
window.mispView = window.mispView || {};

/*******************************
 * Dark mode
 *******************************/
function toggleDarkMode() {
    const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
    const next = !isDark;
    document.documentElement.setAttribute('data-bs-theme', next ? 'dark' : 'light');
    localStorage.setItem('darkMode', next);
    updateDarkModeUI(next);
}

function updateDarkModeUI(isDark) {
    document.querySelectorAll('.dark-mode-icon').forEach(function(icon) {
        icon.className = 'fa-fw dark-mode-icon fas ' + (isDark ? 'fa-sun' : 'fa-moon');
    });
    document.querySelectorAll('.dark-mode-badge').forEach(function(badge) {
        badge.textContent = isDark ? 'ON' : 'OFF';
        badge.className = 'badge ms-2 dark-mode-badge ' + (isDark ? 'bg-success' : 'bg-secondary');
    });
}

document.addEventListener('DOMContentLoaded', function() {
    updateDarkModeUI(localStorage.getItem('darkMode') === 'true');
});

/*******************************
 * Toast notifications
 *******************************/
function showToast(message, variant = 'success') {
    const container = document.getElementById('mainToastContainer');
    if (!container) return;

    const id = 'toast-' + Date.now();
    container.insertAdjacentHTML('beforeend', `
        <div id="${id}" class="toast align-items-center text-bg-${variant} border-0" role="alert" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `);
    const el = document.getElementById(id);
    const toast = new bootstrap.Toast(el, { delay: 3000 });
    toast.show();
    el.addEventListener('hidden.bs.toast', () => el.remove());
}

/*******************************
 * Size the shared #mainModal dialog.
 *
 * Bootstrap ships four widths but only three classes: 'md' IS the class-less
 * default (500px), so a medium modal is obtained by removing every size class,
 * never by adding one. `modal-md` is in the remove list because the theme used
 * to add it — it never had any CSS, so it silently meant 500px, but it stuck to
 * the dialog for every later open.
 *
 *   'sm' 300px | 'md' / null 500px | 'lg' 800px | 'xl' 1140px
 *******************************/
function setModalSize(size, dialog) {
    dialog = dialog || document.querySelector('#mainModal .modal-dialog');
    if (!dialog) {
        return;
    }
    dialog.classList.remove('modal-sm', 'modal-md', 'modal-lg', 'modal-xl');
    if (size && size !== 'md') {
        dialog.classList.add('modal-' + size);
    }
}

/*******************************
 * Confirmation modal (inline — no AJAX)
 *
 * opts:
 *   title         (string)   — modal title
 *   body          (string)   — HTML for the body (already escaped by caller)
 *   confirmLabel  (string)   — confirm button text
 *   confirmClass  (string)   — Bootstrap btn class, default 'btn-primary'
 *   cancelLabel   (string)   — cancel button text, default 'Cancel'
 *   size          (string)   — see setModalSize: 'sm'|'md'|'lg'|'xl', default 'md'
 *   onConfirm     (function) — called after the user confirms
 *******************************/
function showConfirmModal(opts) {
    const modalEl   = document.getElementById('mainModal');
    const modalBody = document.getElementById('mainModalBody');
    if (!modalEl || !modalBody) return;

    const size         = opts.size         || 'md';
    const confirmClass = opts.confirmClass || 'btn-primary';
    const confirmLabel = opts.confirmLabel || 'Confirm';
    const cancelLabel  = opts.cancelLabel  || 'Cancel';

    modalBody.innerHTML =
        '<div class="p-4">' +
            (opts.title
                ? '<h5 class="fw-semibold mb-3">' + escapeHtml(opts.title) + '</h5>'
                : '') +
            (opts.body
                ? '<div class="mb-4">' + opts.body + '</div>'
                : '') +
            '<div class="d-flex gap-2 justify-content-end">' +
                '<button type="button" class="btn btn-sm btn-outline-secondary"' +
                        ' data-bs-dismiss="modal">' + escapeHtml(cancelLabel) + '</button>' +
                '<button type="button" class="btn btn-sm ' + escapeHtml(confirmClass) + '"' +
                        ' id="confirmModalOkBtn">' + escapeHtml(confirmLabel) + '</button>' +
            '</div>' +
        '</div>';

    setModalSize(size, modalEl.querySelector('.modal-dialog'));

    const bsModal = bootstrap.Modal.getOrCreateInstance(modalEl);
    bsModal.show();

    document.getElementById('confirmModalOkBtn').addEventListener('click', function () {
        bsModal.hide();
        if (typeof opts.onConfirm === 'function') opts.onConfirm();
    }, { once: true });
}

// Initializing Bootstrap 5 tooltips
document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
});

/*******************************
 * Index Filtering Bar
 *******************************/
function openModal(url, size = 'xl') {
    setModalSize(size);

    fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(response => response.text())
        .then(html => {
            const container = document.getElementById('mainModalBody');
            container.innerHTML = html;
            container.querySelectorAll('script:not([type="application/json"])').forEach(oldScript => {
                const newScript = document.createElement('script');
                if (oldScript.src) {
                    newScript.src = oldScript.src;
                } else {
                    // Wrap in IIFE so const/let declarations don't leak into the
                    // global scope and cause redeclaration errors on repeated opens.
                    newScript.textContent = '(function(){\n' + oldScript.textContent + '\n})();';
                }
                document.body.appendChild(newScript);
                document.body.removeChild(newScript);
            });

            initTomSelect(container);
            initChoiceFields(container);
            initCollectionForm(container);
            initTemplateElementForm(container);
            initServerForm(container);
            initSharingGroupForm(container);

            // Reuse the single instance for #mainModal — calling openModal again
            // while a modal is already open must not spawn a second Bootstrap.Modal instance
            let modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('mainModal'));
            modal.show();
        });
}

/**
 * Announce that page entity attributes may have changed so derived cards can update.
 *
 * Listeners use document.addEventListener('misp:attributes-changed').
 */
function notifyAttributesChanged() {
    document.dispatchEvent(new CustomEvent('misp:attributes-changed'));
}
window.notifyAttributesChanged = notifyAttributesChanged;

// Attribute mutations in the event view all go through #mainModal, so closing it
// is the point where derived cards can re-read the event.
(function () {
    const modalEl = document.getElementById('mainModal');
    if (!modalEl || modalEl._attrChangeBound) {
        return;
    }
    modalEl._attrChangeBound = true;
    modalEl.addEventListener('hidden.bs.modal', function () {
        // A chained open only swaps content and does not mutate data.
        if (modalEl._chaining) {
            modalEl._chaining = false;
            return;
        }
        notifyAttributesChanged();
    });
})();

// Once #mainModal is fully closed, remove any leftover backdrops and restore body scrolling.
(function () {
    const modalEl = document.getElementById('mainModal');
    if (!modalEl || modalEl._backdropReaperBound) {
        return;
    }
    modalEl._backdropReaperBound = true;
    modalEl.addEventListener('hidden.bs.modal', function () {
        window.setTimeout(function () {
            if (document.querySelector('.modal.show')) {
                return;
            }
            document.querySelectorAll('.modal-backdrop').forEach(function (b) { b.remove(); });
            document.body.classList.remove('modal-open');
            document.body.style.removeProperty('overflow');
            document.body.style.removeProperty('padding-right');
        }, 300);
    });
})();

// Hover enrichment
(function () {
    if (window._omHoverEnrichmentBound) {
        return;
    }
    window._omHoverEnrichmentBound = true;

    const SHOW_DELAY = 400;
    const HIDE_DELAY = 250;
    let showTimer = null;
    let hideTimer = null;
    let currentId = null;
    const cache = {};
    let pop = null;

    function popover() {
        if (!pop) {
            pop = document.createElement('div');
            pop.id = 'omHoverEnrichment';
            pop.className = 'shadow border rounded bg-body';
            pop.style.cssText = 'position:fixed; z-index:1090; width:min(520px,92vw); max-height:70vh; overflow:auto; display:none;';
            pop.addEventListener('mouseenter', function () { window.clearTimeout(hideTimer); });
            pop.addEventListener('mouseleave', hideSoon);
            document.body.appendChild(pop);
        }
        return pop;
    }

    function place(anchor) {
        const p = popover();
        const r = anchor.getBoundingClientRect();
        p.style.visibility = 'hidden';
        p.style.display = 'block';
        const pw = p.offsetWidth;
        const ph = p.offsetHeight;
        const left = Math.max(8, Math.min(r.left, window.innerWidth - pw - 8));
        let top = r.bottom + 6;
        if (top + ph > window.innerHeight - 8) {
            const above = r.top - 6 - ph;
            top = above > 8 ? above : Math.max(8, window.innerHeight - ph - 8);
        }
        p.style.left = left + 'px';
        p.style.top = top + 'px';
        p.style.visibility = 'visible';
    }

    function show(anchor, id) {
        currentId = id;
        const p = popover();
        if (cache[id] !== undefined) {
            p.innerHTML = cache[id];
            p.style.display = 'block';
            place(anchor);
            return;
        }
        p.innerHTML = '<div class="p-3 text-muted small d-flex align-items-center gap-2">'
                    + '<span class="spinner-border spinner-border-sm"></span></div>';
        p.style.display = 'block';
        place(anchor);
        fetch(baseurl + '/attributes/hoverEnrichment/' + encodeURIComponent(id), {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
            .then(function (r) { return r.text(); })
            .then(function (html) {
                cache[id] = html;
                if (currentId === id) { p.innerHTML = html; place(anchor); }
            })
            .catch(function () {
                if (currentId === id) {
                    p.innerHTML = '<div class="p-3 text-danger small">'
                        + '<i class="fas fa-triangle-exclamation me-1"></i>Enrichment lookup failed.</div>';
                }
            });
    }

    function hideSoon() {
        window.clearTimeout(hideTimer);
        hideTimer = window.setTimeout(function () {
            if (pop) { pop.style.display = 'none'; }
            currentId = null;
        }, HIDE_DELAY);
    }

    function hideNow() {
        window.clearTimeout(showTimer);
        window.clearTimeout(hideTimer);
        if (pop) { pop.style.display = 'none'; }
        currentId = null;
    }

    document.body.addEventListener('mouseover', function (e) {
        const el = e.target.closest && e.target.closest('.om-hover-enrichment[data-hover-trigger="hover"]');
        if (!el) { return; }
        window.clearTimeout(hideTimer);
        const id = el.getAttribute('data-hover-enrichment-id');
        if (id === currentId) { return; }
        window.clearTimeout(showTimer);
        showTimer = window.setTimeout(function () { show(el, id); }, SHOW_DELAY);
    });

    document.body.addEventListener('mouseout', function (e) {
        const el = e.target.closest && e.target.closest('.om-hover-enrichment[data-hover-trigger="hover"]');
        if (!el) { return; }
        window.clearTimeout(showTimer);
        hideSoon();
    });

    document.body.addEventListener('click', function (e) {
        const el = e.target.closest && e.target.closest('.om-hover-enrichment[data-hover-trigger="click"]');
        if (!el) { return; }
        e.preventDefault();
        const id = el.getAttribute('data-hover-enrichment-id');
        if (pop && pop.style.display === 'block' && currentId === id) { hideNow(); return; }
        show(el, id);
    });

    // Dismiss the popover on an outside click / Escape / page scroll.
    document.addEventListener('click', function (e) {
        if (!pop || pop.style.display !== 'block') { return; }
        if (pop.contains(e.target)) { return; }
        if (e.target.closest && e.target.closest('.om-hover-enrichment')) { return; }
        hideNow();
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { hideNow(); } });
    window.addEventListener('scroll', function (e) {
        if (pop && pop.style.display === 'block' && !(pop.contains(e.target))) { hideNow(); }
    }, true);
})();

// Close the currently-open #mainModal (if any) and then open `url` in it.
// Used to chain modals without stacking a second Bootstrap backdrop.
function openModalChained(url, size = 'xl') {
    const el = document.getElementById('mainModal');
    const inst = el ? bootstrap.Modal.getInstance(el) : null;
    if (inst && el.classList.contains('show')) {
        el.addEventListener('hidden.bs.modal', function handler() {
            el.removeEventListener('hidden.bs.modal', handler);
            openModal(url, size);
        });
        el._chaining = true;
        inst.hide();
    } else {
        openModal(url, size);
    }
}

// Inject HTML into #mainModalBody and (re-)run its inline scripts in IIFEs.
function renderMainModalContent(html) {
    const container = document.getElementById('mainModalBody');
    container.innerHTML = html;
    container.querySelectorAll('script:not([type="application/json"])').forEach(oldScript => {
        const newScript = document.createElement('script');
        if (oldScript.src) {
            newScript.src = oldScript.src;
        } else {
            newScript.textContent = '(function(){\n' + oldScript.textContent + '\n})();';
        }
        document.body.appendChild(newScript);
        document.body.removeChild(newScript);
    });
    if (typeof initTomSelect === 'function') {
        initTomSelect(container);
    }
    if (typeof initChoiceFields === 'function') {
        initChoiceFields(container);
    }
}

// POST `body` to `url` and render the HTML response into #mainModal, chaining
// from the currently-open modal (hide → show) so backdrops don't stack.
function openModalPostChained(url, body, size = 'xl') {
    const el = document.getElementById('mainModal');
    const inst = el ? bootstrap.Modal.getInstance(el) : null;
    const run = () => {
        setModalSize(size, el.querySelector('.modal-dialog'));
        fetch(url, { method: 'POST', body: body, headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(response => response.text())
            .then(html => {
                renderMainModalContent(html);
                bootstrap.Modal.getOrCreateInstance(el).show();
            });
    };
    if (inst && el.classList.contains('show')) {
        el.addEventListener('hidden.bs.modal', function handler() {
            el.removeEventListener('hidden.bs.modal', handler);
            run();
        });
        el._chaining = true;
        inst.hide();
    } else {
        run();
    }
}

function multiSelectItems(url, suffixe, size = 'md') {
    if (selectedItems.size === 0) {
        return;
    }
    const ids = Array.from(selectedItems.keys());
    const fullUrl = url + '/' + JSON.stringify(ids) + suffixe;
    openModal(fullUrl, size);
}

function redirectToExportResult() {
    const returnFormat = document.getElementById('EventReturnFormat')?.value;
    let idListStr = document.getElementById('PromptForm')?.dataset.idlist;

    if (!returnFormat) return;

    if (Array.isArray(idListStr)) {
        idListStr = JSON.stringify(idListStr);
    }

    window.location = baseurl + '/events/restSearchExport/' + idListStr + '/' + returnFormat;
}

function toggleAllAttributeCheckboxes(selectAllEl) {
    // Prefer the element passed directly from onclick="…(this)" so that
    // when multiple scaffolds are loaded in sibling tab-panes (e.g.
    // Attributes and Reports both have a select-all checkbox), we always
    // operate on the one the user actually clicked rather than the first
    // matching getElementById result.
    const selectAll = selectAllEl || document.getElementById('select_all');
    if (!selectAll) return;
    const checked = selectAll.checked;
    // Scope to the enclosing tab-pane so checkboxes in sibling tabs are
    // not accidentally included. Fall back to document on standalone pages.
    const scope = selectAll.closest('.tab-pane') || document;
    const checkboxes = scope.querySelectorAll('.item-checkbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = checked;
        checkbox.dispatchEvent(new Event('change', { bubbles: true }));
    });
}

function isMobile() {
    return window.innerWidth < 1000;
}

function animateIndexView(el) {
    if (!el) return;
    el.classList.remove('idx-view-anim');
    void el.offsetWidth;
    el.classList.add('idx-view-anim');
}

/**
 * Switch an index between its table and card views.
 *
 * `scope` exists because an index can be rendered inside an ajax tab, where
 * several #tableView/#cardView pairs share the document and getElementById
 * would always answer with the first one.
 */
function setView(view, save = true, scope = document) {
    const tableView = scope.querySelector('#tableView');
    const cardView  = scope.querySelector('#cardView');
    const viewList  = scope.querySelector('#viewList');
    const viewCard  = scope.querySelector('#viewCard');
    // Only a deliberate toggle launches the animation
    if (save) animateIndexView(view === 'card' ? cardView : tableView);
    if (view === 'card') {
        tableView?.classList.add('d-none');
        cardView?.classList.remove('d-none');
        viewList?.classList.remove('active');
        viewCard?.classList.add('active');
    } else {
        cardView?.classList.add('d-none');
        tableView?.classList.remove('d-none');
        viewCard?.classList.remove('active');
        viewList?.classList.add('active');
    }

    if (save) localStorage.setItem('indexViewMode', view);
}

function updateMultiSelectToolbar() {
    // When multiple tabs each contain a mass-action toolbar (e.g. Attributes
    // and Reports), getElementById would return the first one in DOM order
    // regardless of which tab is visible.  Scope the lookup to the active
    // tab-pane so we always update the currently visible toolbar.
    // On standalone index pages (no tab-pane) fall back to document.
    const scope = document.querySelector('.tab-pane.active') || document;
    const toolbar        = scope.querySelector('#multiSelectToolbar');
    const selectedCount  = scope.querySelector('#selectedCount');
    const deleteButton     = scope.querySelector('#multi-delete-button');
    const softDeleteButton = scope.querySelector('#multi-soft-delete-button');
    const editButton     = scope.querySelector('#mass-edit-button');
    const tagButton      = scope.querySelector('#mass-tag-button');
    const localtagButton = scope.querySelector('#mass-local-tag-button');
    const clusterButton  = scope.querySelector('#mass-cluster-button');
    const localclusterButton = scope.querySelector('#mass-local-cluster-button');
    const objectButton   = scope.querySelector('#mass-object-button');
    const relationshipButton = scope.querySelector('#mass-relationship-button');
    const sightingButton = scope.querySelector('#mass-sighting-button');
    const fetchButton    = scope.querySelector('#mass-fetch-button');
    const enableButton   = scope.querySelector('#mass-enable-button');
    const disableButton  = scope.querySelector('#mass-disable-button');
    const requireButton   = scope.querySelector('#mass-require-button');
    const optionalButton  = scope.querySelector('#mass-optional-button');
    const highlightButton   = scope.querySelector('#mass-highlight-button');
    const removehighlightButton  = scope.querySelector('#mass-removehighlight-button');

    const count          = selectedItems.size;

    if (count === 0) {
        toolbar?.classList.add('d-none');
        return;
    }

    toolbar?.classList.remove('d-none');
    if (selectedCount) selectedCount.textContent = count;

    let canDeleteAll = true;
    let allEnabled = true;
    let allDisabled = true;
    let allRequired = true;
    let allOptional = true;
    let allHighlighted = true;
    let allRemovehighlighted = true;

    selectedItems.forEach(item => {
        if (!item.canDelete) canDeleteAll = false;
        if (item.enable === '1') allDisabled = false;
        if (item.enable === '0') allEnabled = false;
        if (item.require === '1') allOptional = false;
        if (item.require === '0') allRequired = false;
        if (item.highlight === '1') allRemovehighlighted = false;
        if (item.highlight === '0') allHighlighted = false;
    });

    const isHidden = !canDeleteAll;

    deleteButton?.classList.toggle('d-none', isHidden);
    softDeleteButton?.classList.toggle('d-none', isHidden);
    editButton?.classList.toggle('d-none', isHidden);
    tagButton?.classList.toggle('d-none', isHidden);
    localtagButton?.classList.toggle('d-none', isHidden);
    clusterButton?.classList.toggle('d-none', isHidden);
    localclusterButton?.classList.toggle('d-none', isHidden);
    objectButton?.classList.toggle('d-none', isHidden);
    relationshipButton?.classList.toggle('d-none', isHidden);
    sightingButton?.classList.toggle('d-none', isHidden);

    fetchButton?.classList.toggle('d-none', !allEnabled);

    if (enableButton && disableButton) {
        if (allDisabled) {
            enableButton.classList.remove('d-none');
            disableButton.classList.add('d-none');
        } else if (allEnabled) {
            enableButton.classList.add('d-none');
            disableButton.classList.remove('d-none');
        } else {
            enableButton.classList.remove('d-none');
            disableButton.classList.remove('d-none');
        }
    }

    if (requireButton && optionalButton) {
        if (allOptional) {
            requireButton.classList.remove('d-none');
            optionalButton.classList.add('d-none');
        } else if (allRequired) {
            requireButton.classList.add('d-none');
            optionalButton.classList.remove('d-none');
        } else {
            requireButton.classList.remove('d-none');
            optionalButton.classList.remove('d-none');
        }
    }

    if (highlightButton && removehighlightButton) {
        if (allRemovehighlighted) {
            highlightButton.classList.remove('d-none');
            removehighlightButton.classList.add('d-none');
        } else if (allHighlighted) {
            highlightButton.classList.add('d-none');
            removehighlightButton.classList.remove('d-none');
        } else {
            highlightButton.classList.remove('d-none');
            removehighlightButton.classList.remove('d-none');
        }
    }
}

function buildFilterUrl() {
    const base = baseIndexUrl.replace(/\/search.*/, '');
    let filters = {};

    const searchMatch = window.location.pathname.match(/\/search(.+)/);
    if (searchMatch) {
        const parts = searchMatch[1].split('/search');
        parts.forEach(part => {
            const [key, value] = part.split(':');
            if (key && value) filters[key] = decodeURIComponent(value);
        });
    }

    const filterField = document.getElementById('filterField');
    const quickValue = filterField ? filterField.value.trim() : '';

    if (filterBarConfig.mode === 'legacy' || filterBarConfig.mode === 'event') {
        delete filters[filterBarConfig.searchField];
        if (filterBarConfig.idField) delete filters[filterBarConfig.idField];

        if (quickValue !== '') {
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            const numberRegex = /^[0-9]+$/;

            if (filterBarConfig.idField && (uuidRegex.test(quickValue) || numberRegex.test(quickValue))) {
                filters[filterBarConfig.idField] = encodeURIComponent(quickValue);
            } else {
                filters[filterBarConfig.searchField] = encodeURIComponent(quickValue);
            }
        }
    } else {
        delete filters['quickFilter'];
        if (quickValue !== '') {
            filters['quickFilter'] = encodeURIComponent(quickValue);
        }
    }

    document.querySelectorAll('.topbar-filter').forEach(el => {
        const name  = el.getAttribute('name');
        const value = el.value;
        if (!name) return;
        if (value !== '') filters[name] = encodeURIComponent(value);
        else delete filters[name];
    });

    let newUrl = base;
    if (filterBarConfig.mode === 'event') {
        Object.keys(filters).forEach(key => {
            newUrl += '/search' + key + ':' + filters[key];
        });
    } else {
        Object.keys(filters).forEach(key => {
            newUrl += '/' + key + ':' + filters[key];
        });
    }

    return newUrl;
}

// Safe global fallback — filter_bar.ctp re-declares this per scaffold,
// but mispOvermind.js references it unconditionally in its change listener.
if (typeof selectedItems === 'undefined') {
    var selectedItems = new Map();
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('viewList')?.addEventListener('click', () => setView('table'));
    document.getElementById('viewCard')?.addEventListener('click', () => setView('card'));

    const savedView = localStorage.getItem('indexViewMode');
    setView(isMobile() ? 'card' : (savedView || 'table'), false);

    document.getElementById('quickFilterButton')?.addEventListener('click', () => {
        window.location.href = buildFilterUrl();
    });

    document.getElementById('quickFilterField')?.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') window.location.href = buildFilterUrl();
    });

    // [data-manual] filters (free-text value_match inputs) are applied by their
    // own button/Enter handler in filter_bar.ctp, never on change.
    document.querySelectorAll('.topbar-filter:not([data-manual])').forEach(el => {
        el.addEventListener('change', () => {
            window.location.href = buildFilterUrl();
        });
    });

    document.addEventListener('change', function(e) {
        if (!e.target.classList.contains('item-checkbox')) return;

        const checkbox = e.target;
        const id       = checkbox.dataset.itemId;
        const canDelete = checkbox.dataset.canDelete == "1";
        const publish    = checkbox.dataset.publish;
        const enable    = checkbox.dataset.enable;
        const require    = checkbox.dataset.require;
        const highlight    = checkbox.dataset.highlight;

        if (checkbox.checked) {
            selectedItems.set(id, { id, canDelete, publish, enable, require, highlight});
        } else {
            selectedItems.delete(id);
        }

        updateMultiSelectToolbar();
    });
});

/*******************************
 * Tags
 *******************************/
function toggleTags(badge) {
    const container = badge.closest('.tag-container');
    const hiddenTags = container.querySelectorAll('.extra-tag');

    if (!hiddenTags.length) return;

    const isHidden = hiddenTags[0].classList.contains('d-none');
    hiddenTags.forEach(g => g.classList.toggle('d-none'));

    badge.textContent = isHidden ? '−' : '+' + hiddenTags.length;
}

document.addEventListener('DOMContentLoaded', function() {
    document.body.addEventListener('click', async function(e) {
        const starIcon = e.target.closest('.tag-star');

        if (starIcon) {
            e.preventDefault();
            e.stopPropagation();

            const tagId = starIcon.getAttribute('data-id');
            const wasFavourite = starIcon.classList.contains('fas');
            starIcon.classList.toggle('fas');
            starIcon.classList.toggle('far');

            const formData = new URLSearchParams();
            formData.append('data[FavouriteTag][data]', tagId);

            try {
                const url = (typeof baseurl !== 'undefined' ? baseurl : '') + '/favourite_tags/toggle';
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'application/json'
                    },
                    body: formData
                });

                const result = await response.json();

                if (!result.saved) {
                    revertStar(starIcon, wasFavourite);
                    console.error('Erreur lors du changement de favori:', result.fails);
                }
            } catch (error) {
                revertStar(starIcon, wasFavourite);
                console.error('Erreur réseau lors de la mise à jour du favori:', error);
            }
        }
    });

    function revertStar(element, shouldBeFavourite) {
        if (shouldBeFavourite) {
            element.classList.add('fas text-warning');
            element.classList.remove('far text-muted');
        } else {
            element.classList.add('far text-muted');
            element.classList.remove('fas text-warning');
        }
    }
});


/*******************************
 * Servers
 *******************************/


function testSyncRule(id, method) {
    function esc(input) {
        return String(input === null || input === undefined ? '' : input)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    var resultContainer = document.getElementById("sync_rule_" + method + "_test_" + id);
    if (!resultContainer) return;

    resultContainer.innerHTML = '<span class="text-muted">' +
        '<i class="fas fa-spinner fa-spin me-1"></i>Running test...' +
        '</span>';

    fetch(baseurl + '/servers/testSyncRules/' + id + '/' + method)
        .then(response => response.json().catch(() => null))
        .then(function(response) {
            resultContainer.innerHTML = '';

            if (typeof response !== 'object' || response === null) {
                resultContainer.innerHTML =
                    '<span class="text-danger fw-semibold">Internal error</span>';
            } else if ("error" in response) {
                resultContainer.innerHTML =
                    '<span class="text-danger fw-semibold">Error: #' +
                    esc(response.error) + '</span>';
            } else {
                var resultTextFiltered = response.without_rules - response.with_rules;
                if (resultTextFiltered !== 0) {
                    resultTextFiltered += ' (' + (((response.without_rules - response.with_rules) / response.without_rules) * 100).toFixed(1) + '%)';
                }

                var resultTextSync = response.with_rules;
                if (resultTextSync !== 0) {
                    resultTextSync += ' (' + ((response.with_rules / response.without_rules) * 100).toFixed(1) + '%)';
                }

                resultContainer.innerHTML =
                    '<div class="border rounded p-2 bg-light">' +
                    '<div class="d-flex justify-content-between gap-2">' +
                    '<span class="text-muted">Dropped Events :</span>' +
                    '<span class="fw-semibold text-danger text-end">' +
                    esc(resultTextFiltered) + '</span></div>' +
                    '<div class="d-flex justify-content-between gap-2">' +
                    '<span class="text-muted">Events to be Synced :</span>' +
                    '<span class="fw-semibold text-success text-end">' +
                    esc(resultTextSync) + '</span></div>' +
                    '</div>';
            }
        })
        .catch(function() {
            resultContainer.innerHTML =
                '<span class="text-danger fw-semibold">Internal error</span>';
        });
}


/*
 * The two remote probes below are shared by the servers table view and the
 * servers card view. The table renders `connection_test_<id>` /
 * `sync_user_test_<id>` containers, the card view draws its own panels, and
 * both views live in the DOM at once — so a caller can hand over its own
 * container rather than fight over duplicate ids.
 */
function resolveServerTestContainer(target, fallbackId) {
    if (target && target.nodeType === 1) return target;
    if (typeof target === 'string' && target) return document.getElementById(target);
    return document.getElementById(fallbackId);
}

// Both probes announce their outcome so a view can dress itself around the
// result (the card view flips its header badge and tint on this).
function announceServerTest(name, detail) {
    document.dispatchEvent(new CustomEvent(name, { detail: detail }));
}

function testConnection(id, target) {
    function esc(input) {
        return String(input === null || input === undefined ? '' : input)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    var container = resolveServerTestContainer(target, "connection_test_" + id);
    if (!container) return Promise.resolve();
    var resultContainer = container.querySelector('.server-action-result') || container;

    resultContainer.innerHTML = '<span class="text-muted">' +
        '<i class="fas fa-spinner fa-spin me-1"></i>Running test...' +
        '</span>';
    announceServerTest('misp:server-connection', { id: id, state: 'running' });

    return fetch(baseurl + '/servers/testConnection/' + id)
        .then(response => response.json())
        .then(function(result) {

            function line(name, value, valid) {
                var badgeClass = 'text-secondary';
                if (valid === true || valid === 'green') {
                    badgeClass = 'text-end text-success';
                } else if (valid === false || valid === 'red') {
                    badgeClass = 'text-end text-danger';
                } else if (valid === 'orange') {
                    badgeClass = 'text-end text-warning';
                }

                var valueText = esc(value || '-');
                return '<div class="d-flex justify-content-between gap-2">' +
                    '<span class="text-muted">' + name + '</span>' +
                    '<span class="fw-semibold ' + badgeClass + '">' +
                    valueText + '</span></div>';
            }

            var html = '';

            if (result.client_certificate) {
                var cert = result.client_certificate;
                html += '<div class="fw-semibold mb-1">Client certificate</div>';
                html += '<div class="border rounded p-2 mb-2 bg-light">';

                if (cert.error) {
                    html += '<div class="text-danger fw-semibold">Error: ' +
                        esc(cert.error) + '</div>';
                } else {
                    html += line("Subject", cert.subject);
                    html += line("Issuer", cert.issuer);
                    html += line("Serial number", cert.serial_number);
                    html += line("Valid from", cert.valid_from, cert.valid_from_ok);
                    html += line("Valid to", cert.valid_to, cert.valid_to_ok);
                    html += line(
                        "Public key",
                        cert.public_key_type + ' (' + cert.public_key_size + ' bits)',
                        cert.public_key_size_ok
                    );
                }
                html += '</div>';
            }

            switch (result.status) {
                case 1:
                    var status_message = "OK";
                    var compatibility = "Compatible";
                    var compatibility_colour = "green";
                    var colours = {local: 'green', remote: 'green', status: 'green'};
                    var issue_colour = "red";

                    if (result.mismatch == "hotfix") issue_colour = "orange";

                    if (result.newer == "local") {
                        colours.remote = issue_colour;

                        if (result.mismatch == "minor") {
                            compatibility = "Pull only";
                            compatibility_colour = "orange";
                        } else if (result.mismatch == "major") {
                            compatibility = "Incompatible";
                            compatibility_colour = "red";
                        } else if (result.mismatch == "minor_compatible") {
                            compatibility_colour = "green";
                        }
                    } else if (result.newer == "remote") {
                        colours.local = issue_colour;

                        if (result.mismatch != "hotfix") {
                            compatibility = "Incompatible";
                            compatibility_colour = "red";
                        }
                    } else if (result.mismatch == "proposal") {
                        compatibility_colour = "orange";
                        compatibility = "Proposal pull disabled (remote version < v2.4.111)";
                    }

                    if (result.mismatch !== false && result.mismatch != "proposal") {
                        if (result.newer == "remote") {
                            status_message = "Local instance outdated, update!";
                        } else if (result.newer == "local") {
                            if (result.mismatch == "minor_compatible") {
                                status_message = "Remote on 2.4, moving to 2.5 is recommended.";
                            } else {
                                status_message = "Remote outdated, notify admin!";
                            }
                        }
                        colours.status = issue_colour;
                    }

                    var post_result = '';
                    if (result.post !== false) {
                        var post_colour = "red";

                        if (result.post == 1) {
                            post_colour = "green";
                            post_result = "Received sent package";
                        } else if (result.post == 8) {
                            post_result = "Could not POST message";
                        } else if (result.post == 9) {
                            post_result = "Invalid body";
                        } else if (result.post == 10) {
                            post_result = "Invalid headers";
                        } else {
                            post_colour = "orange";
                            post_result = "Remote too old for this test";
                        }
                    }

                    html += '<div class="border rounded p-2 bg-light">';
                    html += line('Local version', result.local_version, colours.local);
                    html += line('Remote version', result.version, colours.remote);
                    html += line('Status', status_message, colours.status);
                    html += line('Compatibility', compatibility, compatibility_colour);
                    html += line('POST test', post_result, post_colour);
                    html += '</div>';
                    break;

                case 2:
                    html += '<div class="text-danger fw-semibold">Server unreachable</div>';
                    break;
                case 3:
                    html += '<div class="text-danger fw-semibold">Unexpected error</div>';
                    break;
                case 4:
                    html += '<div class="text-danger fw-semibold">Authentication failed</div>';
                    break;
                case 5:
                    html += '<div class="text-danger fw-semibold">Password change required</div>';
                    break;
                case 6:
                    html += '<div class="text-danger fw-semibold">Terms not accepted</div>';
                    break;
                case 7:
                    html += '<div class="text-warning fw-semibold">Remote user not a sync user</div>';
                    break;
                case 8:
                    html += '<div class="text-warning fw-semibold">Remote user not a sync user (sightings only)</div>';
                    break;
            }

            resultContainer.innerHTML = html;
            announceServerTest('misp:server-connection', {
                id: id,
                state: result.status === 1 ? 'ok' : 'down',
                status: result.status
            });
        })
        .catch(function() {
            resultContainer.innerHTML = '<span class="text-danger fw-semibold">Internal error</span>';
            announceServerTest('misp:server-connection', { id: id, state: 'down' });
        });
}


function getRemoteSyncUser(id, target) {
    function esc(input) {
        return String(input === null || input === undefined ? '' : input)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    var container = resolveServerTestContainer(target, "sync_user_test_" + id);
    if (!container) return Promise.resolve();
    var resultContainer = container.querySelector('.server-action-result') || container;
    announceServerTest('misp:server-sync-user', { id: id, state: 'running' });

    return fetch(baseurl + '/servers/getRemoteUser/' + id)
        .then(function(response) {
            resultContainer.innerHTML = '<span class="text-muted">' +
                '<i class="fas fa-spinner fa-spin me-1"></i>Running test...' +
                '</span>';
            return response.json().catch(() => null);
        })
        .then(function(response) {
            resultContainer.innerHTML = '';

            if (typeof response !== 'object' || response === null) {
                resultContainer.innerHTML =
                    '<span class="text-danger fw-semibold">Internal error</span>';
                announceServerTest('misp:server-sync-user', { id: id, state: 'down' });
            } else if ("error" in response) {
                resultContainer.innerHTML =
                    '<div class="text-danger fw-semibold">Error: #' +
                    esc(response.error) + '</div>';
                announceServerTest('misp:server-sync-user', { id: id, state: 'down' });
            } else {
                announceServerTest('misp:server-sync-user', { id: id, state: 'ok' });
                var wrapper = document.createElement('div');
                wrapper.className = 'border rounded p-2 bg-light';
                Object.keys(response).forEach(function(key) {
                    var value = response[key];
                    var row = document.createElement('div');
                    row.className = 'd-flex justify-content-between gap-2';
                    row.innerHTML = '<span class="text-muted">' + esc(key) + '</span>' +
                        '<span class="fw-semibold">' + esc(value) + '</span>';
                    wrapper.appendChild(row);
                });
                resultContainer.appendChild(wrapper);
            }
        })
        .catch(function() {
            resultContainer.innerHTML =
                '<span class="text-danger fw-semibold">Internal error</span>';
            announceServerTest('misp:server-sync-user', { id: id, state: 'down' });
        });
}

/*******************************
 * Other
 *******************************/
async function getPopup(id, context, target, admin, popupType) {
    const grayOut = document.querySelector("#gray_out");
    const loadingIcons = document.querySelectorAll(".loading");
    if (!popupType) popupType = '#popover_form';
    const popupElement = document.querySelector(popupType);

    if (grayOut) {
        grayOut.style.display = "block";
        grayOut.style.opacity = "1";
    }

    let url = baseurl;
    if (admin) url += "/admin";
    if (context) url += "/" + context;
    if (target) url += "/" + target;
    if (id) url += "/" + id;

    loadingIcons.forEach(el => el.style.display = "block");

    try {
        const response = await fetch(url, {
            method: 'GET',
            cache: 'no-cache'
        });

        if (!response.ok) throw response;

        const data = await response.text();
        loadingIcons.forEach(el => el.style.display = "none");
        if (popupElement) {
            popupElement.innerHTML = data;
            openPopup(popupType, false);
        }
    } catch (error) {
        loadingIcons.forEach(el => el.style.display = "none");
        if (grayOut) grayOut.style.display = "none";
        if (typeof xhrFailCallback === "function") {
            xhrFailCallback(error);
        }
    }
}

function publishPopup(id, type, scope) {
    scope = scope === undefined ? 'events' : scope;
    let action = "alert";

    if (type === "publish") action = "publish";
    else if (type === "unpublish") action = "unpublish";
    else if (type === "sighting") action = "publishSightings";

    fetch(`${baseurl}/${scope}/${action}/${id}`)
        .then(response => {
            if (!response.ok) throw response;
            return response.json();
        })
        .then(data => openConfirmation(data))
        .catch(error => {
            if (typeof xhrFailCallback === 'function') xhrFailCallback(error);
        });
}

function openConfirmation(data) {
    const box = document.getElementById("confirmation_box");
    if (box) {
        box.innerHTML = data;
        openPopup(box);
    }
}

function openPopup(id, adjust_layout = true, callback) {
    const el = (typeof id === 'string') ? document.querySelector(id) : id;
    const grayOut = document.getElementById("gray_out");

    if (!el) return;

    if (adjust_layout) {
        el.style.top = '';
        el.style.height = '';
        el.classList.remove('vertical-scroll');

        const windowHeight = window.innerHeight;
        const popupHeight = el.offsetHeight;

        if (windowHeight < popupHeight) {
            el.style.top = "50px";
            el.style.height = (windowHeight - 50) + "px";
            el.classList.add('vertical-scroll');
        } else {
            let topOffset;
            if (windowHeight > (300 + popupHeight)) {
                topOffset = ((windowHeight - popupHeight) / 2) - 125;
            } else {
                topOffset = (windowHeight - popupHeight) / 2;
            }
            el.style.top = topOffset + "px";
        }
    }

    if (grayOut) {
        grayOut.style.display = 'block';
        grayOut.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 400 });
    }

    el.style.display = 'block';
    const animation = el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 400 });

    animation.onfinish = () => {
        if (typeof callback === 'function') {
            callback();
        }
    };
}

function cancelPrompt(isolated) {
    const grayOut = document.getElementById('gray_out');
    if (grayOut && isolated === undefined) {
        const fade = grayOut.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 300, fill: 'forwards' });
        fade.onfinish = () => { grayOut.style.display = 'none'; };
    }
    ['popover_form', 'confirmation_box'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        const fade = el.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 300, fill: 'forwards' });
        fade.onfinish = () => {
            el.style.display = 'none';
            if (id === 'confirmation_box') el.innerHTML = '';
        };
    });
}

// No-arg wrapper so the index-page top-bar action and the side menu
// can both trigger the same popover without inlining getPopup args.
function openEventTemplateLibraryUpdatePopup() {
    getPopup('', 'event_templates', 'update');
}

async function submitEventTemplatesLibraryUpdate() {
    const loadingIcons = document.querySelectorAll('.loading');
    loadingIcons.forEach(el => el.style.display = 'block');
    try {
        const response = await fetch(`${baseurl}/event_templates/update`, {
            method: 'POST',
            headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': (window.csrfToken || '')},
            cache: 'no-cache',
        });
        if (!response.ok) throw response;
        const summary = await response.json();
        cancelPrompt();
        const counts = {
            installed: (summary.installed || []).length,
            updated: (summary.updated || []).length,
            skipped_current: (summary.skipped_current || []).length,
            skipped_forked: (summary.skipped_forked || []).length,
            failed: (summary.failed || []).length,
        };
        const msg = `Library update — installed ${counts.installed}, updated ${counts.updated}, `
            + `skipped ${counts.skipped_current + counts.skipped_forked}, failed ${counts.failed}.`;
        if (typeof showMessage === 'function') {
            showMessage(counts.failed > 0 ? 'fail' : 'success', msg);
        }
        setTimeout(() => window.location.reload(), 800);
    } catch (error) {
        loadingIcons.forEach(el => el.style.display = 'none');
        if (typeof xhrFailCallback === 'function') xhrFailCallback(error);
    } finally {
        loadingIcons.forEach(el => el.style.display = 'none');
    }
}

/**
 * Turn every `.tom-select` in `container` into a TomSelect. Safe to call more
 * than once on the same scope — which happens routinely (a modal body, an
 * ajax fragment, and initChoiceCards' sharing-group reveal all call it).
 *
 * The selector is qualified by tag on purpose: TomSelect copies the source
 * element's class list onto the `.ts-wrapper` div it builds, so a bare
 * `.tom-select` query matches twice per control after the first pass — and the
 * wrapper carries no `.tomselect` back-reference, so it slips past the guard
 * below and `new TomSelect(div)` throws on `e.value.trim()`.
 */
function initTomSelect(container) {
    container.querySelectorAll('select.tom-select').forEach(el => {
        if (el.tomselect) return;

        const config = {
            create: false,
            persist: false,
            placeholder: el.dataset.placeholder || 'Select options...'
        };

        if (el.hasAttribute('multiple')) {
            config.plugins = ['remove_button'];
        }

        new TomSelect(el, config);
    });
}

function initCollectionForm(container) {
    const distributionSelect = container.querySelector('#distribution-select');
    const sgContainer = container.querySelector('#sg-container');

    if (!distributionSelect || !sgContainer) return;

    function toggleSharingGroup() {
        if (parseInt(distributionSelect.value) === 4) {
            sgContainer.classList.remove('d-none');
        } else {
            sgContainer.classList.add('d-none');
        }
    }

    toggleSharingGroup();
    distributionSelect.addEventListener('change', toggleSharingGroup);
}

function toggleSecret(fieldId, btn) {
    const input = document.getElementById(fieldId);
    const icon = btn.querySelector('i');

    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.replace('fa-eye', 'fa-eye-slash');
        btn.classList.add('text-primary');
    } else {
        input.type = 'password';
        icon.classList.replace('fa-eye-slash', 'fa-eye');
        btn.classList.remove('text-primary');
    }
}


/*******************************
 * Template Element Add
 *******************************/
function initTemplateElementForm(container) {
    const form = container.querySelector('#templateElementAddForm');
    if (!form) return;

    const configDataNode = container.querySelector('#templateElementFormConfig');
    if (!configDataNode) return;

    let configData = {};
    try {
        configData = JSON.parse(configDataNode.textContent);
    } catch (e) {
        console.error("Erreur de parsing JSON pour le template element form", e);
        return;
    }

    const typeSelectorEl = container.querySelector('#ElementTypeSelector');
    const categoryEl = container.querySelector('#DynamicCategory');
    const typeEl = container.querySelector('#DynamicType');

    const typeSelectorTs = typeSelectorEl ? typeSelectorEl.tomselect : null;
    const categoryTs = categoryEl ? categoryEl.tomselect : null;
    const typeTs = typeEl ? typeEl.tomselect : null;

    const dynamicFormFields = container.querySelector('#dynamicFormFields');
    const checkComplex = container.querySelector('#checkComplex');

    function toggleGroups(selectedType) {
        if (!selectedType) {
            dynamicFormFields.classList.add('d-none');
            return;
        }

        dynamicFormFields.classList.remove('d-none');
        container.querySelectorAll('.element-group-attr, .element-group-file').forEach(el => el.classList.add('d-none'));

        if (selectedType === 'attribute') {
            container.querySelectorAll('.element-group-attr').forEach(el => el.classList.remove('d-none'));
            populateCategoryDropdown('attribute');
        } else if (selectedType === 'file') {
            container.querySelectorAll('.element-group-file').forEach(el => el.classList.remove('d-none'));
            populateCategoryDropdown('file');
        }
    }

    function populateCategoryDropdown(mode) {
        if (!categoryTs) return;

        categoryTs.clear(true);
        categoryTs.clearOptions();
        categoryTs.addOption({value: '', text: 'Select Category...'});

        const options = (mode === 'attribute') ? configData.categoriesAttr : configData.categoriesFile;

        Object.keys(options).forEach(key => {
            categoryTs.addOption({value: key, text: options[key]});
        });
        categoryTs.refreshOptions(false);

        if (configData.preSelectedCategory) {
            categoryTs.setValue(configData.preSelectedCategory, true);
            if (mode === 'attribute') populateTypeDropdown();
        }
    }

    function populateTypeDropdown() {
        if (!typeTs || !categoryTs) return;

        const category = categoryTs.getValue();
        typeTs.clear(true);
        typeTs.clearOptions();
        typeTs.addOption({value: '', text: 'Select Type...'});

        if (!category) return;

        const isComplex = checkComplex && checkComplex.checked;
        let typesList = [];

        if (isComplex && configData.typeGroupCategoryMapping[category]) {
            typesList = configData.typeGroupCategoryMapping[category];
        } else if (!isComplex && configData.categoryTypesAttr[category]) {
            typesList = configData.categoryTypesAttr[category];
        }

        typesList.forEach(val => {
            typeTs.addOption({value: val, text: val});
        });

        typeTs.refreshOptions(false);

        if (configData.preSelectedType) {
            typeTs.setValue(configData.preSelectedType, true);
        }
    }

    if (typeSelectorTs) {
        typeSelectorTs.on('change', toggleGroups);
    }

    if (categoryTs) {
        categoryTs.on('change', () => {
            const elType = typeSelectorTs ? typeSelectorTs.getValue() : null;
            if (elType === 'attribute') {
                populateTypeDropdown();
            }
        });
    }

    if (checkComplex) {
        checkComplex.addEventListener('change', populateTypeDropdown);
    }

    if (typeSelectorTs) {
        const initialType = typeSelectorTs.getValue();
        if (initialType) toggleGroups(initialType);
    }
}


/**
 * Displays a success or error message
 */
function showMessage(success, message, fullError) {
    let duration = 1000 + (message.length * 40);
    const contentId = `ajax_${success}`;
    const containerId = `ajax_${success}_container`;

    const contentElem = document.getElementById(contentId);
    const containerElem = document.getElementById(containerId);

    if (!contentElem || !containerElem) return;

    if (message.indexOf("$flashErrorMessage") >= 0) {
        const flashMessageLink = `<a href="#" class="bold" data-content="${escapeHtml(fullError)}" data-html="true" onclick="event.preventDefault(); bootstrap.Popover.getOrCreateInstance(this).show();">here</a>`;
        message = message.replace("$flashErrorMessage", flashMessageLink);
        duration = 5000;
    }

    contentElem.innerHTML = message;
    containerElem.style.display = 'block';

    const fadeIn = containerElem.animate([{ opacity: 0 }, { opacity: 1 }], {
        duration: 600,
        fill: 'forwards'
    });

    fadeIn.onfinish = () => {
        setTimeout(() => {
            const fadeOut = containerElem.animate([{ opacity: 1 }, { opacity: 0 }], {
                duration: 600,
                fill: 'forwards'
            });

            fadeOut.onfinish = () => {
                containerElem.style.display = 'none';
            };
        }, duration);
    };
}

function escapeHtml(unsafe) {
    if (typeof unsafe === "boolean" || typeof unsafe === "number") {
        return unsafe;
    }
    if (!unsafe) return "";

    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };

    return unsafe.replace(/[&<>"']/g, (m) => map[m]);
}

function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)csrfToken=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : '';
}

/*******************************
 * Proposals (shadow attributes)
 *
 * Shared by the attribute and object event-view indexes. Accept is a direct
 * XHR (no confirmation); discard goes through a confirmation modal. Both toast
 * and refresh whichever proposal-bearing tab(s) are loaded — no page reload.
 *
 *******************************/
function reloadProposalTabs() {
    if (window.mispView.attrs && typeof window.mispView.attrs.loadFn === 'function') {
        window.mispView.attrs.loadFn(window.mispView.attrs.buildFn());
    }
    if (window.mispView.objects && typeof window.mispView.objects.loadFn === 'function') {
        window.mispView.objects.loadFn(window.mispView.objects.buildFn());
    }
}

function acceptProposal(id) {
    fetch(baseurl + '/shadow_attributes/accept/' + id, {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'Accept':           'application/json',
            'X-CSRF-Token':     getCsrfToken()
        }
    })
        .then(function (r) { return r.json().catch(function () { return {}; }); })
        .then(function (resp) {
            if (resp && resp.saved) {
                showToast(resp.success || 'Proposal accepted.', 'success');
                reloadProposalTabs();
            } else {
                showToast((resp && resp.errors) ? resp.errors : 'Could not accept the proposal.', 'danger');
            }
        })
        .catch(function () { showToast('Could not accept the proposal.', 'danger'); });
}

function copyToClipboard(btn, text) {
    const originalHtml = btn.innerHTML;

    const proceedCopy = () => {
        btn.innerHTML = '<i class="fas fa-check text-primary"></i>';

        const tooltip = bootstrap.Tooltip.getInstance(btn);
        if (tooltip) {
            btn.setAttribute('data-bs-original-title', 'Copied!');
            tooltip.show();
        }

        setTimeout(() => {
            btn.innerHTML = originalHtml;
            if (tooltip) {
                btn.setAttribute('data-bs-original-title', 'Copy to clipboard');
                tooltip.hide();
            }
        }, 2000);
    };

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(proceedCopy);
    } else {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        try {
            document.execCommand("copy");
            proceedCopy();
        } catch (err) {
            console.error('Fallback copy failed', err);
        }
        document.body.removeChild(textarea);
    }
}

/**
 * Copy an arbitrary string to the clipboard and show a discreet toast.
 * This helper is what index row "copy" actions use.
 */
function copyValueToClipboard(text, message) {
    if (text === undefined || text === null || text === '') {
        showToast('Nothing to copy', 'warning');
        return;
    }

    const done = () => showToast(message || 'Copied to clipboard');

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done).catch((err) => {
            console.error('Clipboard copy failed', err);
        });
    } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        try {
            document.execCommand('copy');
            done();
        } catch (err) {
            console.error('Fallback copy failed', err);
        }
        document.body.removeChild(textarea);
    }
}

function toggleFormats(button, containerId) {
    const container = document.getElementById(containerId);
    const extraFormats = container.querySelectorAll('.extra-format');
    const isExpanding = extraFormats[0].classList.contains('d-none');

    extraFormats.forEach(el => {
        if (isExpanding) {
            el.classList.remove('d-none');
            el.classList.add('animate__animated', 'animate__fadeIn');
        } else {
            el.classList.add('d-none');
        }
    });

    if (isExpanding) {
        button.innerHTML = '<i class="fas fa-minus small me-1"></i>';
        button.classList.replace('bg-dark', 'bg-primary');
        button.classList.replace('text-primary', 'text-dark');
    } else {
        button.innerHTML = '<i class="fas fa-plus small me-1"></i>' + extraFormats.length;
        button.classList.replace('bg-primary', 'bg-dark');
        button.classList.replace('text-dark', 'text-primary');
    }
}


/*******************************
 * Server Add/Edit
 *******************************/

function initServerForm(container) {
    const form = container.querySelector('#ServerEditForm') || container.querySelector('#ServerAddForm');
    if (!form) return;

    /**********************************
     * Organisation type logic
     **********************************/
    const orgType = container.querySelector('[name="data[Server][organisation_type]"], #ServerOrganisationType');

    const externalContainer = container.querySelector('#ServerExternalContainer');
    const localContainer    = container.querySelector('#ServerLocalContainer');
    const nameContainer     = container.querySelector('#ServerExternalNameContainer');
    const uuidContainer     = container.querySelector('#ServerExternalUuidContainer');

    function hideAllOrgFields() {
        if (externalContainer) externalContainer.style.display = 'none';
        if (localContainer)    localContainer.style.display = 'none';
        if (nameContainer)     nameContainer.style.display = 'none';
        if (uuidContainer)     uuidContainer.style.display = 'none';
    }

    function updateOrganisationFields() {
        if (!orgType) return;

        const value = orgType.value;

        hideAllOrgFields();
        switch (value) {
            case 'local':
            case '0':
                if (localContainer) localContainer.style.display = 'block';
                break;

            case 'external':
            case '1':
                if (externalContainer) externalContainer.style.display = 'block';
                break;


            case 'new':
            case '2':
                if (nameContainer) nameContainer.style.display = 'block';
                if (uuidContainer) uuidContainer.style.display = 'block';
                break;
        }
    }

    if (orgType) {
        orgType.addEventListener('change', updateOrganisationFields);
        updateOrganisationFields();
    }

    /**********************************
     * PEM certificate dropzones
     **********************************/
    container.querySelectorAll('.pem-dropzone').forEach(zone => {
        const inputId = zone.dataset.target;
        const input   = inputId ? container.querySelector('#' + inputId) : null;
        if (!input) return;

        zone.addEventListener('click', () => input.click());

        zone.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
        });

        zone.addEventListener('dragover', e => {
            e.preventDefault();
            zone.classList.add('pem-drag-over');
        });

        zone.addEventListener('dragleave', () => zone.classList.remove('pem-drag-over'));

        zone.addEventListener('drop', e => {
            e.preventDefault();
            zone.classList.remove('pem-drag-over');
            const file = e.dataTransfer.files[0];
            if (file) _setPemFile(zone, input, file);
        });

        input.addEventListener('change', () => {
            if (input.files[0]) _setPemFile(zone, input, input.files[0]);
        });
    });

    container.querySelectorAll('.pem-existing').forEach(marker => {
        const zone        = container.querySelector('#' + marker.dataset.zone);
        const input       = container.querySelector('#' + marker.dataset.input);
        const deleteField = container.querySelector('#' + marker.dataset.deleteField);
        const filename    = marker.dataset.filename;

        if (!zone || !input) return;

        // Displays the area as if a file were already loaded
        _setPemExisting(zone, input, deleteField, filename);

        marker.remove();
    });

    /**********************************
     * Sync Rules
     **********************************/

    const syncRuleStates = {}; // Map<string, string>  (value -> label)
    const typeFilterStates = {}; // direction -> { attributes: Map, objects: Map }

    function _renderPills(pillsEl, jsonInputEl, items, badgeClass, onUpdate) {
        pillsEl.innerHTML = '';
        items.forEach((label, value) => {
            const pill = document.createElement('span');
            pill.className = `badge d-inline-flex align-items-center gap-1 ${badgeClass}`;
            pill.style.cssText = 'font-size:.75rem;font-weight:500;padding:4px 8px;';
            pill.innerHTML =
                escapeHtml(label) +
                '<button type="button" class="btn-close btn-close-white ms-1" ' +
                'style="font-size:.55rem;" aria-label="Remove"></button>';
            pill.querySelector('.btn-close').addEventListener('click', () => {
                items.delete(value);
                _renderPills(pillsEl, jsonInputEl, items, badgeClass, onUpdate);
                if (typeof onUpdate === 'function') {
                    onUpdate();
                }
            });
            pillsEl.appendChild(pill);
        });
        jsonInputEl.value = JSON.stringify([...items.keys()]);
    }

    function _syncRuleRender(fieldKey) {
        const pillsEl  = container.querySelector('#SyncRulePills_' + fieldKey);
        const jsonEl   = container.querySelector('#SyncRuleJson_' + fieldKey);
        if (!pillsEl || !jsonEl) return;
        const items      = syncRuleStates[fieldKey] || new Map();
        const badgeClass = fieldKey.includes('blockedlist') ? 'text-bg-danger' : 'text-bg-success';
        const updateLabel = () => {
            const contextLabel = pillsEl.closest('.sync-rule-box')?.querySelector('.sync-rule-label');
            if (contextLabel) contextLabel.classList.toggle('d-none', items.size === 0);
        };
        _renderPills(pillsEl, jsonEl, items, badgeClass, updateLabel);
        updateLabel();
    }


    function _syncRuleAdd(fieldKey, value, label) {
        const trimmed = value.trim();
        if (!trimmed) return;
        if (!syncRuleStates[fieldKey]) syncRuleStates[fieldKey] = new Map();
        syncRuleStates[fieldKey].set(trimmed, (label || trimmed).trim());
        _syncRuleRender(fieldKey);
    }


    // Initializes the states using the existing JSON values (edit mode)
    container.querySelectorAll('.sync-rule-box').forEach(box => {
        const fieldKey = `${box.dataset.direction}_${box.dataset.type}_${box.dataset.list}`;
        const jsonInput = container.querySelector('#SyncRuleJson_' + fieldKey);
        syncRuleStates[fieldKey] = new Map();

        if (jsonInput && jsonInput.value && jsonInput.value !== '[]') {
            try {
                // In edit mode, we only have the IDs, we display the ID while waiting for TomSelect to be ready to resolve the labels
                const existing = JSON.parse(jsonInput.value);
                existing.forEach(v => syncRuleStates[fieldKey].set(String(v), String(v)));
                _syncRuleRender(fieldKey);
            } catch(e) {}
        }

        // "+" button and free text
        const addBtn   = box.querySelector('.sync-rule-add-btn');
        const freetext = box.querySelector('.sync-rule-freetext');

        if (addBtn && freetext) {
            addBtn.addEventListener('click', () => {
                _syncRuleAdd(fieldKey, freetext.value, freetext.value);
                freetext.value = '';
            });
            freetext.addEventListener('keydown', e => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    _syncRuleAdd(fieldKey, freetext.value, freetext.value);
                    freetext.value = '';
                }
            });
        }

        // TomSelect — retrieves the label from the selected option
        const selectEl = container.querySelector('#SyncRule_' + fieldKey + '_select');
        if (selectEl) {
            const waitForTs = setInterval(() => {
                if (!selectEl.tomselect) return;
                clearInterval(waitForTs);

                // Label resolution for preloaded values (edit mode)
                syncRuleStates[fieldKey].forEach((lbl, val) => {
                    const opt = selectEl.tomselect.options[val];
                    if (opt) syncRuleStates[fieldKey].set(val, opt.text);
                });
                _syncRuleRender(fieldKey);

                selectEl.tomselect.on('item_add', value => {
                    const opt   = selectEl.tomselect.options[value];
                    const label = opt ? opt.text : value;
                    _syncRuleAdd(fieldKey, value, label);
                    selectEl.tomselect.removeItem(value, true);
                });
            }, 50);
        }
    });

    /**********************************
     * Pull rules — fetch remote tags & orgs
     **********************************/
    const serverId = form.dataset.serverId || '';

    if (serverId) {
        fetch(baseurl + '/servers/queryAvailableSyncFilteringRules/' + serverId, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
            },
        })
            .then(r => r.json())
            .then(response => {
                const alertFetching = container.querySelector('.sync-pull-fetching');
                const alertSuccess  = container.querySelector('.sync-pull-success');
                const alertError    = container.querySelector('.sync-pull-error');

                if (response.error && response.error.length > 0) {
                    // We display the error and enable freetext only
                    if (alertFetching) alertFetching.classList.add('d-none');
                    if (alertError) {
                        alertError.classList.remove('d-none');
                        alertError.querySelector('.sync-pull-error-msg').textContent = response.error;
                    }

                    container.querySelectorAll('[data-remote="true"]').forEach(sel => {
                        sel.closest('div.mb-2')?.remove();
                    });
                    return;
                }

                const remoteTags  = response.data.tags          || [];
                const remoteOrgs  = response.data.organisations || [];

                container.querySelectorAll('[data-remote="true"]').forEach(selectEl => {
                    const fieldKey  = selectEl.dataset.fieldKey;
                    const isOrgSel  = fieldKey.includes('_orgs_');
                    const dataset   = isOrgSel ? remoteOrgs : remoteTags;

                    //  Wait until TomSelect is ready
                    const waitTs = setInterval(() => {
                        if (!selectEl.tomselect) return;
                        clearInterval(waitTs);

                        const ts = selectEl.tomselect;
                        ts.enable();
                        ts.clearOptions();

                        dataset.forEach(entry => {
                            if (entry.uuid !== undefined && entry.name !== undefined) {
                                ts.addOption({ value: entry.uuid, text: entry.name });
                            } else {
                                ts.addOption({ value: entry, text: entry });
                            }
                        });
                        ts.refreshOptions(false);

                        ts.on('item_add', value => {
                            const opt   = ts.options[value];
                            const label = opt ? opt.text : value;
                            _syncRuleAdd(fieldKey, value, label);
                            ts.removeItem(value, true);
                        });
                    }, 50);
                });

                if (alertFetching) alertFetching.classList.add('d-none');
                if (alertSuccess)  alertSuccess.classList.remove('d-none');
            })
            .catch(err => {
                const alertFetching = container.querySelector('.sync-pull-fetching');
                const alertError    = container.querySelector('.sync-pull-error');
                if (alertFetching) alertFetching.classList.add('d-none');
                if (alertError) {
                    alertError.classList.remove('d-none');
                    alertError.querySelector('.sync-pull-error-msg').textContent =
                        'Connection error — ' + err.message;
                }
            });
    }

    /**********************************
     * Type Filtering Rules
     **********************************/

    function _typeFilterRender(direction, scope) {
        const pillsEl = container.querySelector(`#TypeFilterPills_${direction}_${scope}`);
        const jsonEl  = container.querySelector(`#TypeFilterJson_${direction}_${scope}`);
        if (!pillsEl || !jsonEl) return;
        const items = typeFilterStates[direction]?.[scope] || new Map();
        _renderPills(pillsEl, jsonEl, items, 'text-bg-danger');
    }

    ['push', 'pull'].forEach(direction => {
        typeFilterStates[direction] = { attributes: new Map(), objects: new Map() };

        ['attributes', 'objects'].forEach(scope => {
            const jsonInput = container.querySelector(`#TypeFilterJson_${direction}_${scope}`);
            if (!jsonInput || !jsonInput.value || jsonInput.value === '[]') return;
            try {
                const existing = JSON.parse(jsonInput.value);
                existing.forEach(v => typeFilterStates[direction][scope].set(String(v), String(v)));
                _typeFilterRender(direction, scope);
            } catch(e) {}

            const selectEl = container.querySelector(`#TypeFilterSelect_${direction}_${scope}`);
            if (!selectEl) return;
            const waitForTs = setInterval(() => {
                if (!selectEl.tomselect) return;
                clearInterval(waitForTs);
                typeFilterStates[direction][scope].forEach((lbl, val) => {
                    const opt = selectEl.tomselect.options[val];
                    if (opt) typeFilterStates[direction][scope].set(val, opt.text);
                });
                _typeFilterRender(direction, scope);
            }, 50);
        });

        // Main toggle — shows/hides the warning block
        const toggleCb  = container.querySelector('#typeFilteringEnable_' + direction);
        const warningEl = container.querySelector('#typeFilteringWarning_' + direction);
        if (toggleCb && warningEl) {
            toggleCb.addEventListener('change', () => {
                warningEl.classList.toggle('d-none', !toggleCb.checked);
                // If we uncheck the checkbox, we also uncheck the selected items and clear the confirmations
                if (!toggleCb.checked) {
                    const confirmCb  = container.querySelector('#typeFilteringConfirm_' + direction);
                    const selectsEl  = container.querySelector('#typeFilteringSelects_' + direction);
                    if (confirmCb)  confirmCb.checked = false;
                    if (selectsEl)  selectsEl.classList.add('d-none');
                    // Vider les states
                    typeFilterStates[direction].attributes.clear();
                    typeFilterStates[direction].objects.clear();
                    _typeFilterRender(direction, 'attributes');
                    _typeFilterRender(direction, 'objects');
                }
            });
        }

        // Confirmation checkbox — shows/hides the dropdown menus
        const confirmCb = container.querySelector('#typeFilteringConfirm_' + direction);
        const selectsEl = container.querySelector('#typeFilteringSelects_' + direction);
        if (confirmCb && selectsEl) {
            confirmCb.addEventListener('change', () => {
                selectsEl.classList.toggle('d-none', !confirmCb.checked);
            });
        }

        // TomSelect — listens for item_add on both select elements
        ['attributes', 'objects'].forEach(scope => {
            const scopeKey = scope === 'attributes' ? 'attributes' : 'objects';
            const selectEl = container.querySelector(
                '#TypeFilterSelect_' + direction + '_' + scope
            );
            if (!selectEl) return;

            const waitTs = setInterval(() => {
                if (!selectEl.tomselect) return;
                clearInterval(waitTs);

                selectEl.tomselect.on('item_add', value => {
                    const opt   = selectEl.tomselect.options[value];
                    const label = opt ? opt.text : value;
                    typeFilterStates[direction][scopeKey].set(value, label);
                    _typeFilterRender(direction, scope);
                    selectEl.tomselect.removeItem(value, true);
                });
            }, 50);
        });
    });


    /**********************************
     * url_params — JSON validation
     **********************************/
    const urlParamsEl  = container.querySelector('#SyncRulePullUrlParams');
    const urlParamsErr = container.querySelector('#SyncRulePullUrlParamsError');

    if (urlParamsEl) {
        urlParamsEl.addEventListener('blur', function () {
            const val = urlParamsEl.value.trim();
            if (!val) {
                urlParamsEl.classList.remove('is-invalid', 'is-valid');
                return;
            }
            try {
                JSON.parse(val);
                urlParamsEl.classList.remove('is-invalid');
                urlParamsEl.classList.add('is-valid');
                if (urlParamsErr) urlParamsErr.textContent = '';
            } catch (e) {
                urlParamsEl.classList.remove('is-valid');
                urlParamsEl.classList.add('is-invalid');
                if (urlParamsErr) urlParamsErr.textContent = e.message;
            }
        });
    }



    /**********************************
     * Debug helper
     **********************************/
    //console.log('[initServerForm] initialized');
}

function serverSubmitForm(action) {
    const form = document.getElementById('Server' + action + 'Form');
    if (!form) return;

    // ── 1. JSON Setup ──────────────────────────────────────────────────
    let ajax = {};
    const orgType = document.getElementById('ServerOrganisationType').value;
    switch (orgType) {
        case '0': ajax = { id: document.getElementById('ServerLocal').value };    break;
        case '1': ajax = { id: document.getElementById('ServerExternal').value }; break;
        case '2':
            ajax = {
                name: document.getElementById('ServerExternalName').value,
                uuid: document.getElementById('ServerExternalUuid').value
            };
            break;
    }
    document.getElementById('ServerJson').value = JSON.stringify(ajax);

    // ── 2. Read a SyncRuleJson field (returns [] if missing or invalid) ────────
    function readJsonField(id) {
        const el = form.querySelector('#' + id);
        if (!el) return [];
        try { return JSON.parse(el.value) || []; } catch { return []; }
    }

    // ── 3. Build push_rules ──────────────────────────────────────────────
    const pushRules = {
        tags: {
            OR:  readJsonField('SyncRuleJson_push_tags_allowedlist'),
            NOT: readJsonField('SyncRuleJson_push_tags_blockedlist'),
        },
        orgs: {
            OR:  readJsonField('SyncRuleJson_push_orgs_allowedlist'),
            NOT: readJsonField('SyncRuleJson_push_orgs_blockedlist'),
        },
        type_attributes: {
            NOT: readJsonField('TypeFilterJson_push_attributes'),
        },
        type_objects: {
            NOT: readJsonField('TypeFilterJson_push_objects'),
        },
    };

    const pushRulesField = form.querySelector('[name="data[Server][push_rules]"]');
    if (pushRulesField) pushRulesField.value = JSON.stringify(pushRules);

    // ── 4. Build pull_rules ──────────────────────────────────────────────
    const pullRules = {
        tags: {
            OR:  readJsonField('SyncRuleJson_pull_tags_allowedlist'),
            NOT: readJsonField('SyncRuleJson_pull_tags_blockedlist'),
        },
        orgs: {
            OR:  readJsonField('SyncRuleJson_pull_orgs_allowedlist'),
            NOT: readJsonField('SyncRuleJson_pull_orgs_blockedlist'),
        },
        type_attributes: {
            NOT: readJsonField('TypeFilterJson_pull_attributes'),
        },
        type_objects: {
            NOT: readJsonField('TypeFilterJson_pull_objects'),
        },
        url_params: '',
    };

    // Inject url_params from the textarea (without submitting it directly)
    const urlParamsEl = form.querySelector('#SyncRulePullUrlParams');
    if (urlParamsEl) {
        const raw = urlParamsEl.value.trim();
        if (raw) {
            // Validate that it is valid JSON, but store the raw string
            try {
                JSON.parse(raw);
                pullRules.url_params = raw;
            } catch {
                pullRules.url_params = raw;
            }
        } else {
            pullRules.url_params = '';
        }
    }

    const pullRulesField = form.querySelector('[name="data[Server][pull_rules]"]');
    if (pullRulesField) pullRulesField.value = JSON.stringify(pullRules);

    form.submit();
}


function _setPemFile(zone, input, file) {
    _renderPemZone(zone, input, file.name, null, null);
}

function _setPemExisting(zone, input, deleteField, filename) {
    _renderPemZone(zone, input, filename, deleteField, () => {
        if (deleteField) deleteField.checked = true;
    });
}

function _renderPemZone(zone, input, filename, deleteField, onRemoveExtra) {
    zone.classList.add('pem-has-file');
    const hint = zone.querySelector('.pem-hint');
    const icon = zone.querySelector('.pem-icon');
    const name = zone.querySelector('.pem-filename');
    if (!name) return;

    if (hint) hint.classList.add('d-none');
    if (icon) icon.classList.add('d-none');

    name.classList.remove('d-none');
    name.innerHTML =
        '<i class="fas fa-file-certificate me-1"></i>' + escapeHtml(filename) +
        ' <button type="button" class="pem-remove-btn" aria-label="Remove file">' +
        '<i class="fas fa-trash-alt"></i></button>';

    name.querySelector('.pem-remove-btn').addEventListener('click', e => {
        e.stopPropagation();
        input.value = '';
        zone.classList.remove('pem-has-file');
        name.classList.add('d-none');
        name.innerHTML = '';
        if (hint) hint.classList.remove('d-none');
        if (icon) icon.classList.remove('d-none');
        if (onRemoveExtra) onRemoveExtra();
    });
}



function _onTomSelectReady(el, callback) {
    if (!el) return;
    const interval = setInterval(() => {
        if (!el.tomselect) return;
        clearInterval(interval);
        callback(el.tomselect);
    }, 50);
}




/*******************************
 * Sharing Group Add/Edit
 *******************************/

function initSharingGroupForm(container) {
    const form = container.querySelector('#sharingGroupForm');
    if (!form) return;

    const orgState    = new Map();  // organisations : Map<id|uuid, { id, name, type, uuid, extend, removable }>
    const serverState = new Map();  // servers       : Map<id,      { id, name, url,  all_orgs, removable }>

    // ── Helpers DOM ───────────────────────────────────────────────────────────
    const orgsBody    = container.querySelector('#organisations_table_body');
    const serversBody = container.querySelector('#servers_table_body');
    const jsonInput   = container.querySelector('#SharingGroupJson');
    const roamingCb   = container.querySelector('#SharingGroupRoaming');
    const serverList  = container.querySelector('#serverList');

    // ── Organisations table display ────────────────────────────────────────
    function renderOrgs() {
        if (!orgsBody) return;
        orgsBody.innerHTML = '';

        orgState.forEach((org, key) => {
            const tr = document.createElement('tr');
            // Badge type
            const typeBadge = org.type === 'local'
                ? '<span class="badge text-bg-success">Local</span>'
                : '<span class="badge text-bg-secondary">External</span>';

            // Toggle extend
            const extendChecked = org.extend ? 'checked' : '';
            const removableAttr = org.removable === false ? 'disabled' : '';

            tr.innerHTML = `
                <td>${typeBadge}</td>
                <td>${escapeHtml(org.name)}</td>
                <td><small class="text-muted">${escapeHtml(org.uuid || '—')}</small></td>
                <td>
                    <div class="form-check form-switch mb-0">
                        <input class="form-check-input sg-org-extend"
                               type="checkbox"
                               data-key="${escapeHtml(key)}"
                               ${extendChecked}
                               ${removableAttr}
                               title="${escapeHtml('Allow this organisation to extend the sharing group')}">
                    </div>
                </td>
                <td>
                    ${org.removable !== false
                        ? `<button type="button" class="btn btn-sm btn-outline-danger sg-org-remove" data-key="${escapeHtml(key)}">
                               <i class="fas fa-trash-alt"></i>
                           </button>`
                        : '<span class="text-muted small">—</span>'
                    }
                </td>`;

            // Extend toggle
            tr.querySelector('.sg-org-extend')?.addEventListener('change', e => {
                orgState.get(key).extend = e.target.checked;
                _updateSummary();
            });

            // Remove
            tr.querySelector('.sg-org-remove')?.addEventListener('click', () => {
                orgState.delete(key);
                renderOrgs();
                _updateSummary();
            });

            orgsBody.appendChild(tr);
        });

        _updateSummary();
    }

    // ── Servers table display ──────────────────────────────────────────────
    function renderServers() {
        if (!serversBody) return;
        serversBody.innerHTML = '';

        serverState.forEach((srv, key) => {
            const tr = document.createElement('tr');
            const allOrgsChecked = srv.all_orgs ? 'checked' : '';
            const removableAttr  = srv.removable === false ? 'disabled' : '';

            tr.innerHTML = `
                <td>${escapeHtml(srv.name)}</td>
                <td><small class="text-muted">${escapeHtml(srv.url || '—')}</small></td>
                <td>
                    <div class="form-check form-switch mb-0">
                        <input class="form-check-input sg-srv-allorgs"
                               type="checkbox"
                               data-key="${escapeHtml(key)}"
                               ${allOrgsChecked}
                               ${removableAttr}
                               title="${escapeHtml('Sync with all organisations on this instance')}">
                    </div>
                </td>
                <td>
                    ${srv.removable !== false
                        ? `<button type="button" class="btn btn-sm btn-outline-danger sg-srv-remove" data-key="${escapeHtml(key)}">
                               <i class="fas fa-trash-alt"></i>
                           </button>`
                        : '<span class="text-muted small">—</span>'
                    }
                </td>`;

            tr.querySelector('.sg-srv-allorgs')?.addEventListener('change', e => {
                serverState.get(key).all_orgs = e.target.checked;
                _updateSummary();
            });

            tr.querySelector('.sg-srv-remove')?.addEventListener('click', () => {
                serverState.delete(key);
                renderServers();
                _updateSummary();
            });

            serversBody.appendChild(tr);
        });

        _updateSummary();
    }

    // ── Local orgs ────────────────────────────────────────────────────────────────
    _onTomSelectReady(container.querySelector('#sg-local-org-select'), ts => {
        ts.on('item_add', value => {
            ts.removeItem(value, true);
            if (orgState.has(value)) return;
            const opt  = ts.options[value];
            const meta = (typeof sgOrgMeta !== 'undefined') ? (sgOrgMeta[value] || {}) : {};
            orgState.set(value, {
                id:        value,
                name:      opt?.text || value,
                type:      'local',
                uuid:      meta.uuid || '',
                extend:    false,
                removable: true,
            });
            renderOrgs();
        });
    });

    // ── External orgs ─────────────────────────────────────────────────────────────
    _onTomSelectReady(container.querySelector('#sg-ext-org-select'), ts => {
        ts.on('item_add', value => {
            ts.removeItem(value, true);
            if (orgState.has(value)) return;
            const opt  = ts.options[value];
            const meta = (typeof sgOrgMeta !== 'undefined') ? (sgOrgMeta[value] || {}) : {};
            orgState.set(value, {
                id:        value,
                name:      opt?.text || value,
                type:      'external',
                uuid:      meta.uuid || '',
                extend:    false,
                removable: true,
            });
            renderOrgs();
        });
    });

    // ── Servers ───────────────────────────────────────────────────────────────────
    _onTomSelectReady(container.querySelector('#sg-server-select'), ts => {
        ts.on('item_add', value => {
            ts.removeItem(value, true);
            if (serverState.has(value)) return;
            const opt  = ts.options[value];
            const meta = (typeof sgServerMeta !== 'undefined') ? (sgServerMeta[value] || {}) : {};
            serverState.set(value, {
                id:        value,
                name:      opt?.text || value,
                url:       meta.url  || '',
                all_orgs:  false,
                removable: true,
            });
            renderServers();
        });
    });



    // ── Roaming toggle ────────────────────────────────────────────────────────
    roamingCb?.addEventListener('change', () => {
        if (serverList) serverList.style.display = roamingCb.checked ? 'none' : 'block';
        _updateSummary();
    });

    // ── Navigation accordion (Next / Prev) ────────────────────────────────────
    container.querySelectorAll('.sg-next').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.next;
            const target   = container.querySelector('#' + targetId);
            if (target) new bootstrap.Collapse(target, { toggle: false }).show();
        });
    });

    container.querySelectorAll('.sg-prev').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.prev;
            const target   = container.querySelector('#' + targetId);
            if (target) new bootstrap.Collapse(target, { toggle: false }).show();
        });
    });

    // ── Résumé (Step 4) ───────────────────────────────────────────────────────
    function _updateSummary() {
        const name         = container.querySelector('#SharingGroupName')?.value        || '—';
        const releasable   = container.querySelector('#SharingGroupReleasability')?.value || '—';

        _setText('summarytitle',      name);
        _setText('summaryreleasable', releasable);

        // Local orgs
        const localOrgs    = [...orgState.values()].filter(o => o.type === 'local');
        const localExtend  = localOrgs.filter(o => o.extend);
        _setText('summarylocal',       localOrgs.length   ? localOrgs.map(o => o.name).join(', ')   : '—');
        _setText('summarylocalextend', localExtend.length ? localExtend.map(o => o.name).join(', ') : ('none'));

        // External orgs
        const extOrgs      = [...orgState.values()].filter(o => o.type === 'external');
        const extExtend    = extOrgs.filter(o => o.extend);
        _setText('summaryexternal',       extOrgs.length   ? extOrgs.map(o => o.name).join(', ')   : '—');
        _setText('summaryexternalextend', extExtend.length ? extExtend.map(o => o.name).join(', ') : ('none'));

        // Servers
        const roaming = roamingCb?.checked;
        const srvText = roaming
            ? ('Roaming mode — any connected instance')
            : ([...serverState.values()].map(s => s.name).join(', ') || '—');
        _setText('summaryservers', srvText);
    }

    function _setText(id, text) {
        const el = container.querySelector('#' + id);
        if (el) el.textContent = text;
    }

    // Resume update from Step 1
    ['SharingGroupName', 'SharingGroupReleasability'].forEach(id => {
        container.querySelector('#' + id)?.addEventListener('input', _updateSummary);
    });

    // ── Submit ────────────────────────────────────────────────────────────────
    container.querySelector('#sg-submit-btn')?.addEventListener('click', () => {
        const name = container.querySelector('#SharingGroupName')?.value.trim();
        if (!name) {
            const step1 = container.querySelector('#sgCollapse1');
            if (step1) new bootstrap.Collapse(step1, { toggle: false }).show();
            form.classList.add('was-validated');
            return;
        }

        const payload = {
            sharingGroup: {
                name:          name,
                releasability: container.querySelector('#SharingGroupReleasability')?.value.trim() || '',
                description:   container.querySelector('#SharingGroupDescription')?.value.trim()   || '',
                active:        container.querySelector('#SharingGroupActive')?.checked  ? 1 : 0,
                roaming:       container.querySelector('#SharingGroupRoaming')?.checked ? 1 : 0,
                uuid:          container.querySelector('#SharingGroupUuid')?.value.trim() || undefined,
            },
            organisations: [...orgState.values()].map(o => ({
                id:     o.id,
                name:   o.name,
                type:   o.type,
                uuid:   o.uuid || '',
                extend: o.extend ? 1 : 0,
            })),
            servers: [...serverState.values()].map(s => ({
                id:       s.id,
                name:     s.name,
                url:      s.url,
                all_orgs: s.all_orgs ? 1 : 0,
            })),
        };

        if (jsonInput) jsonInput.value = JSON.stringify(payload);
        form.submit();
    });

    // ── Initialization in edit mode ───────────────────────────────────────────
    // The controller passes $sharingGroup along with SharingGroupOrg and SharingGroupServer
    // We initialize the two Maps using the inline PHP data
    if (typeof sgInitData !== 'undefined' && sgInitData) {
        (sgInitData.organisations || []).forEach(o => {
            const key = String(o.id);
            orgState.set(key, {
                id:        o.id,
                name:      o.name,
                type:      o.type,
                uuid:      o.uuid || '',
                extend:    !!o.extend,
                removable: o.removable !== false,
            });
        });
        (sgInitData.servers || []).forEach(s => {
            const key = String(s.id || s.Server?.id);
            serverState.set(key, {
                id:        s.Server?.id || s.id,
                name:      s.Server?.name || s.name || key,
                url:       s.Server?.url  || s.url  || '',
                all_orgs:  !!s.all_orgs,
                removable: s.removable !== false,
            });
        });
        renderOrgs();
        renderServers();

        // Step 1
        if (sgInitData.sharingGroup) {
            const sg = sgInitData.sharingGroup;
            ['Name', 'Releasability', 'Description'].forEach(f => {
                const el = container.querySelector('#SharingGroup' + f);
                if (el && sg[f.toLowerCase()] !== undefined) el.value = sg[f.toLowerCase()];
            });
            if (sg.active  !== undefined && container.querySelector('#SharingGroupActive'))
                container.querySelector('#SharingGroupActive').checked = !!sg.active;
            if (sg.roaming !== undefined && roamingCb)  {
                roamingCb.checked = !!sg.roaming;
                if (serverList) serverList.style.display = roamingCb.checked ? 'none' : 'block';
            }
        }
        _updateSummary();
    } else {
        if (typeof sgDefaultOrg !== 'undefined' && sgDefaultOrg) {
            const key = String(sgDefaultOrg.id);
            orgState.set(key, { ...sgDefaultOrg, removable: false });
        }
        if (typeof sgDefaultServer !== 'undefined' && sgDefaultServer) {
            const key = String(sgDefaultServer.id);
            serverState.set(key, { ...sgDefaultServer, removable: false });
        }
        renderOrgs();
        renderServers();
    }
}

/*******************************
 * Lazy index-table popovers
 * Index rows are re-rendered by AJAX pagination and filtering, so these
 * popovers are built on the first hover/focus rather than initialised up
 * front on every render. `container: 'body'` keeps them out of the table's
 * overflow container (.table-responsive.table-scroll), which would clip them.
 *******************************/
(function () {
    var LAZY_POPOVERS = '.sighting-counts, .role-perm-counter';

    function lazyPopover(e) {
        var el = e.target && e.target.closest ? e.target.closest(LAZY_POPOVERS) : null;
        if (!el || el._popoverReady) return;
        el._popoverReady = true;
        new bootstrap.Popover(el, {
            trigger:   'hover focus',
            html:      true,
            placement: 'top',
            container: 'body',
        }).show();
    }

    // The triggering event predates the instance, hence the .show() above.
    document.addEventListener('mouseenter', lazyPopover, true);
    document.addEventListener('focusin', lazyPopover);
})();

/*******************************
 * Sighting cells — add-sighting buttons
 * i18n strings are injected once per page via window._sightingI18n
 * (set by the sightings.ctp field partial)
 *******************************/
(function () {
    document.addEventListener('click', async function (e) {
        var btn = e.target.closest('.add-sighting-btn');
        if (!btn) return;
        e.preventDefault();

        var attrId = btn.dataset.attributeId;
        var type   = btn.dataset.type;
        var i18n   = window._sightingI18n || {};

        btn.disabled = true;
        try {
            var response = await fetch(baseurl + '/sightings/add/' + attrId, {
                method:  'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type':     'application/x-www-form-urlencoded',
                    'Accept':           'application/json',
                    'X-CSRF-Token':     getCsrfToken(),
                },
                body: 'data[Sighting][type]=' + encodeURIComponent(type)
                    + '&data[Sighting][id]='  + encodeURIComponent(attrId),
            });

            var data = await response.json();

            if (response.ok && !data.errors) {
                var countEl = document.querySelector(
                    '#sightings_' + attrId + ' .sighting-' + (type === '0' ? 's' : 'f')
                );
                if (countEl) countEl.textContent = parseInt(countEl.textContent || '0') + 1;
                showToast(type === '0'
                    ? (i18n.addedSighting || 'Sighting added')
                    : (i18n.addedFP       || 'Marked as false positive'),
                    'success');
            } else {
                showToast(i18n.failed    || 'Failed to add sighting', 'danger');
            }
        } catch (_e) {
            showToast(i18n.reqFailed || 'Request failed — please try again', 'danger');
        } finally {
            btn.disabled = false;
        }
    });
})();


/*******************************
 * Overmind form shared utilities
 * Used by Events/add, Attributes/add, and any form with a
 * distribution TomSelect or non-correlating type logic.
 *******************************/
/* ── Distribution colours / icons ──────────────────────────────────────── */
var DIST_MAP = {
    0: { icon: 'misp-icon misp-icon-organisation misp-simple', bg: '#f8d7da', color: '#842029' },
    1: { icon: 'fas fa-users',                                  bg: '#ffe5b4', color: '#b45309' },
    2: { icon: 'fas fa-network-wired',                          bg: '#e7d3c3', color: '#5a3e2b' },
    3: { icon: 'fas fa-globe',                                  bg: '#d1f7e0', color: '#0f5132' },
    4: { icon: 'misp-icon misp-icon-sharing-group misp-simple', bg: '#6a96ee', color: '#0e146d' },
    5: { icon: 'fas fa-code-fork',                              bg: '#e6b7df', color: '#380f33' },
};

function renderDistOption(data, escape) {
    var cfg = DIST_MAP[parseInt(data.value, 10)]
        || { icon: 'fas fa-question', bg: '#f1f1f1', color: '#333' };
    return '<div class="d-flex align-items-center gap-2 py-1">'
        + '<span class="badge d-inline-flex align-items-center px-2 py-1" style="'
            + 'background:' + cfg.bg + ';color:' + cfg.color + ';'
            + 'border:1px solid ' + cfg.color + '33;">'
        + '<i class="' + cfg.icon + '"></i>'
        + '</span>'
        + '<span>' + escape(data.text) + '</span>'
        + '</div>';
}

function renderDistSelected(data, escape) {
    var cfg = DIST_MAP[parseInt(data.value, 10)]
        || { icon: 'fas fa-question', bg: '#f1f1f1', color: '#333' };
    return '<div class="d-flex align-items-center gap-1">'
        + '<span class="badge d-inline-flex align-items-center px-1" style="'
            + 'background:' + cfg.bg + ';color:' + cfg.color + ';'
            + 'border:1px solid ' + cfg.color + '33; font-size:.65rem;">'
        + '<i class="' + cfg.icon + '"></i>'
        + '</span>'
        + '<span>' + escape(data.text) + '</span>'
        + '</div>';
}

/*
 * distBadgeHtml(level, withLabel?, labels?)
 * Renders a small inline distribution badge (icon + optional label).
 * @param {number}  level      Distribution level 0–5
 * @param {boolean} withLabel  Show the text label beside the icon
 * @param {object}  labels     Map of level → label string (e.g. distLevels from PHP)
 */
function distBadgeHtml(level, withLabel, labels) {
    var d   = DIST_MAP[level] || DIST_MAP[0];
    var lbl = (withLabel && labels && labels[level]) ? labels[level] : '';
    return '<span class="badge d-inline-flex align-items-center gap-1 px-2 py-1"'
        + ' style="background:' + d.bg + ';color:' + d.color
        + ';border:1px solid ' + d.color + '30;font-weight:500;">'
        + '<i class="' + d.icon + '"></i>'
        + (lbl ? '<span class="ms-1" style="font-size:.7rem;">' + escapeHtml(lbl) + '</span>' : '')
        + '</span>';
}

/*******************************
 * tagTextColour / tagBadgeStyle
 * The client-side mirror of TextColourHelper::getTextColour() and of the
 * badge styling in Elements/genericElementsBS5/Badges/tag.ctp — a tag drawn
 * by JavaScript has to come out looking exactly like one drawn by PHP.
 * @param {string} hex  Tag colour, '#rrggbb'
 *******************************/
function tagTextColour(hex) {
    hex = hex || '#0088cc';
    var r = parseInt(hex.slice(1, 3), 16);
    var g = parseInt(hex.slice(3, 5), 16);
    var b = parseInt(hex.slice(5, 7), 16);
    return ((2 * r) + b + (3 * g)) / 6 < 127 ? 'white' : 'black';
}

function tagBadgeStyle(colour) {
    colour = colour || '#0088cc';
    return 'background-color:' + colour + '; color:' + tagTextColour(colour) + ';'
        + ' filter: drop-shadow(-1px 3px 2px rgba(50, 50, 0, 0.5));'
        + ' background-image: linear-gradient(145deg, rgba(255,255,255,0.25) 0%,'
        + ' rgba(255,255,255,0.05) 40%, rgba(0,0,0,0.05) 100%);'
        + ' text-align:left; white-space:normal; word-wrap:break-word;';
}

/*******************************
 * initTagPickerSection
 * The tag picker used everywhere in the theme: category buttons, a TomSelect
 * search over the current category, and the picked tags drawn below as real
 * MISP badges with a remove cross. Drives both the standalone edit-tags modal
 * (Modals/tag_picker.ctp, one section per locality) and the in-form field
 * (Forms/tag_picker_field.ctp).
 *
 * `root` must contain .tag-cat-btn buttons (each with data-cat), a
 * select.tag-picker, .tag-selected and .tag-selected-empty.
 *
 * @param {Element}  root      Section container
 * @param {object}   catData   {<cat>: [{id,name,colour}], collections: [{id,name,tags:[…]}]}
 * @param {Array}    initTags  Pre-selected [{id,name,colour}]
 * @param {object}   [options] localMarker: draw the local user glyph on badges;
 *                             onChange: called with the selected id array
 * @return {{ids: function}} the current selection
 *******************************/
function initTagPickerSection(root, catData, initTags, options) {
    options = options || {};
    var selEl = root.querySelector('.tag-selected');
    var emptyEl = root.querySelector('.tag-selected-empty');
    var pickerEl = root.querySelector('.tag-picker');

    var selected = {};               /* id(string) -> {id,name,colour} */
    var currentCat = 'all';

    function ids() {
        return Object.keys(selected).map(Number);
    }

    function addTag(tag) {
        if (!tag || tag.id == null) { return; }
        selected[String(tag.id)] = {
            id: tag.id, name: tag.name, colour: tag.colour || '#0088cc'
        };
    }

    function render() {
        var keys = Object.keys(selected);
        emptyEl.classList.toggle('d-none', keys.length > 0);
        selEl.innerHTML = '';
        keys.sort(function (a, b) {
            return selected[a].name.localeCompare(selected[b].name);
        });
        keys.forEach(function (id) {
            var t = selected[id];

            var wrap = document.createElement('div');
            wrap.className = 'd-inline-flex align-items-center';

            var badge = document.createElement('span');
            badge.className = 'badge me-1 mb-1 d-inline-flex align-items-center gap-1';
            badge.style.cssText = tagBadgeStyle(t.colour);

            var txt = document.createElement('span');
            if (options.localMarker) {
                txt.innerHTML = '<i class="fas fa-user me-1"></i>';
            }
            txt.appendChild(document.createTextNode(t.name));

            var x = document.createElement('i');
            x.className = 'fas fa-times';
            x.style.cssText = 'cursor:pointer; opacity:.8;';
            x.setAttribute('role', 'button');
            x.setAttribute('aria-label', 'Remove');
            x.addEventListener('click', function () {
                delete selected[id];
                render();
            });

            badge.appendChild(txt);
            badge.appendChild(x);
            wrap.appendChild(badge);
            selEl.appendChild(wrap);
        });
        if (typeof options.onChange === 'function') { options.onChange(ids()); }
    }

    function buildOptions(cat) {
        if (cat === 'collections') {
            return (catData.collections || []).map(function (c) {
                return {
                    value: String(c.id), name: c.name,
                    count: (c.tags || []).length, isCollection: true
                };
            });
        }
        return (catData[cat] || []).map(function (t) {
            return { value: String(t.id), name: t.name, colour: t.colour };
        });
    }

    function renderOpt(item, escape) {
        if (item.isCollection) {
            return '<div class="d-flex align-items-center gap-2 py-1">'
                + '<i class="fas fa-layer-group text-tag"></i>'
                + '<span class="text-truncate">'
                + escape(item.name) + '</span>'
                + '<span class="badge bg-light text-muted ms-auto">'
                + (item.count || 0) + '</span></div>';
        }
        var col = item.colour || '#0088cc';
        return '<div class="d-flex align-items-center gap-2 py-1">'
            + '<span style="display:inline-block;width:10px;height:10px;'
            + 'border-radius:2px;flex-shrink:0;background:' + escape(col) + ';"></span>'
            + '<span class="text-truncate">'
            + escape(item.name) + '</span></div>';
    }

    var ts = new TomSelect(pickerEl, {
        valueField: 'value',
        labelField: 'name',
        searchField: ['name'],
        maxItems: 1,
        options: [],
        render: { option: renderOpt, item: renderOpt, option_create: false },
        onItemAdd: function (value) {
            if (currentCat === 'collections') {
                var coll = (catData.collections || []).find(function (c) {
                    return String(c.id) === String(value);
                });
                if (coll) { (coll.tags || []).forEach(addTag); }
            } else {
                var tag = (catData[currentCat] || []).find(function (t) {
                    return String(t.id) === String(value);
                });
                if (tag) { addTag(tag); }
            }
            render();
            var self = this;
            setTimeout(function () { self.clear(true); self.blur(); }, 0);
        }
    });

    function setCategory(cat) {
        currentCat = cat;
        root.querySelectorAll('.tag-cat-btn').forEach(function (b) {
            b.classList.toggle('active', b.getAttribute('data-cat') === cat);
        });
        ts.clear(true);
        ts.clearOptions();
        ts.addOptions(buildOptions(cat));
        ts.refreshOptions(false);
    }

    root.querySelectorAll('.tag-cat-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            setCategory(btn.getAttribute('data-cat'));
        });
    });

    (initTags || []).forEach(addTag);
    render();
    var first = root.querySelector('.tag-cat-btn');
    setCategory(first ? first.getAttribute('data-cat') : 'all');

    return { ids: ids };
}

/*******************************
 * galaxyBadgeStyle
 * The client-side mirror of GalaxyColour::palette()/badgeStyle() — a cluster
 * badge drawn by JavaScript has to come out looking exactly like one drawn by
 * PHP, so keep the numbers in sync with the lib.
 * @param {number} hue  GalaxyColour::hue() of the cluster's galaxy
 *******************************/
function galaxyBadgeStyle(hue) {
    hue = (hue == null) ? 270 : hue;
    return 'background-color:hsla(' + hue + ',65%,55%,var(--galaxy-alpha,0.12));'
        + 'color:hsl(' + hue + ',65%,28%);'
        + 'border:1px solid hsl(' + hue + ',55%,65%);'
        + 'background-image:linear-gradient(145deg,rgba(255,255,255,0.15) 0%,'
        + 'rgba(255,255,255,0.04) 40%,rgba(0,0,0,0.04) 100%);'
        + 'white-space:normal;word-wrap:break-word;text-align:left;max-width:260px;';
}

/*******************************
 * initGalaxyPickerSection
 * The galaxy cluster picker used everywhere in the theme: galaxy category
 * buttons, a TomSelect searching the cluster endpoint remotely (an empty query
 * lists the scoped galaxy's clusters, "All Galaxies" needs 2 characters), and
 * the picked clusters drawn below as galaxy badges with a remove cross. Drives
 * both the standalone edit-clusters modal (Modals/galaxy_picker.ctp, one
 * section per locality) and the in-form field (Forms/galaxy_picker_field.ctp).
 *
 * `root` must contain .galaxy-cat-btn buttons (the per-galaxy ones carrying
 * data-galaxy-id), a select.galaxy-picker, .galaxy-selected and
 * .galaxy-selected-empty.
 *
 * @param {Element} root          Section container
 * @param {Array}   initClusters  Pre-selected [{id,name,galaxy,hue}]
 * @param {object}  options       searchUrl: cluster search endpoint (required);
 *                                localMarker: draw the local user glyph on badges;
 *                                onChange: called with the selected id array
 * @return {{ids: function}} the current selection
 *******************************/
function initGalaxyPickerSection(root, initClusters, options) {
    options = options || {};
    var selEl = root.querySelector('.galaxy-selected');
    var emptyEl = root.querySelector('.galaxy-selected-empty');
    var pickerEl = root.querySelector('.galaxy-picker');
    var searchUrl = options.searchUrl;

    var selected = {};          /* id(string) -> {id,name,galaxy,hue} */
    var currentGalaxyId = null; /* null = "All" (search across galaxies) */

    function ids() {
        return Object.keys(selected).map(Number);
    }

    function addCluster(c) {
        if (!c || c.id == null) { return; }
        selected[String(c.id)] = {
            id: c.id, name: c.name, galaxy: c.galaxy || '',
            hue: (c.hue == null ? 270 : c.hue)
        };
    }

    function render() {
        var keys = Object.keys(selected);
        emptyEl.classList.toggle('d-none', keys.length > 0);
        selEl.innerHTML = '';
        keys.sort(function (a, b) {
            return selected[a].name.localeCompare(selected[b].name);
        });
        keys.forEach(function (id) {
            var c = selected[id];

            var badge = document.createElement('span');
            badge.className = 'badge p-2 d-inline-flex align-items-center gap-2';
            badge.style.cssText = galaxyBadgeStyle(c.hue);
            if (c.galaxy) { badge.title = c.galaxy; }

            var txt = document.createElement('span');
            txt.style.cssText = 'overflow:hidden;text-overflow:ellipsis;'
                + 'white-space:nowrap;min-width:0;';
            if (options.localMarker) {
                txt.innerHTML = '<i class="fas fa-user me-1"></i>';
            }
            txt.appendChild(document.createTextNode(c.name));

            var x = document.createElement('i');
            x.className = 'fas fa-times';
            x.style.cssText = 'cursor:pointer; opacity:.8; flex-shrink:0;';
            x.setAttribute('role', 'button');
            x.setAttribute('aria-label', 'Remove');
            x.addEventListener('click', function () {
                delete selected[id];
                render();
            });

            badge.appendChild(txt);
            badge.appendChild(x);
            selEl.appendChild(badge);
        });
        if (typeof options.onChange === 'function') { options.onChange(ids()); }
    }

    function renderOpt(item, escape) {
        return '<div class="d-flex flex-column py-1">'
            + '<span>' + escape(item.name) + '</span>'
            + (item.galaxy
                ? '<span class="text-muted" style="font-size:.72rem;">'
                    + escape(item.galaxy) + '</span>'
                : '')
            + '</div>';
    }

    var ts = new TomSelect(pickerEl, {
        valueField:   'id',
        labelField:   'name',
        searchField:  ['name', 'galaxy'],
        maxItems:     1,
        options:      [],
        loadThrottle: 300,
        /* Use a different class name for the loading state to avoid a CSS collision. */
        loadingClass: 'ts-loading',
        /* When a galaxy is selected, even an empty query lists its clusters */
        shouldLoad:   function (q) {
            return currentGalaxyId ? true : q.length >= 2;
        },
        /* The endpoint handles matching, so TomSelect's filter is disabled to keep all server-sorted results. */
        score:        function () {
            return function () { return 1; };
        },
        load: function (query, callback) {
            var self = this;
            var url = searchUrl + '?q=' + encodeURIComponent(query);
            if (currentGalaxyId) {
                url += '&galaxy_id=' + encodeURIComponent(currentGalaxyId);
            }
            fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (r) { return r.json(); })
                .then(function (json) {
                    /* clearOptions() clears stale results and forces the endpoint to reload when the query changes. */
                    self.clearOptions();
                    callback(json);
                })
                .catch(function () { callback(); });
        },
        render: {
            option: renderOpt,
            item: renderOpt,
            option_create: false,
            /* Use a custom loading spinner to avoid a CSS collision */
            loading: function () {
                return '<div class="text-center py-2">'
                    + '<span class="spinner-border spinner-border-sm '
                    + 'text-galaxy" role="status" aria-hidden="true">'
                    + '</span></div>';
            }
        },
        onItemAdd: function (value) {
            var item = this.options[value];
            if (item) { addCluster(item); render(); }
            var self = this;
            setTimeout(function () { self.clear(true); self.blur(); }, 0);
        }
    });

    /* Clear stale results when the query is too short to offer any valid options. */
    ts.on('type', function (q) {
        if (currentGalaxyId || q.length >= 2) { return; }
        if (Object.keys(ts.options).length === 0) { return; }
        ts.clearOptions();
        ts.refreshOptions();
    });

    /* Category buttons: "All" (remote search) or one galaxy (scoped) */
    root.querySelectorAll('.galaxy-cat-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            root.querySelectorAll('.galaxy-cat-btn').forEach(function (b) {
                b.classList.toggle('active', b === btn);
            });
            var gid = btn.getAttribute('data-galaxy-id');
            currentGalaxyId = gid ? gid : null;

            /* reset cache + options so the new scope reloads cleanly */
            ts.clearOptions();
            ts.clearCache();

            if (currentGalaxyId) {
                /* preload this galaxy's clusters and show them */
                ts.load('');
                ts.focus();
                ts.open();
            }
        });
    });

    (initClusters || []).forEach(addCluster);
    render();

    return { ids: ids };
}

/**
 * The `d-none` toggle a choice field can drive on another block — the
 * distribution field revealing its sharing group. Returns a function to call
 * with the current value; a group that declares no reveal gets a no-op, so
 * callers never branch.
 */
function choiceRevealBinder(group) {
    var expected = group.dataset.choiceRevealValue;
    var target = group.dataset.choiceRevealTarget
        ? document.querySelector(group.dataset.choiceRevealTarget)
        : null;
    if (!target || expected === undefined) {
        return function () {};
    }
    return function (current) {
        target.classList.toggle('d-none', String(current) !== expected);
    };
}

/*******************************
 * initChoiceCards
 * Wires every card-based radio group inside `container` — the markup of
 * Elements/genericElementsBS5/Forms/choice_cards.ctp, which the distribution
 * field, the analysis level and the threat level are all built from.
 *
 * The hidden <select> stays the value: the cards only mirror it, and a click
 * fires a real `change` on it so host forms (an object's review pane, a
 * warning banner) keep listening to the select and to nothing else.
 *
 * Idempotent — a group is bound once, so calling this on a container that is
 * already live costs nothing.
 * @param {Element|Document} [container]  defaults to the whole document
 *******************************/
function initChoiceCards(container) {
    var scope = container || document;

    scope.querySelectorAll('[data-choice-cards]').forEach(function (group) {
        if (group.dataset.choiceBound) { return; }
        group.dataset.choiceBound = '1';

        var select = group.querySelector('[data-choice-input]');
        var cards = Array.prototype.slice.call(
            group.querySelectorAll('[data-choice-value]')
        );
        if (!select || !cards.length) { return; }

        var reveal = choiceRevealBinder(group);
        var revealTarget = group.dataset.choiceRevealTarget
            ? document.querySelector(group.dataset.choiceRevealTarget)
            : null;

        function sync() {
            var current = String(select.value);
            var hit = false;
            cards.forEach(function (card) {
                var on = card.dataset.choiceValue === current;
                if (on) { hit = true; }
                card.classList.toggle('is-selected', on);
                card.setAttribute('aria-checked', on ? 'true' : 'false');
                /* Only the selected card is in the tab order, so the group is
                   one tab stop and the arrow keys move within it. */
                card.tabIndex = on ? 0 : -1;
            });
            /* A value with no card of its own (a level the form dropped) would
               otherwise leave the group unreachable by keyboard. */
            if (!hit) { cards[0].tabIndex = 0; }
            reveal(current);
        }

        function pick(card) {
            if (card.dataset.choiceValue === String(select.value)) { return; }
            select.value = card.dataset.choiceValue;
            select.dispatchEvent(new Event('change', { bubbles: true }));
        }

        var steps = {
            ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1
        };

        cards.forEach(function (card, index) {
            card.addEventListener('click', function () { pick(card); });
            card.addEventListener('keydown', function (e) {
                if (e.key === ' ' || e.key === 'Enter') {
                    e.preventDefault();
                    pick(card);
                    return;
                }
                if (!(e.key in steps)) { return; }
                e.preventDefault();
                var next = cards[
                    (index + steps[e.key] + cards.length) % cards.length
                ];
                pick(next);
                next.focus();
            });
        });

        select.addEventListener('change', sync);
        sync();

        /* The sharing-group select the distribution field reveals is a
           .tom-select, and a full page has nothing else that would init it. */
        if (revealTarget && typeof initTomSelect === 'function') {
            initTomSelect(revealTarget);
        }
    });
}
window.initChoiceCards = initChoiceCards;

/*******************************
 * initChoiceSliders
 * Wires every slider-based choice inside `container` — the markup of
 * Elements/genericElementsBS5/Forms/choice_slider.ctp.
 *
 * The slider's own number is a position in the scale, never the value: option
 * `i` of the hidden <select> is what stop `i` posts, and the select stays the
 * one thing host forms read and listen on.
 *
 * Idempotent, like initChoiceCards.
 * @param {Element|Document} [container]  defaults to the whole document
 *******************************/
function initChoiceSliders(container) {
    var scope = container || document;

    scope.querySelectorAll('[data-choice-slider]').forEach(function (group) {
        if (group.dataset.choiceBound) { return; }
        group.dataset.choiceBound = '1';

        var select = group.querySelector('[data-choice-input]');
        var range = group.querySelector('[data-choice-slider-input]');
        var readout = group.querySelector('[data-slider-value]');
        var subLine = group.querySelector('[data-slider-sub]');
        var ticks = Array.prototype.slice.call(
            group.querySelectorAll('[data-slider-index]')
        );
        if (!select || !range || !select.options.length) { return; }

        var reveal = choiceRevealBinder(group);
        var last = select.options.length - 1;

        /* The stop's colour and gloss live on its tick, so repainting is a
           read off the DOM rather than a table shipped in a data attribute. */
        function paint(index) {
            var option = select.options[index];
            var tick = ticks[index];
            if (!option) { return; }

            group.style.setProperty(
                '--ov-slider-fill', (last > 0 ? (index / last) * 100 : 0) + '%'
            );
            group.style.setProperty(
                '--ov-slider-tone',
                (tick && tick.style.getPropertyValue('--ov-slider-tone'))
                    || 'var(--ov-slider-accent)'
            );

            if (readout) { readout.textContent = option.text; }
            if (subLine) { subLine.textContent = tick ? tick.dataset.sub : ''; }
            range.setAttribute('aria-valuetext', option.text);

            ticks.forEach(function (t, i) {
                t.classList.toggle('is-current', i === index);
            });
            reveal(option.value);
        }

        function pick(index) {
            var bounded = Math.max(0, Math.min(last, index));
            range.value = bounded;
            paint(bounded);
            if (select.selectedIndex === bounded) { return; }
            select.selectedIndex = bounded;
            /* Host forms listen on the select and on nothing else. */
            select.dispatchEvent(new Event('change', { bubbles: true }));
        }

        /* `input` for the drag, so the readout follows the thumb. */
        range.addEventListener('input', function () { pick(+range.value); });

        /* The tick labels are a mouse shortcut, not a control: the range is
           the focusable one, and it already reaches every stop by keyboard. */
        ticks.forEach(function (tick) {
            tick.addEventListener('click', function () {
                pick(+tick.dataset.sliderIndex);
                range.focus();
            });
        });

        /* Something setting the select directly (a template prefill) must not
           leave the slider behind. */
        select.addEventListener('change', function () {
            if (+range.value !== select.selectedIndex) {
                range.value = select.selectedIndex;
                paint(select.selectedIndex);
            }
        });

        paint(+range.value);
    });
}
window.initChoiceSliders = initChoiceSliders;

/**
 * The badge a choice_select draws beside an option — the same tile
 * renderDistOption/renderDistSelected build for the distribution selects, but
 * fed from the element's own glyph table instead of DIST_MAP, so a field that
 * is not distribution gets one too.
 *
 * @param {Object} entry  {icon, tone, toneBg} for the option, or null
 * @param {boolean} small the closed control's badge, tighter than a row's
 * @returns {HTMLElement|null}
 */
function choiceBadge(entry, small) {
    if (!entry || !entry.icon) { return null; }
    var badge = document.createElement('span');
    badge.className = 'badge d-inline-flex align-items-center '
        + (small ? 'px-1' : 'px-2 py-1');
    badge.style.background = entry.toneBg || 'transparent';
    badge.style.color = entry.tone || 'inherit';
    /* `33` is 20% alpha on the tone — the border every distribution badge in
       the theme wears. */
    badge.style.border = '1px solid ' + (entry.tone || 'transparent') + '33';
    if (small) { badge.style.fontSize = '.65rem'; }

    var icon = document.createElement('i');
    icon.className = entry.icon;
    badge.appendChild(icon);
    return badge;
}

/**
 * TomSelect render callback for a choice_select: the option's badge, then its
 * wording. `small` picks the closed control's tighter shape.
 */
function choiceSelectRenderer(glyphs, small) {
    return function (data) {
        var row = document.createElement('div');
        row.className = 'd-flex align-items-center '
            + (small ? 'gap-1' : 'gap-2 py-1');

        var badge = choiceBadge(glyphs[String(data.value)], small);
        if (badge) { row.appendChild(badge); }

        var label = document.createElement('span');
        /* textContent, not the escape() helper: the wording never reaches the
           DOM as markup, so nothing can be smuggled through an option title. */
        label.textContent = data.text;
        row.appendChild(label);
        return row;
    };
}

/*******************************
 * initChoiceSelects
 * Wires every compact choice inside `container` — the markup of
 * Elements/genericElementsBS5/Forms/choice_select.ctp, the one-line shape of
 * the same field the cards draw as tiles.
 *
 * It builds the TomSelect itself rather than leaving it to initTomSelect():
 * the badges are the whole point of this shape, and they live in the render
 * callbacks. Here the <select> is the control, not a mirror of one, so there is
 * no value to keep in sync — only the reveal the cards also drive.
 *
 * Idempotent, like initChoiceCards.
 * @param {Element|Document} [container]  defaults to the whole document
 *******************************/
function initChoiceSelects(container) {
    var scope = container || document;

    scope.querySelectorAll('[data-choice-select]').forEach(function (group) {
        if (group.dataset.choiceBound) { return; }
        group.dataset.choiceBound = '1';

        var select = group.querySelector('[data-choice-input]');
        if (!select) { return; }

        var glyphs = {};
        group.querySelectorAll('[data-choice-icon]').forEach(function (node) {
            glyphs[node.dataset.choiceIcon] = {
                icon: node.dataset.icon,
                tone: node.dataset.tone,
                toneBg: node.dataset.toneBg
            };
        });

        var reveal = choiceRevealBinder(group);
        var revealTarget = group.dataset.choiceRevealTarget
            ? document.querySelector(group.dataset.choiceRevealTarget)
            : null;

        function sync() {
            reveal(String(select.value));
        }

        if (typeof TomSelect === 'function' && !select.tomselect) {
            new TomSelect(select, {
                create: false,
                persist: false,
                render: {
                    option: choiceSelectRenderer(glyphs, false),
                    item: choiceSelectRenderer(glyphs, true)
                },
                onChange: sync
            });
        } else {
            select.addEventListener('change', sync);
        }
        sync();

        /* The sharing-group select this reveals is a .tom-select, and a full
           page has nothing else that would init it — same as the cards. */
        if (revealTarget && typeof initTomSelect === 'function') {
            initTomSelect(revealTarget);
        }
    });
}
window.initChoiceSelects = initChoiceSelects;

function initChoiceFields(container) {
    initChoiceCards(container);
    initChoiceSliders(container);
    initChoiceSelects(container);
}
window.initChoiceFields = initChoiceFields;

document.addEventListener('DOMContentLoaded', function () {
    initChoiceFields(document);
});

function initDistributionSelect(elId, onChange) {
    var el = document.getElementById(elId);
    if (!el || el.tomselect) { return; }
    new TomSelect(el, {
        create:   false,
        onChange: onChange || null,
        render: {
            option: renderDistOption,
            item:   renderDistSelected
        }
    });
}

function formTypeChanged(idPrefix) {
    var typeEl = document.getElementById(idPrefix + 'Type');
    if (!typeEl) { return; }
    var isNonCorr = (typeof non_correlating_types !== 'undefined')
        && non_correlating_types.indexOf(typeEl.value) !== -1;
    var corrEl = document.getElementById(idPrefix + 'DisableCorrelation');
    if (corrEl) { corrEl.disabled = isNonCorr; }
}

function checkNoticeList(type) {
    var fieldsToCheck = { attribute: ['category', 'type'] };
    var fields = fieldsToCheck[type];
    if (!fields) { return; }

    var triggers = (typeof notice_list_triggers !== 'undefined')
        ? notice_list_triggers : {};
    var base = (typeof baseurl !== 'undefined') ? baseurl : '';

    fields.forEach(function (fieldName) {
        var box = document.getElementById('notice_' + fieldName);
        if (!box) { return; }
        box.innerHTML = '';
        box.style.display = 'none';

        if (!(fieldName in triggers)) { return; }
        var elId = type.charAt(0).toUpperCase() + type.slice(1)
                 + fieldName.charAt(0).toUpperCase() + fieldName.slice(1);
        var el = document.getElementById(elId);
        if (!el || !(el.value in triggers[fieldName])) { return; }

        triggers[fieldName][el.value].forEach(function (notice) {
            var msg = (notice.message && notice.message.en)
                ? notice.message.en : '';

            var wrap = document.createElement('div');
            wrap.className = 'd-flex align-items-start gap-2 rounded-2 p-2 mt-1';
            wrap.style.cssText = 'background:rgba(13,110,253,.06);'
                + 'border:1px solid rgba(13,110,253,.25);font-size:.8rem;';

            /* innerHTML for static structure; textContent set below to avoid XSS */
            wrap.innerHTML =
                '<i class="fas fa-circle-info flex-shrink-0"'
                + ' style="color:var(--primary);margin-top:.15rem;"></i>'
                + '<div class="flex-fill" style="min-width:0;overflow:hidden;">'
                    + '<div class="d-flex align-items-center gap-1"'
                    + ' style="min-width:0;overflow:hidden;">'
                        + '<a class="fw-semibold text-decoration-none flex-shrink-0"'
                        + ' style="color:var(--primary);"></a>'
                        + '<span class="notice-preview" style="flex:1;min-width:0;'
                        + 'overflow:hidden;white-space:nowrap;'
                        + 'text-overflow:ellipsis;color:#666;"></span>'
                        + '<button type="button" style="background:none;border:none;'
                        + 'padding:0;color:var(--primary);cursor:pointer;'
                        + 'flex-shrink:0;">'
                        + '<i class="fas fa-chevron-down"'
                        + ' style="font-size:.7rem;"></i></button>'
                    + '</div>'
                    + '<div class="notice-full"'
                    + ' style="display:none;color:#666;margin-top:.2rem;"></div>'
                + '</div>';

            var link    = wrap.querySelector('a');
            var preview = wrap.querySelector('.notice-preview');
            var full    = wrap.querySelector('.notice-full');
            var btn     = wrap.querySelector('button');
            var chevron = btn.querySelector('i');

            link.href         = base + '/noticelists/view/' + notice.list_id;
            link.textContent  = notice.list_name;
            preview.textContent = msg;
            full.textContent    = msg;

            btn.addEventListener('click', function () {
                var expanded = btn.getAttribute('aria-expanded') === 'true';
                preview.style.display = expanded ? '' : 'none';
                full.style.display    = expanded ? 'none' : '';
                chevron.className     = expanded
                    ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
                btn.setAttribute('aria-expanded', String(!expanded));
            });

            box.appendChild(wrap);
            box.style.display = '';
        });
    });
}

function parseSeenDisplay(val) {
    if (!val) { return ''; }
    var m = val.trim().match(
        /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{1,2}))?$/
    );
    if (!m) { return ''; }
    return m[3]
        + '-'  + m[2].padStart(2, '0')
        + '-'  + m[1].padStart(2, '0')
        + 'T'  + (m[4] || '00').padStart(2, '0')
        + ':'  + (m[5] || '00').padStart(2, '0');
}
/*******************************
 * renderPaginator
 * Renders a pagination nav inside `el`.
 * Hides `el` (d-none) when pageCount <= 1.
 * @param {Element}  el         Container element
 * @param {number}   page       Current page (1-based)
 * @param {number}   pageCount  Total pages
 * @param {function} onPage     Callback(n) on page button click
 *******************************/
function renderPaginator(el, page, pageCount, onPage) {
    if (!el) { return; }
    if (pageCount <= 1) { el.classList.add('d-none'); return; }
    el.classList.remove('d-none');

    var maxShow = 5, half = Math.floor(maxShow / 2);
    var start = Math.max(1, page - half);
    var end   = Math.min(pageCount, start + maxShow - 1);
    if (end - start + 1 < maxShow) { start = Math.max(1, end - maxShow + 1); }

    function li(content, disabled, active, n) {
        var cls = 'page-item' + (disabled ? ' disabled' : '') + (active ? ' active' : '');
        if (disabled || active) {
            return '<li class="' + cls + '"><span class="page-link">' + content + '</span></li>';
        }
        return '<li class="' + cls + '">'
            + '<button type="button" class="page-link" data-pn="' + n + '">'
            + content + '</button></li>';
    }

    var items = li('<i class="fas fa-chevron-left"></i>', page <= 1, false, page - 1);
    if (start > 1) {
        items += li('1', false, false, 1);
        if (start > 2) { items += '<li class="page-item disabled"><span class="page-link">&hellip;</span></li>'; }
    }
    for (var i = start; i <= end; i++) { items += li(i, false, i === page, i); }
    if (end < pageCount) {
        if (end < pageCount - 1) { items += '<li class="page-item disabled"><span class="page-link">&hellip;</span></li>'; }
        items += li(pageCount, false, false, pageCount);
    }
    items += li('<i class="fas fa-chevron-right"></i>', page >= pageCount, false, page + 1);

    el.innerHTML = '<nav><ul class="pagination pagination-sm mb-0">' + items + '</ul></nav>';
    el.querySelectorAll('[data-pn]').forEach(function (btn) {
        btn.addEventListener('click', function () { onPage(parseInt(btn.dataset.pn, 10)); });
    });
}

/*******************************
 * toggleCollapsible
 * Toggles visibility of a target element via d-none.
 * Updates the button icon (chevron) and last text node.
 * @param {Element} btn        The trigger button
 * @param {string}  targetId   ID of element to show/hide
 * @param {string}  showLabel  Label shown when element is hidden
 * @param {string}  hideLabel  Label shown when element is visible
 *******************************/
function toggleCollapsible(btn, targetId, showLabel, hideLabel) {
    var el   = document.getElementById(targetId);
    var icon = btn.querySelector('i');
    if (!el) { return; }
    var isHidden = el.classList.contains('d-none');
    el.classList.toggle('d-none', !isHidden);
    if (icon) { icon.className = isHidden ? 'fas fa-chevron-up me-1' : 'fas fa-chevron-down me-1'; }
    var last = btn.lastChild;
    if (last && last.nodeType === 3) { last.textContent = ' ' + (isHidden ? hideLabel : showLabel); }
}

/*******************************
 * initAttributeForm
 * Bootstraps all interactive behaviour for Attributes/add and Attributes/edit.
 * Call once the DOM is ready: initAttributeForm(currentDist, isEdit)
 * @param {number}  currentDist  Initial distribution value (0–5)
 * @param {boolean} isEdit       True when editing an existing attribute
 *******************************/
function initAttributeForm(currentDist, isEdit) {

    /* Show/hide the sharing-group select */
    function toggleSg(val) {
        var sg = document.getElementById('attr-sg-container');
        if (sg) { sg.style.display = parseInt(val, 10) === 4 ? '' : 'none'; }
    }

    /* Checkbox-card colours for Batch / IDS / Correlation */
    var CARD_CFG = {
        AttributeBatchImport: {
            card: 'card-batch', icon: 'icon-batch',
            on:  { border: '#0d6efd', color: '#0d6efd', iconClass: null },
            off: { border: '#dee2e6', color: '#adb5bd', iconClass: null }
        },
        AttributeToIds: {
            card: 'card-ids', icon: 'icon-ids',
            on:  { border: '#ffc107', color: '#ffc107', iconClass: null },
            off: { border: '#dee2e6', color: '#adb5bd', iconClass: null }
        },
        AttributeDisableCorrelation: {
            card: 'card-correl', icon: 'icon-correl',
            on:  { border: '#dee2e6', color: '#adb5bd', iconClass: 'fas fa-link-slash' },
            off: { border: '#198754', color: '#198754', iconClass: 'fas fa-link' }
        }
    };

    function applyCardStyle(checkboxId) {
        var cfg  = CARD_CFG[checkboxId];
        if (!cfg) { return; }
        var cb   = document.getElementById(checkboxId);
        var card = document.getElementById(cfg.card);
        var icon = document.getElementById(cfg.icon);
        if (!cb || !card) { return; }
        var theme = cb.checked ? cfg.on : cfg.off;
        card.style.borderColor = theme.border;
        if (icon) {
            icon.style.color   = theme.color;
            icon.style.opacity = '1';
            if (theme.iconClass) { icon.className = theme.iconClass; }
        }
    }

    function setupCardListeners() {
        Object.keys(CARD_CFG).forEach(function (id) {
            var cb = document.getElementById(id);
            if (!cb) { return; }
            applyCardStyle(id);
            cb.addEventListener('change', function () { applyCardStyle(id); });
        });
    }

    /* Filter the Type TomSelect to the types allowed for the selected category */
    function applyTypeFilter(selectedCategory, preserveValue) {
        var typeEl  = document.getElementById('AttributeType');
        if (!typeEl) { return; }

        /* Capture current value before clearing options */
        var previousType = typeEl.value;

        var mapping = (typeof category_type_mapping !== 'undefined')
            ? category_type_mapping : {};
        var allowed = [];

        if (!selectedCategory || !mapping[selectedCategory]) {
            var seen = {};
            Object.keys(mapping).forEach(function (cat) {
                mapping[cat].forEach(function (t) {
                    if (!seen[t]) { seen[t] = true; allowed.push(t); }
                });
            });
        } else {
            allowed = mapping[selectedCategory].slice();
        }

        /* Value to select: keep previous on init, reset to empty on user change */
        var nextVal = (preserveValue && allowed.indexOf(previousType) !== -1)
            ? previousType : '';

        while (typeEl.options.length) { typeEl.remove(0); }
        typeEl.add(new Option('', ''));
        allowed.forEach(function (t) { typeEl.add(new Option(t, t)); });
        typeEl.value    = nextVal;
        typeEl.disabled = false;

        if (typeEl.tomselect) {
            var ts = typeEl.tomselect;
            ts.clear(true);
            ts.clearOptions();
            ts.addOption({ value: '', text: '' });
            ts.addOptions(allowed.map(function (t) { return { value: t, text: t }; }));
            ts.setValue(nextVal, true);
            ts.refreshItems();
        }

        formTypeChanged('Attribute');
    }

    /* TomSelect: Category */
    function initCategorySelect() {
        var el = document.getElementById('AttributeCategory');
        if (!el || el.tomselect) { return; }
        new TomSelect(el, {
            create: false,
            onChange: function (val) {
                applyTypeFilter(val);
                if (val === 'Internal reference') {
                    var distEl = document.getElementById('AttributeDistribution');
                    if (distEl && distEl.tomselect) {
                        distEl.tomselect.setValue('0');
                    } else {
                        toggleSg(0);
                    }
                }
                checkNoticeList('attribute');
            }
        });
    }

    /* TomSelect: Type */
    function initTypeSelect() {
        var el = document.getElementById('AttributeType');
        if (!el || el.tomselect) { return; }
        new TomSelect(el, {
            create: false,
            onChange: function () {
                formTypeChanged('Attribute');
                checkNoticeList('attribute');
            }
        });
    }

    /* datetime-local pickers → hidden YYYY-MM-DD HH:MM:SS fields */
    function setupTemporalInputs() {
        [['attr-first-seen-picker', 'AttributeFirstSeen'],
         ['attr-last-seen-picker',  'AttributeLastSeen']].forEach(function (pair) {
            var picker = document.getElementById(pair[0]);
            var hidden = document.getElementById(pair[1]);
            if (!picker || !hidden) { return; }
            picker.addEventListener('change', function () {
                hidden.value = picker.value ? picker.value.replace('T', ' ') : '';
            });
        });
    }

    /* Live format validation of the Value field against the selected Type.
     * Reuses the server-side AttributeValidationTool via an AJAX endpoint so
     * the rules stay in sync with what MISP will actually accept. */
    function setupValueValidation() {
        var valueEl = document.getElementById('AttributeValue');
        var typeEl  = document.getElementById('AttributeType');
        if (!valueEl || !typeEl) { return; }

        var batchEl = document.getElementById('AttributeBatchImport');
        var form    = valueEl.form || (valueEl.closest && valueEl.closest('form'));
        var base    = (typeof baseurl !== 'undefined') ? baseurl : '';
        var errorId = 'AttributeValueError';
        var lastValid = true;   // best-effort submit guard
        var seq = 0;            // ignore out-of-order responses

        function showError(message) {
            lastValid = false;
            valueEl.style.borderColor = '#dc3545';
            var msg = document.getElementById(errorId);
            if (!msg) {
                msg = document.createElement('div');
                msg.id        = errorId;
                msg.className  = 'text-danger d-flex align-items-start gap-1 mt-1';
                msg.style.fontSize = '.75rem';
                var icon = document.createElement('i');
                icon.className = 'fas fa-circle-exclamation';
                icon.style.marginTop = '.15rem';
                msg.appendChild(icon);
                msg.appendChild(document.createElement('span'));
                valueEl.parentNode.appendChild(msg);
            }
            msg.querySelector('span').textContent = message;
        }

        function clearError() {
            lastValid = true;
            valueEl.style.borderColor = '#d8dde3';
            var msg = document.getElementById(errorId);
            if (msg) { msg.remove(); }
        }

        function validate() {
            var value = valueEl.value;
            var type  = typeEl.value;
            if (!type || !value.trim()) { clearError(); return; }

            var mySeq = ++seq;
            var params = new URLSearchParams();
            params.append('type', type);
            params.append('value', value);
            if (batchEl && batchEl.checked) { params.append('batch', '1'); }

            fetch(base + '/attributes/validateValue', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                },
                body: params.toString()
            })
                .then(function (r) { return r.json(); })
                .then(function (res) {
                    if (mySeq !== seq) { return; } // a newer check superseded this
                    if (res && res.valid === false) {
                        showError(res.message
                            || 'The value does not match the expected format.');
                    } else {
                        clearError();
                    }
                })
                .catch(function () { /* network issue: don't block the user */ });
        }

        valueEl.addEventListener('blur', validate);
        valueEl.addEventListener('input', function () {
            /* remove stale error while the user is fixing the value */
            if (!lastValid) { clearError(); }
        });
        typeEl.addEventListener('change', validate);
        if (batchEl) { batchEl.addEventListener('change', validate); }

        /* Block submission only when we already know the value is invalid. */
        if (form) {
            form.addEventListener('submit', function (e) {
                if (!lastValid && valueEl.value.trim() && typeEl.value) {
                    e.preventDefault();
                    e.stopPropagation();
                    valueEl.focus();
                }
            });
        }
    }

    initCategorySelect();
    initTypeSelect();
    initDistributionSelect('AttributeDistribution', function (val) { toggleSg(val); });
    setupCardListeners();
    setupTemporalInputs();
    setupValueValidation();
    if (typeof initCollectionForm === 'function') { initCollectionForm(document); }

    toggleSg(currentDist);
    var initCat = document.getElementById('AttributeCategory');
    applyTypeFilter(initCat ? initCat.value : '', true);
    if (isEdit) { checkNoticeList('attribute'); }
}

/*******************************
 * Events/add and Events/edit
 *
 * initEventForm(container) wires the event form inside `container` (default:
 * the document) and binds nothing outside it, so it is safe on a modal body,
 * on a full page, and twice on either.
 *
 * What it owns:
 *   - the three choice_cards groups (distribution, analysis, threat level)
 *   - the extends-event preview
 *   - the DD/MM/YYYY date field over its ISO hidden twin
 *   - required-field validation, and a submit that cannot fire twice
 *
 * The field look — the underline, the box, the invalid state — lives in
 * mainOvermind.css under `.ov-form-*`; nothing here writes a style.
 *******************************/
function initEventForm(container) {
    /* Takes the form itself, any container holding it, or nothing at all. */
    var scope = (container && container.querySelector) ? container : document;
    var form = (scope.matches && scope.matches('#EventForm'))
        ? scope
        : scope.querySelector('#EventForm');
    if (!form || form.dataset.eventFormBound) { return; }
    form.dataset.eventFormBound = '1';

    var base = (typeof baseurl === 'string') ? baseurl : '';

    /* ── Invalid state ───────────────────────────────────────────
     * One place decides what a rejected field looks like: the class on the
     * field (or on the box around it) and one message under its group. */
    function fieldGroup(el) {
        return el.closest('.ov-form-group') || el.parentNode;
    }

    function markInvalid(el, message) {
        (el.closest('.ov-form-box') || el).classList.add('is-invalid-field');
        var group = fieldGroup(el);
        var msg = group.querySelector('.ov-field-error');
        if (!msg) {
            msg = document.createElement('div');
            msg.className = 'ov-field-error';
            var icon = document.createElement('i');
            icon.className = 'fas fa-circle-exclamation';
            var text = document.createElement('span');
            msg.appendChild(icon);
            msg.appendChild(text);
            group.appendChild(msg);
        }
        msg.querySelector('span').textContent = message;
    }

    function markValid(el) {
        (el.closest('.ov-form-box') || el).classList.remove('is-invalid-field');
        var msg = fieldGroup(el).querySelector('.ov-field-error');
        if (msg) { msg.remove(); }
    }

    /* A validator returns the element to focus when the field is wrong, and
     * null when it is fine; the submit handler collects them all. */
    var validators = [];

    /* ── Event info ──────────────────────────────────────────── */
    function bindInfo() {
        var info = form.querySelector('#EventInfo');
        if (!info) { return; }
        var message = info.dataset.requiredMsg
            || 'Please provide a name for the event.';

        function validate(quiet) {
            if (info.value.trim()) {
                markValid(info);
                return null;
            }
            if (!quiet) { markInvalid(info, message); }
            return info;
        }

        /* Only ever clears while typing: nagging about an empty field the user
         * has not finished with is what the submit check is for. */
        info.addEventListener('input', function () {
            if (info.value.trim()) { markValid(info); }
        });
        validators.push(validate);
    }

    /* ── Extends-event preview ───────────────────────────────────
     * The field takes an id or a UUID; the endpoint answers with a card for
     * the matched event, or a note saying nothing matched. */
    function bindExtendsPreview() {
        var input = form.querySelector('#EventExtendsUuid');
        var preview = form.querySelector('#event_preview');
        if (!input || !preview) { return; }

        var IS_ID = /^[0-9]+$/;
        var IS_UUID =
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        var timer = null;
        var pending = null;

        function hide() {
            preview.classList.add('d-none');
            preview.innerHTML = '';
        }

        function request(value) {
            /* One lookup at a time: the answers are rendered HTML, so a slow
             * early request must not land on top of a later one. */
            if (pending) { pending.abort(); }
            pending = new AbortController();
            preview.setAttribute('aria-busy', 'true');
            fetch(base + '/events/getEventInfoById/' + encodeURIComponent(value), {
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
                signal: pending.signal
            })
                .then(function (r) { return r.ok ? r.text() : ''; })
                .then(function (html) {
                    preview.removeAttribute('aria-busy');
                    if (!html.trim()) { hide(); return; }
                    preview.innerHTML = html;
                    preview.classList.remove('d-none');
                })
                .catch(function (err) {
                    if (err.name === 'AbortError') { return; }
                    preview.removeAttribute('aria-busy');
                    hide();
                });
        }

        function schedule() {
            clearTimeout(timer);
            var value = input.value.trim();
            /* Nothing but a whole id or a whole UUID can match, and a UUID
             * typed by hand would otherwise cost 36 lookups on its way in. */
            if (!IS_ID.test(value) && !IS_UUID.test(value)) {
                if (pending) { pending.abort(); pending = null; }
                hide();
                return;
            }
            timer = setTimeout(function () { request(value); }, 250);
        }

        input.addEventListener('input', schedule);

        /* Delegated, so the card stays clickable through every re-render:
         * clicking it swaps the id the user typed for the event's UUID. */
        preview.addEventListener('click', function (e) {
            var card = e.target.closest('.js-extends-event-card');
            if (!card || !card.dataset.extendsUuid) { return; }
            input.value = card.dataset.extendsUuid;
        });

        schedule();
    }

    /* ── Event date ──────────────────────────────────────────────
     * DD/MM/YYYY in front of the user, YYYY-MM-DD in the hidden field MISP
     * actually reads. */
    function bindDate() {
        var display = form.querySelector('#EventDateDisplay');
        var hidden = form.querySelector('#EventDate');
        if (!display || !hidden) { return; }

        var message = display.dataset.invalidMsg
            || 'Enter the event date as DD/MM/YYYY.';

        function pad(n) { return (n < 10 ? '0' : '') + n; }

        function build(y, m, d) {
            var date = new Date(Date.UTC(y, m - 1, d));
            /* Date() rolls 31/02 over into March, so compare the parts back:
             * that is what rejects a day the month does not have. */
            if (date.getUTCFullYear() !== y
                    || date.getUTCMonth() !== m - 1
                    || date.getUTCDate() !== d) {
                return null;
            }
            return date;
        }

        function parse(text) {
            var value = text.trim();
            var human = value.match(/^(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{4})$/);
            if (human) {
                return build(+human[3], +human[2], +human[1]);
            }
            /* Also accept what the hidden field speaks, so pasting an ISO date
             * out of MISP itself works. */
            var iso = value.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
            return iso ? build(+iso[1], +iso[2], +iso[3]) : null;
        }

        function sync() {
            var date = parse(display.value);
            if (date) {
                hidden.value = date.getUTCFullYear() + '-'
                    + pad(date.getUTCMonth() + 1) + '-'
                    + pad(date.getUTCDate());
                markValid(display);
            }
            return date;
        }

        display.addEventListener('input', sync);

        /* Normalise on the way out: 3/9/2026 leaves as 03/09/2026, and only
         * here does a half-typed date get called wrong. */
        display.addEventListener('blur', function () {
            var date = sync();
            if (date) {
                display.value = pad(date.getUTCDate()) + '/'
                    + pad(date.getUTCMonth() + 1) + '/'
                    + date.getUTCFullYear();
            } else if (display.value.trim()) {
                markInvalid(display, message);
            }
        });

        validators.push(function (quiet) {
            var date = sync();
            if (date) { return null; }
            if (!quiet) { markInvalid(display, message); }
            return display;
        });
    }

    /* ── Submit ──────────────────────────────────────────────── */
    function bindSubmit() {
        var button = form.querySelector('#EventSubmitButton');

        form.addEventListener('submit', function (e) {
            var wrong = validators
                .map(function (validate) { return validate(false); })
                .filter(Boolean);

            if (wrong.length) {
                /* preventDefault alone: a listener elsewhere may still want to
                 * know the form was submitted and turned down. */
                e.preventDefault();
                wrong[0].focus();
                return;
            }

            /* The form navigates away on success, so the only thing a second
             * click can do is create the event twice. */
            if (button) {
                button.disabled = true;
                var icon = button.querySelector('i');
                if (icon) { icon.className = 'fas fa-circle-notch fa-spin me-1'; }
            }
        });
    }

    initChoiceFields(form);
    bindInfo();
    bindExtendsPreview();
    bindDate();
    bindSubmit();
}
window.initEventForm = initEventForm;

/*******************************
 * updateActiveFilterBadge
 * Injects a dismissible "Active filters" row below the filter bar for AJAX
 * tab indexes. Removes any existing badge when searchTerm is empty.
 * @param {Element}  container     Tab container element
 * @param {string}   searchTerm    Current search value; '' removes the badge
 * @param {function} clearCb       Called when the user clicks the Clear button
 * @param {string}   [labelActive] "Active filters" label (default: English)
 * @param {string}   [labelClear]  Clear button label (default: English)
 *******************************/
function updateActiveFilterBadge(container, searchTerm, clearCb, labelActive, labelClear) {
    var existing = container.querySelector('#overmind-active-filter');
    if (existing) existing.remove();
    if (!searchTerm) return;

    var filterBar = container.querySelector('[id^="filter-bar-"]');
    if (!filterBar) return;

    var wrap = document.createElement('div');
    wrap.id = 'overmind-active-filter';
    wrap.className = 'mt-2 d-flex align-items-center flex-wrap gap-2';

    var lbl = document.createElement('strong');
    lbl.className = 'me-1';
    lbl.textContent = (labelActive || 'Active filters') + ':';

    var chip = document.createElement('span');
    chip.className = 'badge bg-primary';
    chip.textContent = 'search: ' + searchTerm;

    var clearBtn = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.className = 'btn btn-sm btn-outline-danger ms-auto';
    clearBtn.innerHTML = '<i class="fas fa-times me-1"></i>';
    clearBtn.appendChild(document.createTextNode(labelClear || 'Clear'));
    clearBtn.addEventListener('click', clearCb);

    wrap.appendChild(lbl);
    wrap.appendChild(chip);
    wrap.appendChild(clearBtn);
    filterBar.insertAdjacentElement('afterend', wrap);
}


/**
 * Auto-dismiss the flash messages after 5s.
 *
 */
function initFlashAutoDismiss() {
    const flash = document.getElementById('flashContainer');
    if (!flash || flash.children.length === 0) return;

    setTimeout(function () {
        flash.classList.add('fade-out');
        setTimeout(function () {
            flash.innerHTML = '';
            flash.classList.remove('fade-out');
        }, 600);
    }, 5000);
}

/**
 * Move Cake's debug output into the collapsible debug strip and badge the
 * error count. No-op unless the layout emitted the strip (debug > 0).
 */
function initDebugStrip() {
    const container = document.getElementById('debugAccordionContent');
    if (!container) return;

    const cakeErrors = document.querySelectorAll('.cake-error');
    const count = cakeErrors.length;
    const badge = document.getElementById('debugErrorBadge');

    if (badge) {
        badge.textContent = count + ' error' + (count > 1 ? 's' : '');
        badge.classList.remove(count > 0 ? 'bg-success' : 'bg-danger');
        badge.classList.add(count > 0 ? 'bg-danger' : 'bg-success');
    }

    cakeErrors.forEach(error => container.appendChild(error));
}

/**
 * Turn the filter-bar selects into TomSelect widgets.
 *
 * Scoped so that fragments injected after page load (an .ajax-tab-content
 * index, a modal body) can initialise their own selects, and idempotent so a
 * second pass over the same scope is a no-op.
 *
 * Both guards are needed. TomSelect copies the original element's classes
 * onto the .ts-wrapper <div> it builds, so a bare `.topbar-filter` query
 * matches that wrapper too on a second pass — and the wrapper carries no
 * `.tomselect` back-reference, so it would be handed to TomSelect as if it
 * were a fresh control (which throws). Hence: select elements only, and skip
 * the ones TomSelect already owns.
 *
 * @param {ParentNode} scope defaults to the whole document
 */
function initTopbarFilterSelects(scope) {
    if (typeof TomSelect === 'undefined') return;

    const selects = (scope || document).querySelectorAll('select.topbar-filter');
    selects.forEach(function (el) {
        if (el.tomselect) return;
        new TomSelect(el, {
            create: false,
            sortField: { field: 'text', direction: 'asc' }
        });
    });
}

/**
 * Fetch an ajax container's URL into it, once, and run the scripts it brings.
 *
 * @param {Element} container carries data-url, gains data-loaded
 */
function loadAjaxContainer(container) {
    if (!container || container.dataset.loaded) return;

    const url = container.dataset.url;
    if (!url) return;

    fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
        .then(res => {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.text();
        })
        .then(html => {
            container.innerHTML = html;
            container.dataset.loaded = '1';

            // innerHTML does not execute <script>, so re-create each one.
            container.querySelectorAll('script').forEach(function (oldScript) {
                const newScript = document.createElement('script');
                if (oldScript.src) {
                    newScript.src = oldScript.src;
                } else {
                    newScript.textContent = oldScript.textContent;
                }
                document.head.appendChild(newScript);
                document.head.removeChild(newScript);
            });

            initTopbarFilterSelects(container);
        })
        .catch(() => {
            container.innerHTML =
                '<div class="text-danger">Error loading content</div>';
        });
}

/**
 * Reload an already-loaded ajax index container against a new (filtered,
 * sorted or paginated) URL, keeping the user inside the current tab instead
 * of navigating the whole page. Called by IndexTable/filter_bar.
 *
 * @param {Element} container
 * @param {string} url
 */
window.reloadAjaxTabIndex = function (container, url) {
    if (!container || !url) return;
    container.dataset.url = url;
    delete container.dataset.loaded;
    container.innerHTML =
        '<div class="text-center p-4"><div class="spinner-border"></div></div>';
    loadAjaxContainer(container);
};

// Lazy-load a tab's ajax content the first time it is shown, and drop the
// selection state of the tab being left so its checkboxes don't bleed into
// the newly active tab's mass-select toolbar.
document.addEventListener('shown.bs.tab', function (event) {
    const target = event.target.getAttribute('data-bs-target')
        || event.target.getAttribute('href');
    const tabPane = target ? document.querySelector(target) : null;
    if (!tabPane) return;

    const prevTarget = event.relatedTarget
        ? (event.relatedTarget.getAttribute('data-bs-target')
            || event.relatedTarget.getAttribute('href'))
        : null;
    const prevPane = prevTarget ? document.querySelector(prevTarget) : null;
    if (prevPane) {
        prevPane.querySelectorAll('.item-checkbox:checked').forEach(function (cb) {
            cb.checked = false;
        });
    }
    if (typeof selectedItems !== 'undefined') {
        selectedItems.clear();
    }
    if (typeof updateMultiSelectToolbar === 'function') {
        updateMultiSelectToolbar();
    }

    tabPane.querySelectorAll('.ajax-tab-content').forEach(loadAjaxContainer);
});

/**
 * Session watchdog — send the user to the login page once their session is
 * gone, instead of leaving them on a page whose every action will bounce.
 *
 * Enabled by the layout (window.mispAutoLogout) when MISP.disable_auto_logout
 * is off and someone is logged in.
 *
 */
function initSessionWatchdog() {
    if (!window.mispAutoLogout || typeof baseurl === 'undefined') return;

    const MIN_INTERVAL = 10000; // don't re-check on every focus flicker
    let lastCheck = 0;
    let inFlight = false;

    function check() {
        if (document.hidden || inFlight) return;

        const now = Date.now();
        if (now - lastCheck < MIN_INTERVAL) return;
        lastCheck = now;
        inFlight = true;

        // Measured against the endpoint (session cookie, X-Requested-With):
        //   authenticated -> 200
        //   session gone  -> 401 (the ajax pre-auth branch)
        // The `.json` form answers 200/403 instead, but routes through
        // AppController's REST branch, which authenticates by Authorization
        // header rather than by session — so the plain URL is the narrower
        // question to ask. 403 and a follow-through to /users/login are
        // accepted too, since both mean the same thing.
        fetch(baseurl + '/users/checkIfLoggedIn', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            cache: 'no-store'
        })
            .then(res => {
                const loggedOut = res.status === 401
                    || res.status === 403
                    || (res.redirected && /\/users\/login/.test(res.url));
                if (loggedOut) {
                    window.location.replace(baseurl + '/users/login');
                }
            })
            // A network blip must not throw the user out.
            .catch(() => {})
            .finally(() => { inFlight = false; });
    }

    document.addEventListener('visibilitychange', function () {
        if (!document.hidden) check();
    });
    window.addEventListener('focus', check);
}

document.addEventListener('DOMContentLoaded', function () {
    initFlashAutoDismiss();
    initDebugStrip();
    initTopbarFilterSelects();
    initSessionWatchdog();
    // The tab that is already active gets no shown.bs.tab event.
    document.querySelectorAll('.tab-pane.active .ajax-tab-content')
        .forEach(loadAjaxContainer);
});



/* ==========================================================================
 * Index URLs
 * ==========================================================================
 *
 * MISP indexes carry their state in CakePHP named URL segments
 * (`/events/index/sort:date/searchpublished:1`), sometimes next to positional
 * scope arguments (`/authKeys/index/<userId>`) and sometimes in the query
 * string instead (a value holding a '/' cannot survive a named segment).
 * Five places used to split that apart by hand with the same
 * `split('/')` / `indexOf(':')` dance; this is that dance, once.
 */

/**
 * @param {string} url       absolute or root-relative, query string included
 * @param {string} itemPath  the index path the segments follow, e.g. '/events/index'
 * @returns {{positional: string[], named: Object, query: URLSearchParams, path: string}}
 */
function parseIndexUrl(url, itemPath) {
    // One side is often absolute (a config's baseurl) and the other not (what
    // popstate hands over), so compare paths, never whole URLs.
    const stripOrigin = function (u) { return (u || '').replace(/^[a-z]+:\/\/[^/]+/i, ''); };
    url = stripOrigin(url);
    itemPath = stripOrigin(itemPath);

    const cut = url.indexOf('?');
    const path = cut === -1 ? url : url.slice(0, cut);
    const query = new URLSearchParams(cut === -1 ? '' : url.slice(cut + 1));
    const positional = [];
    const named = {};

    const at = itemPath ? path.indexOf(itemPath) : -1;
    const after = at !== -1 ? path.slice(at + itemPath.length) : '';
    after.split('/').filter(Boolean).forEach(function (segment) {
        const colon = segment.indexOf(':');
        if (colon < 0) {
            positional.push(segment);
        } else {
            named[segment.slice(0, colon)] = decodeURIComponent(segment.slice(colon + 1));
        }
    });
    return { positional: positional, named: named, query: query, path: path };
}

/**
 * The inverse. Named values are encoded here, so callers hand over raw ones.
 *
 * @param {string} base                 index URL with no state on it
 * @param {Object} parts                { positional, named, query }
 * @returns {string}
 */
function formatIndexUrl(base, parts) {
    let url = base;
    (parts.positional || []).forEach(function (segment) { url += '/' + segment; });
    const named = parts.named || {};
    Object.keys(named).forEach(function (key) {
        url += '/' + key + ':' + encodeURIComponent(named[key]);
    });
    const query = parts.query ? parts.query.toString() : '';
    return url + (query ? '?' + query : '');
}

/* ==========================================================================
 * Index filter bars — deferred apply
 * ==========================================================================
 *
 * The code snippets provided here create a *draft* using pills: \
 * his will be executed via a single button using Ajax, refreshing the container 
 *
 * Two bars share this engine — Elements/Logs/filter_card.ctp (the log
 * indexes) and genericElementsBS5/IndexTable/filter_bar.ctp (a scaffolded
 * index that declares a `more_filters` control). They agree on the
 * interaction and disagree on everything around it: where a filter lives in
 * the URL, what counts as a scope worth keeping, whether an ajax tab wraps
 * the whole thing. So every URL decision is the caller's, handed in as
 * `buildUrl` / `clearAll` / `reload`.
 */

/**
 * @param {Element} root  element owning the controls; marked as wired
 * @param {Object}  opts
 *   Required:
 *     inputs()       -> Element[]     the controls the draft is read from
 *     nameOf(el)     -> string        that control's filter name
 *     buildUrl()     -> string        URL for the current draft
 *     summaryEl      Element          where the chips and buttons are drawn
 *   Optional:
 *     labelOf(name)          -> string   chip label      (default: the name)
 *     displayOf(name, value) -> string   chip value      (default: the value)
 *     quickEl                Element     free-text box outside the draft grid
 *     quickLabel             string      its chip label
 *     applied / appliedQuick             what the page currently shows
 *     countEl                Element     badge showing how many filters are set
 *     results                string      selector of the container to swap
 *     swap                   string[]    other nodes to refresh from the response
 *     rootLinks / resultLinks string[]   links to keep inside the ajax loop
 *     syncFromUrl(url)                   read a URL back into the controls
 *     clearAll()                         reset the controls ("Clear all")
 *     reload(url)            -> bool     take over the reload (ajax tabs)
 *     onApplied()                        after a successful swap
 *     strings                object      see S below
 * @returns {Object|null} { refresh } so a caller can redraw the chips
 */
function initIndexFilterDraft(root, opts) {
    if (!root || root.dataset.filterDraftReady || !opts || !opts.summaryEl) { return null; }
    root.dataset.filterDraftReady = '1';

    const S = opts.strings || {};
    const summaryEl = opts.summaryEl;
    const results = opts.results ? document.querySelector(opts.results) : null;

    // What the page currently shows. Replaced on every successful apply, so
    // the chips can tell an applied filter from one still being typed.
    let applied = Object.assign({}, opts.applied || {});
    let appliedQuick = opts.appliedQuick || '';
    let inFlight = null;

    /* ── draft state ─────────────────────────────────────────────────── */

    function inputs() { return opts.inputs(); }

    function draft() {
        const out = {};
        inputs().forEach(function (el) {
            const name = opts.nameOf(el);
            const value = (el.value || '').trim();
            if (name && value !== '') { out[name] = value; }
        });
        return out;
    }

    function draftQuick() {
        return opts.quickEl ? (opts.quickEl.value || '').trim() : '';
    }

    function labelFor(name) {
        return opts.labelOf ? opts.labelOf(name) : name;
    }

    // A select stores `remove_tag` but the user picked "Remove tag".
    function displayFor(name, value) {
        return opts.displayOf ? opts.displayOf(name, value) : value;
    }

    // TomSelect keeps its own DOM, so the underlying <select> alone is not enough.
    function setValue(el, value) {
        if (el.tomselect) {
            el.tomselect.setValue(value, true);
        } else {
            el.value = value;
        }
    }

    /* ── chips ───────────────────────────────────────────────────────── */

    function chip(label, value, state) {
        const el = document.createElement('span');
        el.className = 'badge d-inline-flex align-items-center gap-1 '
            + (state === 'removed'
                ? 'text-bg-light border border-danger text-danger text-decoration-line-through'
                : state === 'pending'
                    ? 'text-bg-warning border border-warning-subtle'
                    : 'bg-primary');
        if (state === 'pending') {
            el.title = S.notApplied || '';
            el.insertAdjacentHTML('beforeend', '<i class="fas fa-clock"></i>');
        } else if (state === 'removed') {
            el.title = S.willBeRemoved || '';
        }
        el.insertAdjacentText('beforeend', label + ': ' + value);
        return el;
    }

    function removeButton(chipEl, onClick) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn-close btn-close-sm ms-1';
        btn.style.fontSize = '.5rem';
        btn.title = S.remove || '';
        btn.addEventListener('click', onClick);
        chipEl.appendChild(btn);
    }

    function renderSummary() {
        const current = draft();
        const quick = draftQuick();
        let pending = 0;

        summaryEl.textContent = '';

        const chips = document.createElement('div');
        chips.className = 'd-flex align-items-center flex-wrap gap-2 flex-grow-1';

        if (opts.quickEl) {
            if (quick !== '') {
                const state = quick === appliedQuick ? 'applied' : 'pending';
                if (state === 'pending') { pending++; }
                const c = chip(opts.quickLabel || '', quick, state);
                removeButton(c, function () { opts.quickEl.value = ''; renderSummary(); });
                chips.appendChild(c);
            } else if (appliedQuick !== '') {
                pending++;
                chips.appendChild(chip(opts.quickLabel || '', appliedQuick, 'removed'));
            }
        }

        Object.keys(current).forEach(function (name) {
            const state = current[name] === applied[name] ? 'applied' : 'pending';
            if (state === 'pending') { pending++; }
            const c = chip(labelFor(name), displayFor(name, current[name]), state);
            removeButton(c, function () {
                inputs().forEach(function (el) {
                    if (opts.nameOf(el) === name) { setValue(el, ''); }
                });
                renderSummary();
            });
            chips.appendChild(c);
        });

        Object.keys(applied).forEach(function (name) {
            if (current[name] === undefined) {
                pending++;
                chips.appendChild(chip(labelFor(name), displayFor(name, applied[name]), 'removed'));
            }
        });

        // Filters that are applied but have no control here — the scope a
        // button like "My events" puts in the URL. Read-only, but visible:
        // without a chip the only sign they are on is the row count.
        const extras = opts.extraChips ? opts.extraChips() : [];
        extras.forEach(function (extra) {
            chips.appendChild(chip(extra.label, extra.value, 'applied'));
        });

        if (!chips.children.length) {
            const empty = document.createElement('span');
            empty.className = 'text-muted small filter-draft-empty';
            empty.textContent = S.noFilter || '';
            chips.appendChild(empty);
        }

        summaryEl.appendChild(buildBar(chips, pending, extras.length));

        if (opts.countEl) {
            // Everything that filters counts, not just the controls in the
            // panel: with the panel folded away the badge is the only thing
            // saying a search or a scope is still on.
            const n = Object.keys(current).length + (quick !== '' ? 1 : 0) + extras.length;
            opts.countEl.textContent = String(n);
            opts.countEl.classList.toggle('d-none', n === 0);
        }
    }

    function buildBar(chips, pending, extraCount) {
        const bar = document.createElement('div');
        bar.className = 'd-flex align-items-start flex-wrap gap-2';
        bar.appendChild(chips);

        const status = document.createElement('span');
        status.className = 'small align-self-center filter-draft-status '
            + (pending ? 'text-warning-emphasis fw-semibold' : 'text-muted');
        status.textContent = pending
            ? (pending === 1 ? S.pendingOne : (S.pendingMany || '').replace('%s', pending))
            : S.applied;
        bar.appendChild(status);

        const applyBtn = document.createElement('button');
        applyBtn.type = 'button';
        applyBtn.className = 'btn btn-sm ' + (pending ? 'btn-primary' : 'btn-outline-primary');
        applyBtn.innerHTML = '<i class="fas fa-filter me-1"></i>' + S.apply;
        applyBtn.addEventListener('click', apply);
        bar.appendChild(applyBtn);

        // Extras count too: a scope set from a button outside this panel is
        // still a filter the user has to be able to drop.
        if (Object.keys(applied).length || appliedQuick !== '' || extraCount) {
            const clearBtn = document.createElement('button');
            clearBtn.type = 'button';
            clearBtn.className = 'btn btn-sm btn-outline-danger';
            clearBtn.innerHTML = '<i class="fas fa-times me-1"></i>' + S.clearAll;
            clearBtn.addEventListener('click', function () {
                if (opts.clearAll) {
                    opts.clearAll();
                } else {
                    if (opts.quickEl) { opts.quickEl.value = ''; }
                    inputs().forEach(function (el) { setValue(el, ''); });
                }
                apply();
            });
            bar.appendChild(clearBtn);
        }
        return bar;
    }

    /* ── applying ────────────────────────────────────────────────────── */

    function apply() {
        load(opts.buildUrl(), true);
    }

    function setBusy(busy) {
        root.classList.toggle('filter-draft-busy', busy);
        if (!results) { return; }
        results.classList.toggle('is-busy', busy);
        let overlay = results.querySelector(':scope > .index-results-overlay');
        if (busy && !overlay) {
            overlay = document.createElement('div');
            overlay.className = 'index-results-overlay';
            overlay.innerHTML = '<div class="spinner-border text-primary" role="status"></div>';
            results.appendChild(overlay);
        } else if (!busy && overlay) {
            overlay.remove();
        }
    }

    /**
     * Fetch a filtered/sorted/paged version of this index and swap in its
     * results. The whole page is requested rather than a fragment — the
     * layout is cheap next to the queries these filters cost, and it keeps
     * the views free of an ajax branch — but only the results and the nodes
     * named in `swap` are taken out of the response, so the live filter bar
     * (and its TomSelect instances) is never rebuilt.
     */
    function load(url, push) {
        // An ajax tab reloads its own fragment, bar included, and comes back
        // with the server's state — nothing to keep in sync here.
        if (opts.reload && opts.reload(url)) { return; }
        if (!results) { window.location.href = url; return; }
        if (inFlight) { inFlight.abort(); }
        const controller = new AbortController();
        inFlight = controller;
        setBusy(true);

        fetch(url, { credentials: 'same-origin', signal: controller.signal })
            .then(function (response) {
                if (!response.ok) { throw new Error('HTTP ' + response.status); }
                return response.text();
            })
            .then(function (html) {
                const doc = new DOMParser().parseFromString(html, 'text/html');
                const fresh = doc.querySelector(opts.results);
                if (!fresh) { throw new Error('no results container in response'); }

                results.innerHTML = fresh.innerHTML;
                (opts.swap || []).forEach(function (selector) { swap(doc, selector); });

                if (push) { history.pushState({ indexFilter: true }, '', url); }
                if (opts.syncFromUrl) { opts.syncFromUrl(url); }
                applied = draft();
                appliedQuick = draftQuick();
                renderSummary();
                bindNavLinks();
                // Rows the selection pointed at are gone.
                if (window.selectedItems && typeof selectedItems.clear === 'function') {
                    selectedItems.clear();
                    if (typeof updateMultiSelectToolbar === 'function') { updateMultiSelectToolbar(); }
                }
                if (typeof initTomSelect === 'function') { initTomSelect(results); }
                if (opts.onApplied) { opts.onApplied(); }
                results.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            })
            .catch(function (error) {
                if (error.name === 'AbortError') { return; }
                showLoadError();
            })
            .finally(function () {
                if (inFlight === controller) { inFlight = null; setBusy(false); }
            });
    }

    function swap(doc, selector) {
        const target = document.querySelector(selector);
        const fresh = doc.querySelector(selector);
        if (target && fresh) { target.innerHTML = fresh.innerHTML; }
    }

    function showLoadError() {
        // The summary can live inside a collapse or a dropdown, so an error
        // raised from a button outside it would land out of sight.
        const panel = summaryEl.closest('.collapse');
        if (panel && !panel.classList.contains('show')
            && window.bootstrap && bootstrap.Collapse) {
            bootstrap.Collapse.getOrCreateInstance(panel).show();
        }
        const alert = document.createElement('div');
        alert.className = 'alert alert-danger alert-dismissible fade show mb-0 mt-3';
        alert.innerHTML = '<i class="fas fa-exclamation-triangle me-1"></i>'
            + S.loadError
            + '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';
        summaryEl.appendChild(alert);
    }

    /* ── paging and sorting stay inside the ajax loop ─────────────────── */

    function bindNavLinks() {
        (opts.rootLinks || []).forEach(function (selector) {
            root.querySelectorAll(selector).forEach(bindLink);
        });
        if (!results) { return; }
        (opts.resultLinks || []).forEach(function (selector) {
            results.querySelectorAll(selector).forEach(bindLink);
        });
    }

    function bindLink(link) {
        if (link.dataset.filterDraftBound) { return; }
        link.dataset.filterDraftBound = '1';
        link.addEventListener('click', function (event) {
            if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) { return; }
            event.preventDefault();
            load(link.getAttribute('href'), true);
        });
    }

    /* ── wiring ──────────────────────────────────────────────────────── */

    function watch(el) {
        el.addEventListener('change', renderSummary);
        el.addEventListener('input', renderSummary);
        el.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') { event.preventDefault(); apply(); }
        });
        // TomSelect swallows the original <select>'s change event in some
        // versions, so listen on the instance as well.
        if (el.tomselect) { el.tomselect.on('change', renderSummary); }
    }

    inputs().forEach(watch);
    if (opts.quickEl) { watch(opts.quickEl); }

    // `base` is an absolute URL, `location.pathname` is not — compare paths.
    const basePath = opts.base ? opts.base.replace(/^[a-z]+:\/\/[^/]+/i, '') : null;
    window.addEventListener('popstate', function () {
        // Another page's history entry is none of this bar's business.
        if (basePath && window.location.pathname.indexOf(basePath) !== 0) { return; }
        load(window.location.pathname + window.location.search, false);
    });

    renderSummary();
    bindNavLinks();

    return { refresh: renderSummary, apply: apply };
}
window.initIndexFilterDraft = initIndexFilterDraft;

/* --------------------------------------------------------------------------
 * Adapter: the log indexes' filter card
 * --------------------------------------------------------------------------
 * Its configuration (base URL, applied filters, field labels) is rendered
 * next to it as a JSON <script>; see Elements/Logs/filter_card.ctp.
 */
function initLogFilterCard(root) {
    if (!root) { return; }
    const configEl = root.querySelector('.log-filter-config');
    if (!configEl) { return; }
    const cfg = JSON.parse(configEl.textContent);
    const quickEl = root.querySelector('.log-quick-filter');

    // TomSelect copies the select's classes onto its wrapper, so
    // `.filter-draft-input` alone matches two nodes per control.
    function inputs() {
        return Array.prototype.slice.call(
            root.querySelectorAll('select.filter-draft-input, input.filter-draft-input'));
    }

    /*
     * Filters go in the query string, paginator parameters stay named URL
     * segments. A named segment cannot carry a '/' — `url:%2Fevents` reaches
     * the access log controller with the value dropped — and the free-text
     * search of a URL column is exactly where slashes turn up.
     */
    function buildUrl() {
        const query = new URLSearchParams();
        const quick = quickEl ? (quickEl.value || '').trim() : '';
        if (quick !== '') { query.set(cfg.quickName, quick); }
        inputs().forEach(function (el) {
            const value = (el.value || '').trim();
            if (value !== '') { query.set(el.getAttribute('name'), value); }
        });
        return formatIndexUrl(cfg.base, { named: cfg.preserved, query: query });
    }

    /**
     * Read a URL back into the card. Applying round-trips to itself, but the
     * back button and the pagination/sort links do not: they hand over a URL
     * this card did not build, and its inputs, its chips and the paginator
     * parameters it carries across all have to follow.
     */
    function syncFromUrl(url) {
        const parts = parseIndexUrl(url, cfg.base);
        // `page` is deliberately not carried across: a new filter starts over.
        cfg.preserved = {};
        ['sort', 'direction', 'limit'].forEach(function (key) {
            if (parts.named[key] !== undefined) { cfg.preserved[key] = parts.named[key]; }
        });

        // A filter may still arrive as a named segment, from an older link.
        inputs().forEach(function (el) {
            const name = el.getAttribute('name');
            const value = parts.query.get(name) || parts.named[name] || '';
            if (el.tomselect) { el.tomselect.setValue(value, true); } else { el.value = value; }
        });
        if (quickEl) {
            quickEl.value = parts.query.get(cfg.quickName) || parts.named[cfg.quickName] || '';
        }
    }

    if (typeof initTomSelect === 'function') { initTomSelect(root); }

    const draft = initIndexFilterDraft(root, {
        base: cfg.base,
        inputs: inputs,
        nameOf: function (el) { return el.getAttribute('name'); },
        labelOf: function (name) {
            return (cfg.fields[name] && cfg.fields[name].label) || name;
        },
        displayOf: function (name, value) {
            const options = cfg.fields[name] && cfg.fields[name].options;
            return (options && options[value]) || value;
        },
        quickEl: quickEl,
        quickLabel: cfg.strings.searchLabel,
        applied: cfg.applied,
        appliedQuick: cfg.appliedQuick,
        countEl: root.querySelector('.filter-draft-count'),
        summaryEl: root.querySelector('.filter-draft-summary'),
        results: cfg.results,
        swap: ['#headerCountBadge', '.log-filter-pager'],
        rootLinks: ['.log-filter-pager a[href]'],
        resultLinks: ['.pagination a[href]', 'thead a[href]'],
        buildUrl: buildUrl,
        syncFromUrl: syncFromUrl,
        strings: cfg.strings,
    });

    // The magnifier next to the search box applies too — it is the only
    // control left in reach when the advanced panel is folded away.
    const quickBtn = root.querySelector('.log-quick-btn');
    if (quickBtn && draft) { quickBtn.addEventListener('click', draft.apply); }
}
window.initLogFilterCard = initLogFilterCard;

/* --------------------------------------------------------------------------
 * Adapter: the scaffold's index filter bar
 * --------------------------------------------------------------------------
 * genericElementsBS5/IndexTable/filter_bar.ctp calls this whenever it renders
 * a `more_filters` control. Everything here is URL work.
 *
 * @param {Element} bar   the filter bar element
 * @param {Object}  cfg   scope, ajaxContainer, base, itemPath, mode,
 *                        transport, searchField, idField, ownedKeys,
 *                        results, swap, strings
 * @returns {Object|null} the draft handle, so the bar's own buttons can apply
 */
function initScaffoldFilterDraft(bar, cfg) {
    const scope = cfg.scope || document;
    /*
     * By id, never by a scoped query: a tab pane can hold two scaffolded
     * indexes (the event view renders the attribute list twice), and only one
     * of them may declare `more_filters`. Searching the pane hands the
     * panel-less bar its neighbour's panel, and its config then builds the
     * neighbour's URLs.
     */
    const panel = document.getElementById(cfg.advId);
    if (!panel) { return null; }

    // TomSelect copies the select's classes onto its wrapper, so
    // `.filter-draft-input` alone matches two nodes per control.
    const inputs = function () {
        return Array.prototype.slice.call(panel.querySelectorAll('select.filter-draft-input'));
    };
    const controlFor = function (name) { return panel.querySelector('[name="' + name + '"]'); };
    // `#filterField` is a repeated id across bars; scope it to this one.
    const searchEl = bar.querySelector('#filterField');

    // In `event` mode every filter key is prefixed in the URL.
    const rawKey = function (name) {
        return (cfg.mode === 'event' ? 'search' : '') + name;
    };
    // The URL this bar is currently showing: an ajax tab tracks its own.
    const source = function () {
        return (cfg.ajaxContainer && cfg.ajaxContainer.dataset.url)
            ? cfg.ajaxContainer.dataset.url
            : (window.location.pathname + window.location.search);
    };

    // "Clear all" on a full page used to be a plain link to the bare index,
    // scope included; inside an ajax tab it kept the scope. One flag, read
    // and reset by the next build, preserves both.
    let clearScope = false;

    function controlValues() {
        const out = {};
        const term = searchEl ? searchEl.value.trim() : '';
        if (term !== '') {
            // A number or a UUID means the user is after one record, not a phrase.
            const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            const key = (cfg.idField && (uuidRe.test(term) || /^[0-9]+$/.test(term)))
                ? cfg.idField : cfg.searchField;
            out[key] = term;
        }
        scope.querySelectorAll('.topbar-filter').forEach(function (el) {
            const name = el.getAttribute('name');
            if (!name) { return; }
            const value = (el.value || '').trim();
            if (value !== '') { out[name] = value; }
        });
        return out;
    }

    /*
     * Filters as a query string, for an index that declares
     * `transport => 'query'` (the global attribute index) because a named
     * segment cannot hold a '/'. The path is left exactly as it is — it
     * carries whatever scope the bar does not own.
     */
    function buildQueryDraftUrl() {
        const parts = parseIndexUrl(source(), cfg.itemPath);
        const query = parts.query;
        query.delete('page');
        if (clearScope) {
            clearScope = false;
            Array.prototype.slice.call(query.keys()).forEach(function (key) {
                if (['sort', 'direction', 'limit'].indexOf(key) === -1) { query.delete(key); }
            });
        }
        [cfg.searchField, cfg.idField].forEach(function (k) { if (k) { query.delete(k); } });
        cfg.ownedKeys.forEach(function (key) {
            if (['sort', 'direction', 'page', 'limit'].indexOf(key) === -1) { query.delete(key); }
        });
        const values = controlValues();
        Object.keys(values).forEach(function (name) { query.set(name, values[name]); });
        const qs = query.toString();
        return parts.path + (qs ? '?' + qs : '');
    }

    /*
     * Filters as named segments. Everything the bar does not own is kept —
     * the positional scope arguments, the unowned named keys, and the
     * paginator's sort/direction, because dropping those would silently reset
     * the column the table is sorted on. Only `page` resets: a new filter
     * starts over.
     */
    function buildUrl() {
        if (cfg.transport === 'query') { return buildQueryDraftUrl(); }
        const parts = parseIndexUrl(source(), cfg.itemPath);
        const named = parts.named;
        delete named['page'];
        if (clearScope) {
            clearScope = false;
            parts.positional.length = 0;
            Object.keys(named).forEach(function (key) {
                if (['sort', 'direction', 'limit'].indexOf(key) === -1) { delete named[key]; }
            });
        }
        [cfg.searchField, cfg.idField].forEach(function (k) { if (k) { delete named[rawKey(k)]; } });
        cfg.ownedKeys.forEach(function (key) {
            if (['sort', 'direction', 'page', 'limit'].indexOf(key) === -1) { delete named[rawKey(key)]; }
        });
        const values = controlValues();
        Object.keys(values).forEach(function (name) { named[rawKey(name)] = values[name]; });
        return formatIndexUrl(cfg.base, { positional: parts.positional, named: named });
    }

    /*
     * Applied filters with no control in this bar — the `searchemail:` that
     * the "My events" button puts in the URL. They used to show in the
     * server-rendered "Active filters" row; now that the summary owns the
     * chips, they have to be read back out of the URL or clicking "My events"
     * leaves no trace at all.
     */
    function extraChips() {
        const parts = parseIndexUrl(source(), cfg.itemPath);
        const out = [];
        const seen = {};
        const add = function (key, value) {
            if (cfg.mode === 'event' && key.indexOf('search') === 0) { key = key.slice(6); }
            if (!key || value === '' || cfg.ownedKeys.indexOf(key) !== -1 || seen[key]) { return; }
            seen[key] = true;
            out.push({
                label: key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' '),
                value: value,
            });
        };
        Object.keys(parts.named).forEach(function (key) { add(key, parts.named[key]); });
        parts.query.forEach(function (value, key) { add(key, value); });
        return out;
    }

    return initIndexFilterDraft(bar, {
        base: cfg.base,
        inputs: inputs,
        nameOf: function (el) { return el.getAttribute('name'); },
        labelOf: function (name) {
            const field = controlFor(name) && controlFor(name).closest('.filter-draft-field');
            const label = field && field.querySelector('label');
            return label ? label.textContent.trim() : name;
        },
        displayOf: function (name, value) {
            const el = controlFor(name);
            if (el && el.tagName === 'SELECT') {
                const option = Array.prototype.find.call(el.options, function (o) {
                    return o.value === value;
                });
                if (option && option.text.trim() !== '') { return option.text.trim(); }
            }
            return value;
        },
        // The search term is part of the draft too, exactly as on the log
        // indexes: one summary says everything the next run will apply.
        quickEl: searchEl,
        quickLabel: cfg.strings.searchLabel,
        appliedQuick: searchEl ? searchEl.value.trim() : '',
        // The server rendered the controls already selected, so what they
        // hold at init is exactly what the page is showing.
        applied: (function () {
            const out = {};
            inputs().forEach(function (el) {
                const value = (el.value || '').trim();
                if (value !== '') { out[el.getAttribute('name')] = value; }
            });
            return out;
        }()),
        // The badge rides the toggle button, which lives in the bar's flex
        // row — outside the panel the controls are in.
        countEl: bar.querySelector('.filter-draft-count'),
        summaryEl: panel.querySelector('.filter-draft-summary'),
        extraChips: extraChips,
        results: cfg.results,
        swap: cfg.swap,
        rootLinks: ['.index-filter-pager a[href]'],
        resultLinks: ['.pagination a[href]', 'thead a[href]'],
        // A tab that drives its own URLs — the attribute list inside an event
        // view builds `events/viewAttributes/<id>/category:x` — registers the
        // two functions it owns on its container. Looked up per call, because
        // it registers them after this bar has already wired itself.
        buildUrl: function () {
            const over = cfg.ajaxContainer && cfg.ajaxContainer.__indexFilterOverride;
            return (over && over.buildUrl) ? over.buildUrl() : buildUrl();
        },
        // Drops the bar's own filters and the search term. Outside an ajax
        // tab it drops the scope too, the way the old "Clear all" link to the
        // bare index did; inside one the scope is what the tab is about.
        clearAll: function () {
            clearScope = !cfg.ajaxContainer;
            if (searchEl) { searchEl.value = ''; }
            inputs().forEach(function (el) {
                if (el.tomselect) { el.tomselect.setValue('', true); } else { el.value = ''; }
            });
        },
        // An ajax tab reloads its own fragment, this bar included, and comes
        // back with the server's state — nothing to keep in sync here.
        reload: function (url) {
            const over = cfg.ajaxContainer && cfg.ajaxContainer.__indexFilterOverride;
            if (over && over.reload) { return over.reload(url); }
            if (cfg.ajaxContainer && typeof reloadAjaxTabIndex === 'function') {
                reloadAjaxTabIndex(cfg.ajaxContainer, url);
                return true;
            }
            return false;
        },
        strings: cfg.strings,
    });
}
window.initScaffoldFilterDraft = initScaffoldFilterDraft;

document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-log-filter-card]').forEach(initLogFilterCard);
});
