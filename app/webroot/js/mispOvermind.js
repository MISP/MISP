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
 * Confirmation modal (inline — no AJAX)
 *
 * opts:
 *   title         (string)   — modal title
 *   body          (string)   — HTML for the body (already escaped by caller)
 *   confirmLabel  (string)   — confirm button text
 *   confirmClass  (string)   — Bootstrap btn class, default 'btn-primary'
 *   cancelLabel   (string)   — cancel button text, default 'Cancel'
 *   size          (string)   — modal size suffix: 'sm'|'lg'|'xl', default 'sm'
 *   onConfirm     (function) — called after the user confirms
 *******************************/
function showConfirmModal(opts) {
    const modalEl   = document.getElementById('mainModal');
    const modalBody = document.getElementById('mainModalBody');
    if (!modalEl || !modalBody) return;

    const size         = opts.size         || 'sm';
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

    const dialog = modalEl.querySelector('.modal-dialog');
    dialog.classList.remove('modal-sm', 'modal-lg', 'modal-xl');
    dialog.classList.add('modal-' + size);

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
    const modalDialog = document.querySelector('#mainModal .modal-dialog');
    modalDialog.classList.remove('modal-sm', 'modal-lg', 'modal-xl');
    if (size) {
        modalDialog.classList.add('modal-' + size);
    }

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
}

// POST `body` to `url` and render the HTML response into #mainModal, chaining
// from the currently-open modal (hide → show) so backdrops don't stack.
function openModalPostChained(url, body, size = 'xl') {
    const el = document.getElementById('mainModal');
    const inst = el ? bootstrap.Modal.getInstance(el) : null;
    const run = () => {
        const dialog = el.querySelector('.modal-dialog');
        dialog.classList.remove('modal-sm', 'modal-lg', 'modal-xl');
        if (size) {
            dialog.classList.add('modal-' + size);
        }
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

function multiSelectItems(url, suffixe, size = 'sm') {
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

function setView(view, save = true) {
    const tableView = document.getElementById('tableView');
    const cardView  = document.getElementById('cardView');
    const viewList  = document.getElementById('viewList');
    const viewCard  = document.getElementById('viewCard');
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
        if (value !== '') filters[name] = value;
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

    document.querySelectorAll('.topbar-filter').forEach(el => {
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


function testConnection(id) {
    function esc(input) {
        return String(input === null || input === undefined ? '' : input)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    var container = document.getElementById("connection_test_" + id);
    if (!container) return;
    var resultContainer = container.querySelector('.server-action-result') || container;

    resultContainer.innerHTML = '<span class="text-muted">' +
        '<i class="fas fa-spinner fa-spin me-1"></i>Running test...' +
        '</span>';

    fetch(baseurl + '/servers/testConnection/' + id)
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
        })
        .catch(function() {
            resultContainer.innerHTML = '<span class="text-danger fw-semibold">Internal error</span>';
        });
}


function getRemoteSyncUser(id) {
    function esc(input) {
        return String(input === null || input === undefined ? '' : input)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    var container = document.getElementById("sync_user_test_" + id);
    if (!container) return;
    var resultContainer = container.querySelector('.server-action-result') || container;

    fetch(baseurl + '/servers/getRemoteUser/' + id)
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
            } else if ("error" in response) {
                resultContainer.innerHTML =
                    '<div class="text-danger fw-semibold">Error: #' +
                    esc(response.error) + '</div>';
            } else {
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
            headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
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

function initTomSelect(container) {
    container.querySelectorAll('.tom-select').forEach(el => {
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
 * Sighting cells — popover lazy-init + add-sighting
 * i18n strings are injected once per page via window._sightingI18n
 * (set by the sightings.ctp field partial)
 *******************************/
(function () {
    /* Lazy popover */
    document.addEventListener('mouseenter', function (e) {
        var el = e.target.closest('.sighting-counts');
        if (!el || el._popoverReady) return;
        el._popoverReady = true;
        new bootstrap.Popover(el, {
            trigger:   'hover focus',
            html:      true,
            placement: 'top',
        }).show();
    }, true);

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
 * initEventForm
 * Bootstraps all interactive behaviour for Events/add and Events/edit.
 * Call once the DOM is ready: initEventForm(baseurl)
 * @param {string} base  MISP base URL (no trailing slash)
 *******************************/
function initEventForm(base) {

    /* Fetch a live event summary when the user types a UUID/ID */
    function setupUuidPreview() {
        var input   = document.getElementById('EventExtendsUuid');
        var preview = document.getElementById('event_preview');
        if (!input || !preview) { return; }

        var timer = null;
        function fetchPreview(val) {
            clearTimeout(timer);
            if (!val || !val.trim()) {
                preview.style.display = 'none';
                return;
            }
            timer = setTimeout(function () {
                fetch(base + '/events/getEventInfoById/'
                        + encodeURIComponent(val.trim()),
                    { credentials: 'same-origin' })
                    .then(function (r) { return r.text(); })
                    .then(function (html) {
                        preview.innerHTML     = html;
                        preview.style.display = '';
                        bindCardClick();
                    })
                    .catch(function () { preview.style.display = 'none'; });
            }, 100);
        }

        /* Clicking the matched-event card copies its UUID into the input */
        function bindCardClick() {
            var card = preview.querySelector('.js-extends-event-card');
            if (!card) { return; }
            card.addEventListener('click', function () {
                var uuid = card.dataset.extendsUuid;
                if (uuid) { input.value = uuid; }
            });
        }

        input.addEventListener('input', function () { fetchPreview(input.value); });
        if (input.value) { fetchPreview(input.value); }
    }

    /* Card-based radio groups for Analysis and Threat Level */
    function setupRadioCards() {
        var selectIds = {
            analysis: 'EventAnalysisInput',
            threat:   'EventThreatLevelInput',
        };
        document.querySelectorAll('.event-card').forEach(function (card) {
            card.addEventListener('click', function () {
                var group  = card.dataset.group;
                var select = document.getElementById(selectIds[group]);
                if (select) { select.value = card.dataset.value; }

                document.querySelectorAll(
                    '.event-card[data-group="' + group + '"]'
                ).forEach(function (c) {
                    var inner = c.querySelector('.border');
                    if (!inner) { return; }
                    var selected = c === card;
                    inner.style.borderColor = selected ? 'var(--primary)' : '#d8dde3';
                    inner.style.background  = selected ? 'rgba(24,146,177,.08)' : '';
                });
            });
        });
    }

    /* Convert DD/MM/YYYY display input → YYYY-MM-DD hidden field */
    function setupDateInput() {
        var display = document.getElementById('EventDateDisplay');
        var hidden  = document.getElementById('EventDate');
        if (!display || !hidden) { return; }

        display.addEventListener('input', function () {
            var parts = display.value.split('/');
            if (parts.length === 3
                    && parts[0].length === 2
                    && parts[1].length === 2
                    && parts[2].length === 4) {
                hidden.value = parts[2] + '-' + parts[1] + '-' + parts[0];
            }
        });
    }

    /* Require a non-empty Event Info (name) before submitting */
    function setupInfoValidation() {
        var info = document.getElementById('EventInfo');
        if (!info) { return; }
        var form = info.form || (info.closest && info.closest('form'));
        if (!form) { return; }

        var errorId = 'EventInfoError';
        var message = info.dataset.requiredMsg
            || 'Please provide a name for the event.';

        function showError() {
            info.style.setProperty('border', '1px solid #dc3545', 'important');
            info.style.setProperty('border-radius', '4px', 'important');
            if (!document.getElementById(errorId)) {
                var msg = document.createElement('div');
                msg.id        = errorId;
                msg.className  = 'text-danger d-flex align-items-center gap-1';
                msg.style.fontSize  = '.75rem';
                msg.style.marginTop = '.35rem';
                var icon = document.createElement('i');
                icon.className = 'fas fa-circle-exclamation';
                msg.appendChild(icon);
                msg.appendChild(document.createTextNode(message));
                info.parentNode.appendChild(msg);
            }
        }

        function clearError() {
            info.style.removeProperty('border');
            info.style.removeProperty('border-radius');
            info.style.setProperty('border-bottom', '1px solid #d8dde3', 'important');
            var msg = document.getElementById(errorId);
            if (msg) { msg.remove(); }
        }

        form.addEventListener('submit', function (e) {
            if (!info.value.trim()) {
                e.preventDefault();
                e.stopPropagation();
                showError();
                info.focus();
            }
        });

        info.addEventListener('input', function () {
            if (info.value.trim()) { clearError(); }
        });
    }

    initDistributionSelect('distribution-select', null);
    if (typeof initCollectionForm === 'function') { initCollectionForm(document); }
    setupUuidPreview();
    setupRadioCards();
    setupDateInput();
    setupInfoValidation();
}

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
