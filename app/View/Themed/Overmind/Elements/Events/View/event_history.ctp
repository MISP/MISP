<?php
$eventId  = h($data['Event']['id'] ?? '');
$uid      = 'evt-history-' . $eventId;
$fetchUrl = h($baseurl . '/audit_logs/eventIndexV2/' . $eventId);
?>

<div class="card shadow-sm mb-3" id="history-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex flex-wrap align-items-center gap-2">

            <div class="rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;background:#e0e7ff;">
                <i class="fas fa-history" style="color:#4f46e5;font-size:1rem;"></i>
            </div>

            <div>
                <div class="fw-bold lh-1"><?= __('History') ?></div>
                <div class="small text-muted mt-1" id="<?= $uid ?>-count">…</div>
            </div>

            <!-- Action filter -->
            <select id="<?= $uid ?>-filter-action"
                    class="form-select flex-shrink-0 w-auto ms-auto">
                <option value=""><?= __('All actions') ?></option>
                <option value="add"><?= __('Add') ?></option>
                <option value="edit"><?= __('Edit') ?></option>
                <option value="soft_delete"><?= __('Soft delete') ?></option>
                <option value="delete"><?= __('Delete') ?></option>
                <option value="undelete"><?= __('Undelete') ?></option>
                <option value="tag"><?= __('Tag') ?></option>
                <option value="tag_local"><?= __('Tag (local)') ?></option>
                <option value="remove_tag"><?= __('Remove tag') ?></option>
                <option value="remove_local_tag"><?= __('Remove tag (local)') ?></option>
                <option value="galaxy"><?= __('Galaxy') ?></option>
                <option value="galaxy_local"><?= __('Galaxy (local)') ?></option>
                <option value="remove_galaxy"><?= __('Remove galaxy') ?></option>
                <option value="remove_local_galaxy"><?= __('Remove galaxy (local)') ?></option>
                <option value="publish"><?= __('Publish') ?></option>
                <option value="publish_sightings"><?= __('Publish sightings') ?></option>
                <option value="instantiate"><?= __('Instantiate') ?></option>
            </select>

            <!-- Model filter -->
            <select id="<?= $uid ?>-filter-model"
                    class="form-select flex-shrink-0 w-auto">
                <option value=""><?= __('All models') ?></option>
            </select>

            <!-- Search -->
            <div class="input-group flex-grow-1" style="max-width:400px;">
                <input type="search"
                       id="<?= $uid ?>-search"
                       class="form-control"
                       placeholder="<?= __('Search…') ?>"
                       autocomplete="off">
                <button class="btn btn-primary" type="button" id="<?= $uid ?>-search-btn">
                    <i class="fas fa-search"></i>
                </button>
            </div>

            <!-- Pagination (hidden until data loads) -->
            <div class="d-none d-flex justify-content-end"
                 id="<?= $uid ?>-pager"></div>

        </div>
    </div>

    <!-- BODY -->
    <div id="<?= $uid ?>-body" class="p-3">
        <div class="d-flex align-items-center justify-content-center py-5 text-muted">
            <div class="spinner-border spinner-border-sm" role="status"></div>
        </div>
    </div>

</div>

<script>
(function () {
    var uid       = <?= json_encode($uid) ?>;
    var fetchUrl  = <?= json_encode($fetchUrl) ?>;
    var body      = document.getElementById(uid + '-body');
    var countEl   = document.getElementById(uid + '-count');
    var pagerEl   = document.getElementById(uid + '-pager');
    var selAction = document.getElementById(uid + '-filter-action');
    var selModel  = document.getElementById(uid + '-filter-model');
    var searchEl  = document.getElementById(uid + '-search');

    /* ── i18n ──────────────────────────────────── */
    var i18n = {
        showChanges: <?= json_encode(__('Show changes')) ?>,
        hideChanges: <?= json_encode(__('Hide changes')) ?>,
        noEntries:   <?= json_encode(__('No history entries found.')) ?>,
        loadError:   <?= json_encode(__('Could not load history.')) ?>,
        total:       <?= json_encode(__('total')) ?>,
        page:        <?= json_encode(__('page')) ?>,
        visible:     <?= json_encode(__('visible')) ?>
    };

    /* ── State ─────────────────────────────────── */
    var curPage    = 1;
    var totalPages = 1;
    var totalCount = 0;
    var modelReady = false;

    /* ── Action metadata ───────────────────────── */
    var A = {
        add:                 { label: <?= json_encode(__('Add'))                   ?>, color:'#198754', bg:'#d1e7dd', icon:'fas fa-plus-circle'   },
        edit:                { label: <?= json_encode(__('Edit'))                  ?>, color:'#0d6efd', bg:'#cfe2ff', icon:'fas fa-pencil-alt'     },
        soft_delete:         { label: <?= json_encode(__('Soft delete'))           ?>, color:'#fd7e14', bg:'#ffe5cc', icon:'fas fa-trash-restore'  },
        delete:              { label: <?= json_encode(__('Delete'))                ?>, color:'#dc3545', bg:'#f8d7da', icon:'fas fa-trash-alt'      },
        undelete:            { label: <?= json_encode(__('Undelete'))              ?>, color:'#20c997', bg:'#d2f4ea', icon:'fas fa-trash-restore'  },
        tag:                 { label: <?= json_encode(__('Tag'))                   ?>, color:'#6f42c1', bg:'#e8d5f5', icon:'misp-icon misp-icon-tag misp-simple'              },
        tag_local:           { label: <?= json_encode(__('Tag (local)'))           ?>, color:'#6f42c1', bg:'#e8d5f5', icon:'misp-icon misp-icon-tag misp-simple'              },
        remove_tag:          { label: <?= json_encode(__('Remove tag'))            ?>, color:'#d63384', bg:'#fad8e8', icon:'misp-icon misp-icon-tag misp-simple'              },
        remove_local_tag:    { label: <?= json_encode(__('Remove tag (local)'))    ?>, color:'#d63384', bg:'#fad8e8', icon:'misp-icon misp-icon-tag misp-simple'              },
        galaxy:              { label: <?= json_encode(__('Galaxy'))                ?>, color:'#6610f2', bg:'#e0d0fd', icon:'misp-icon misp-icon-galaxy misp-simple'          },
        galaxy_local:        { label: <?= json_encode(__('Galaxy (local)'))        ?>, color:'#6610f2', bg:'#e0d0fd', icon:'misp-icon misp-icon-galaxy misp-simple'          },
        remove_galaxy:       { label: <?= json_encode(__('Remove galaxy'))         ?>, color:'#c2185b', bg:'#fce3f0', icon:'misp-icon misp-icon-galaxy misp-simple'          },
        remove_local_galaxy: { label: <?= json_encode(__('Remove galaxy (local)')) ?>, color:'#c2185b', bg:'#fce3f0', icon:'misp-icon misp-icon-galaxy misp-simple'          },
        publish:             { label: <?= json_encode(__('Publish'))               ?>, color:'#0284c7', bg:'#e0f2fe', icon:'fas fa-paper-plane'                                },
        publish_sightings:   { label: <?= json_encode(__('Publish sightings'))     ?>, color:'#0891b2', bg:'#cffafe', icon:'misp-icon misp-icon-sighting misp-simple'        },
        instantiate:         { label: <?= json_encode(__('Instantiate'))           ?>, color:'#6c757d', bg:'#e2e3e5', icon:'fas fa-clone'          }
    };

    /* ── Helpers ───────────────────────────────── */
    function fmtTime(ts) {
        if (!ts) { return '—'; }
        var d = new Date(String(ts).replace(' ', 'T'));
        return isNaN(d) ? ts : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function fmtDay(ts) {
        if (!ts) { return ''; }
        var d = new Date(String(ts).replace(' ', 'T'));
        return isNaN(d) ? ts : d.toLocaleDateString([], {
            weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
        });
    }

    function dayKey(ts) { return ts ? String(ts).substring(0, 10) : ''; }

    /* ── Build URL with CakePHP named params ───── */
    function buildUrl(page) {
        var parts = [];
        if (page > 1)       { parts.push('page:'   + page); }
        if (selAction.value){ parts.push('action:' + selAction.value); }
        if (selModel.value) { parts.push('model:'  + selModel.value); }
        return parts.length ? fetchUrl + '/' + parts.join('/') : fetchUrl;
    }

    /* ── Build change diff HTML ────────────────── */
    function buildDiff(change, action) {
        if (!change || typeof change !== 'object') { return ''; }
        var deleteSet = { delete:1, soft_delete:1, remove_galaxy:1, remove_local_galaxy:1, remove_tag:1, remove_local_tag:1 };
        var keys = Object.keys(change);
        if (!keys.length) { return ''; }
        var lines = keys.map(function (field) {
            var val = change[field];
            if (deleteSet[action]) {
                return '<div>'
                    + '<span class="fw-bold me-1">' + escapeHtml(field) + ':</span>'
                    + '<span class="text-danger text-decoration-line-through" style="opacity:.85;">' + escapeHtml(JSON.stringify(val)) + '</span>'
                    + ' <i class="fas fa-times ms-1 text-danger" style="font-size:.65rem;"></i>'
                    + '</div>';
            }
            if (Array.isArray(val) && val.length === 2) {
                return '<div>'
                    + '<span class="fw-bold me-1">' + escapeHtml(field) + ':</span>'
                    + '<span class="text-danger text-decoration-line-through" style="opacity:.85;">' + escapeHtml(JSON.stringify(val[0])) + '</span>'
                    + '<span class="text-muted mx-1" style="font-size:.65rem;"><i class="fas fa-arrow-right"></i></span>'
                    + '<span class="text-success">' + escapeHtml(JSON.stringify(val[1])) + '</span>'
                    + '</div>';
            }
            return '<div>'
                + '<span class="fw-bold me-1">' + escapeHtml(field) + ':</span>'
                + '<span class="text-success">' + escapeHtml(JSON.stringify(val)) + '</span>'
                + '</div>';
        });
        return '<div class="font-monospace bg-light border rounded-2 p-2 mt-2 overflow-x-auto"'
            + ' style="font-size:.75rem;line-height:1.6;">'
            + lines.join('') + '</div>';
    }

    /* ── Build single timeline entry ───────────── */
    function buildEntry(item) {
        var log    = item.AuditLog     || {};
        var user   = item.User         || {};
        var org    = item.Organisation || {};
        var action = log.action || '';
        var meta   = A[action] || { label: action, color:'#6c757d', bg:'#e2e3e5', icon:'fa-circle' };

        var diffHtml = buildDiff(log.change, action);
        var diffId   = uid + '-d-' + (log.id || Math.random().toString(36).slice(2));
        var searchVal = [log.title||'', log.model||'', action, user.email||'', org.name||'']
            .join(' ').toLowerCase();

        var titleHtml = '';
        if (log.model) {
            titleHtml += '<span class="text-muted text-uppercase me-1"'
                + ' style="font-size:.68rem;letter-spacing:.04em;">'
                + escapeHtml(log.model) + '</span>';
        }
        titleHtml += escapeHtml(log.title || ('#' + (log.model_id || '')));

        var metaLine = '';
        if (user.email) {
            metaLine += '<span class="d-inline-flex align-items-center gap-1">'
                + '<span class="misp-icon misp-icon-user1 misp-simple" style="font-size:.65rem;"></span>'
                + escapeHtml(user.email) + '</span>';
        }
        if (org.name) {
            metaLine += '<span class="d-inline-flex align-items-center gap-1">'
                + '<span class="misp-icon misp-icon-organisation misp-simple" style="font-size:.65rem;"></span>'
                + escapeHtml(org.name) + '</span>';
        }

        var toggleBtn = '';
        if (diffHtml) {
            toggleBtn = '<button type="button"'
                + ' class="btn btn-link btn-sm p-0 mt-1 text-decoration-none diff-toggle"'
                + ' style="font-size:.72rem;color:inherit;opacity:.7;"'
                + ' data-target="' + escapeHtml(diffId) + '"'
                + ' data-show="' + escapeHtml(i18n.showChanges) + '"'
                + ' data-hide="' + escapeHtml(i18n.hideChanges) + '">'
                + '<i class="fas fa-chevron-down me-1"></i>'
                + escapeHtml(i18n.showChanges) + '</button>'
                + '<div id="' + escapeHtml(diffId) + '" class="d-none">' + diffHtml + '</div>';
        }

        return '<div class="tl-entry" data-search="' + escapeHtml(searchVal) + '">'
            + '<div class="tl-dot" style="color:' + escapeHtml(meta.color) + ';background:' + escapeHtml(meta.bg) + ';"></div>'
            + '<div class="d-flex align-items-start gap-2 flex-wrap">'
            + '<span class="text-muted flex-shrink-0 mt-1" style="font-size:.72rem;min-width:2.8rem;">' + fmtTime(log.created) + '</span>'
            + '<span class="badge flex-shrink-0 d-inline-flex align-items-center gap-1 mt-1"'
            + ' style="background:' + escapeHtml(meta.bg) + ';color:' + escapeHtml(meta.color) + ';'
            + 'font-size:.68rem;border:1px solid ' + escapeHtml(meta.color) + '33;">'
            + '<i class="' + escapeHtml(meta.icon) + '"></i>' + escapeHtml(meta.label) + '</span>'
            + '<div class="flex-fill" style="min-width:0;">'
            + '<div class="small fw-medium lh-sm">' + titleHtml + '</div>'
            + (metaLine ? '<div class="d-flex flex-wrap gap-2 mt-1 text-muted" style="font-size:.72rem;">' + metaLine + '</div>' : '')
            + toggleBtn
            + '</div></div></div>';
    }

    /* ── Build timeline (grouped by day) ───────── */
    function buildTimeline(entries) {
        if (!entries.length) {
            return '<div class="d-flex align-items-center justify-content-center py-5 text-muted gap-2">'
                + '<i class="fas fa-history fa-2x opacity-25"></i>'
                + '<span class="small">' + escapeHtml(i18n.noEntries) + '</span>'
                + '</div>';
        }
        var groups = [], curDay = null, curGroup = null;
        entries.forEach(function (item) {
            var log = item.AuditLog || {};
            var dk  = dayKey(log.created);
            if (dk !== curDay) {
                curGroup = { day: dk, label: fmtDay(log.created), entries: [] };
                groups.push(curGroup);
                curDay = dk;
            }
            curGroup.entries.push(item);
        });
        var html = '<div class="tl">';
        groups.forEach(function (g) {
            html += '<div class="tl-group mb-2" data-day="' + escapeHtml(g.day) + '">'
                  + '<div class="tl-day fw-bold text-uppercase text-muted bg-light rounded-2">'
                  + escapeHtml(g.label) + '</div>';
            g.entries.forEach(function (item) { html += buildEntry(item); });
            html += '</div>';
        });
        return html + '</div>';
    }

    /* ── Client-side search (current page only) ── */
    function applySearch() {
        var q = searchEl.value.toLowerCase().trim();
        body.querySelectorAll('.tl-entry').forEach(function (el) {
            el.classList.toggle('d-none', !!q && !(el.dataset.search || '').includes(q));
        });
        body.querySelectorAll('.tl-group').forEach(function (grp) {
            grp.classList.toggle('d-none', !grp.querySelector('.tl-entry:not(.d-none)'));
        });
        updateCount();
    }

    /* ── Count label ───────────────────────────── */
    function updateCount() {
        if (!countEl) { return; }
        var all     = body.querySelectorAll('.tl-entry').length;
        var visible = body.querySelectorAll('.tl-entry:not(.d-none)').length;
        var parts   = [];
        if (totalCount > 0) { parts.push(totalCount + ' ' + i18n.total); }
        if (totalPages > 1) { parts.push(i18n.page + ' ' + curPage + '/' + totalPages); }
        if (visible < all)  { parts.push(visible + ' ' + i18n.visible); }
        countEl.textContent = parts.join(' · ');
    }

    /* ── Fetch a page from the server ──────────── */
    function fetchPage(page) {
        body.innerHTML =
            '<div class="d-flex align-items-center justify-content-center py-5 text-muted">'
            + '<div class="spinner-border spinner-border-sm" role="status"></div>'
            + '</div>';

        fetch(buildUrl(page), {
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin'
        })
        .then(function (r) {
            if (!r.ok) { throw new Error(r.status); }
            return r.json();
        })
        .then(function (resp) {
            var entries = Array.isArray(resp.data) ? resp.data : [];
            curPage    = resp.page      || 1;
            totalPages = resp.pageCount || 1;
            totalCount = resp.count     || entries.length;

            if (!modelReady) {
                populateModelFilter(entries);
                if (selModel && !selModel.tomselect) {
                    new TomSelect(selModel, {
                        create: false,
                        onChange: function () { fetchPage(1); }
                    });
                }
                modelReady = true;
            }

            body.innerHTML = buildTimeline(entries);
            applySearch();
            renderPaginator(pagerEl, curPage, totalPages, fetchPage);
            updateCount();
        })
        .catch(function () {
            body.innerHTML =
                '<div class="d-flex align-items-center justify-content-center py-5 text-muted small gap-2">'
                + '<i class="fas fa-exclamation-triangle fa-2x opacity-50"></i>'
                + escapeHtml(i18n.loadError) + '</div>';
            if (countEl) { countEl.textContent = ''; }
            if (pagerEl) { pagerEl.classList.add('d-none'); }
        });
    }

    /* ── Populate model TomSelect ──────────────── */
    function populateModelFilter(entries) {
        var seen = {};
        entries.forEach(function (item) {
            var m = item.AuditLog && item.AuditLog.model;
            if (m && !seen[m]) {
                seen[m] = true;
                var opt = document.createElement('option');
                opt.value = m; opt.textContent = m;
                selModel.appendChild(opt);
            }
        });
    }

    /* ── TomSelect: Action (server-side filter) ── */
    if (selAction && !selAction.tomselect) {
        new TomSelect(selAction, {
            create: false,
            onChange: function () { fetchPage(1); }
        });
    }

    /* ── Event delegation: diff toggle ─────────── */
    body.addEventListener('click', function (e) {
        var btn = e.target.closest('.diff-toggle');
        if (!btn) { return; }
        toggleCollapsible(btn, btn.dataset.target, btn.dataset.show, btn.dataset.hide);
    });

    /* ── Search listeners (client-side) ─────────── */
    searchEl.addEventListener('input', applySearch);
    var searchBtn = document.getElementById(uid + '-search-btn');
    if (searchBtn) { searchBtn.addEventListener('click', applySearch); }
    searchEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { applySearch(); }
    });

    /* ── Initial load ──────────────────────────── */
    fetchPage(1);

}());
</script>
