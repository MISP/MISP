<?php

$safeId      = h($id);
$safeContext = h($context);
$safeOrgId   = h($me['org_id']);

$urlGraph  = $baseurl . '/sightings/viewSightings/'   . $safeId . '/' . $safeContext;
$urlAll    = $baseurl . '/sightings/listSightings/'   . $safeId . '/' . $safeContext;
$urlOrg    = $baseurl . '/sightings/listSightings/'   . $safeId . '/' . $safeContext . '/' . $safeOrgId;
$urlAdd    = $baseurl . '/sightings/add/' . $safeId;
?>

<div class="container-fluid py-3">

    <!-- ── Header ── -->
    <div class="d-flex align-items-center justify-content-between mb-3">
        <h5 class="d-flex align-items-center gap-2 fw-semibold mb-0">
            <span class="d-inline-flex align-items-center justify-content-center rounded-2"
                  style="width:32px;height:32px;background:#fbceff;">
                <span class="misp-icon misp-icon-sighting misp-simple" style="color:#890096;font-size:.85rem;"></span>
            </span>
            <?= __('Sightings') ?>
        </h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"
                aria-label="<?= __('Close') ?>"></button>
    </div>

    <!-- ── Tab nav ── -->
    <ul class="nav nav-pills gap-1 mb-3" id="sightingAdvTabs" role="tablist">

        <li class="nav-item" role="presentation">
            <button class="nav-ajax nav-link active" role="tab"
                    data-tab="graph"
                    data-url="<?= h($urlGraph) ?>">
                <i class="fas fa-chart-area me-1"></i><?= __('Graph') ?>
            </button>
        </li>

        <li class="nav-item" role="presentation">
            <button class="nav-ajax nav-link" role="tab"
                    data-tab="all"
                    data-url="<?= h($urlAll) ?>">
                <i class="fas fa-list me-1"></i><?= __('All') ?>
            </button>
        </li>

        <li class="nav-item" role="presentation">
            <button class="nav-ajax nav-link" role="tab"
                    data-tab="org"
                    data-url="<?= h($urlOrg) ?>">
                <span class="misp-icon misp-icon-organisation misp-simple me-1"></span><?= __('My org') ?>
            </button>
        </li>

        <?php if ($safeContext === 'attribute'): ?>
        <li class="nav-item" role="presentation">
            <button class="nav-ajax nav-link" role="tab" data-tab="add">
                <i class="fas fa-plus me-1"></i><?= __('Add sighting') ?>
            </button>
        </li>
        <?php endif; ?>

    </ul>

    <!-- ── Content area ── -->
    <div id="sightingAdvContent"
         style="max-height:80vh;overflow-y:auto;overflow-x:auto;">
        <div class="d-flex justify-content-center align-items-center py-5">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden"><?= __('Loading…') ?></span>
            </div>
        </div>
    </div>

</div>

<!-- ── Inline add-sighting panel (rendered by JS, not loaded from server) ── -->
<template id="sightingAddForm">
    <form id="sightingAdvForm" class="p-1">
        <div class="mb-3">
            <label class="form-label fw-semibold"><?= __('Type') ?></label>
            <select name="type" class="form-select form-select-sm">
                <option value="0"><?= __('Sighting') ?></option>
                <option value="1"><?= __('False-positive') ?></option>
                <option value="2"><?= __('Expiration') ?></option>
            </select>
        </div>
        <div class="mb-3">
            <label class="form-label fw-semibold"><?= __('Source') ?></label>
            <input type="text" name="source" class="form-control form-control-sm"
                   placeholder="<?= __('honeypot, IDS sensor id, SIEM…') ?>">
        </div>
        <div class="row g-2 mb-3">
            <div class="col">
                <label class="form-label fw-semibold"><?= __('Date') ?></label>
                <input type="date" name="date" class="form-control form-control-sm"
                       value="<?= date('Y-m-d') ?>">
            </div>
            <div class="col">
                <label class="form-label fw-semibold"><?= __('Time') ?></label>
                <input type="time" name="time" class="form-control form-control-sm"
                       step="1" value="<?= date('H:i:s') ?>">
            </div>
        </div>
        <div class="mb-3">
            <label class="form-label fw-semibold"><?= __('Filters') ?> <small class="text-muted fw-normal">(JSON)</small></label>
            <input type="text" name="filters" class="form-control form-control-sm"
                   placeholder='{ "to_ids": 1, "tags": ["tlp:white"] }'>
        </div>
        <div class="d-flex gap-2 justify-content-end">
            <button type="submit" class="btn btn-sm btn-primary">
                <?= __('Add') ?>
            </button>
        </div>
        <div id="sightingAddResult" class="mt-2"></div>
    </form>
</template>

<script>
(function () {
    var _id      = <?= json_encode($id) ?>;
    var _addUrl  = <?= json_encode($urlAdd) ?>;
    var contentEl = document.getElementById('sightingAdvContent');

    /* ── Load remote tab content ── */
    function loadRemote(url) {
        contentEl.innerHTML =
            '<div class="d-flex justify-content-center align-items-center py-5">'
            + '<div class="spinner-border text-primary" role="status">'
            + '<span class="visually-hidden"><?= __('Loading…') ?></span>'
            + '</div></div>';

        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status);
                return r.text();
            })
            .then(function (html) {
                contentEl.innerHTML = html;
                /* Re-execute scripts (both inline and external src) */
                contentEl.querySelectorAll('script').forEach(function (old) {
                    var s = document.createElement('script');
                    if (old.src) {
                        s.src = old.src;
                        document.head.appendChild(s);
                    } else {
                        s.textContent = old.textContent;
                        document.body.appendChild(s);
                        document.body.removeChild(s);
                    }
                });
            })
            .catch(function () {
                contentEl.innerHTML =
                    '<div class="alert alert-danger m-3">'
                    + '<i class="fas fa-triangle-exclamation me-2"></i>'
                    + <?= json_encode(__('Failed to load content.')) ?>
                    + '</div>';
            });
    }

    /* ── Show the inline add-sighting form ── */
    function showAddForm() {
        var tpl = document.getElementById('sightingAddForm');
        contentEl.innerHTML = '';
        contentEl.appendChild(tpl.content.cloneNode(true));

        document.getElementById('sightingAdvForm').addEventListener('submit', async function (e) {
            e.preventDefault();
            var resultEl = document.getElementById('sightingAddResult');
            var formData = new FormData(this);
            var date  = formData.get('date') || '';
            var time  = formData.get('time') || '';
            var body  = 'data[Sighting][type]='    + encodeURIComponent(formData.get('type'))
                      + '&data[Sighting][source]='  + encodeURIComponent(formData.get('source') || '')
                      + '&data[Sighting][filters]=' + encodeURIComponent(formData.get('filters') || '');
            if (date) {
                body += '&data[Sighting][date_sighting]=' + encodeURIComponent(date + ' ' + (time || '00:00:00'));
            }

            resultEl.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i><?= __('Saving…') ?></div>';

            try {
                var r = await fetch(_addUrl, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type':     'application/x-www-form-urlencoded',
                        'Accept':           'application/json',
                        'X-CSRF-Token':     getCsrfToken(),
                    },
                    body: body,
                });
                var data = await r.json();
                if (data.saved) {
                    resultEl.innerHTML =
                        '<div class="alert alert-success py-1 small">'
                        + '<i class="fas fa-check me-1"></i>'
                        + <?= json_encode(__('Sighting added successfully.')) ?>
                        + '</div>';
                    showToast(<?= json_encode(__('Sighting added')) ?>, 'success');
                } else {
                    var err = typeof data.errors === 'string'
                        ? data.errors
                        : JSON.stringify(data.errors || {});
                    resultEl.innerHTML =
                        '<div class="alert alert-danger py-1 small">'
                        + escapeHtml(err) + '</div>';
                }
            } catch (_e) {
                resultEl.innerHTML =
                    '<div class="alert alert-danger py-1 small">'
                    + <?= json_encode(__('Request failed — please try again')) ?>
                    + '</div>';
            }
        });
    }

    /* ── Tab click handler ── */
    document.getElementById('sightingAdvTabs').addEventListener('click', function (e) {
        var btn = e.target.closest('[data-tab]');
        if (!btn) return;
        e.preventDefault();

        document.querySelectorAll('#sightingAdvTabs .nav-link').forEach(function (el) {
            el.classList.remove('active');
        });
        btn.classList.add('active');

        if (btn.dataset.tab === 'add') {
            showAddForm();
        } else {
            loadRemote(btn.dataset.url);
        }
    });

    /* ── Auto-load first tab (Graph) ── */
    var firstTab = document.querySelector('#sightingAdvTabs .nav-link.active');
    if (firstTab) loadRemote(firstTab.dataset.url);
})();
</script>
