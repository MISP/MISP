<?php

App::uses('ClassRegistry', 'Utility');
App::uses('EventTemplateDependencies', 'Tools');


$__uid = 'etTp' . substr(md5(uniqid('etTp', true)), 0, 8);

// Event templating needs composer packages that MISP's upgrade flow does not
// install. Every event_templates action refuses to run while they are missing,
// so the picker must say so up front rather than hand out links that 503.
$__missingDeps = EventTemplateDependencies::missing();
$__unavailable = !empty($__missingDeps);

$__templates = [];
if (!$__unavailable) {
    // Same visibility rule as EventTemplatesController::__visibilityConditions().
    $__conditions = ['EventTemplate.active' => 1];
    if (empty($isSiteAdmin)) {
        $__conditions['OR'] = [
            'EventTemplate.org_id' => (int)$me['org_id'],
            'EventTemplate.distribution' => 1,
        ];
    }
    $__templates = ClassRegistry::init('EventTemplate')->find('all', [
        'recursive' => -1,
        'conditions' => $__conditions,
        'fields' => [
            'EventTemplate.id',
            'EventTemplate.name',
            'EventTemplate.description',
            'EventTemplate.modified',
            'EventTemplate.org_id',
        ],
        'contain' => [
            'Organisation' => ['fields' => ['Organisation.id', 'Organisation.name']],
        ],
        'order' => ['EventTemplate.modified' => 'DESC'],
    ]);
}

$__canBuild = !$__unavailable && $this->Acl->canAccess('eventTemplates', 'add');
$__canManage = $this->Acl->canAccess('eventTemplates', 'index');
$__count = count($__templates);

// The header band swaps to a warning tone when the feature can't run, so the
// modal reads as a diagnostic rather than a broken picker.
$__accent = $__unavailable ? 'var(--bs-warning)' : 'var(--event, var(--primary))';
$__tint = $__unavailable ? 'rgba(255,193,7,.08)' : 'rgba(24,146,177,.06)';
$__accentText = $__unavailable ? 'text-warning-emphasis' : 'text-event';
$__accentIcon = $__unavailable ? 'text-warning' : 'text-event';
$__fixCommand = 'cd ' . rtrim(APP, DS) . ' && composer install';
?>
<div class="modal fade et-template-picker" id="<?= h($__uid) ?>" tabindex="-1"
     aria-labelledby="<?= h($__uid) ?>-title" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-xl">
        <div class="modal-content border-0" style="margin:auto;">
            <div class="modal-body p-0 m-0">

                <!-- ── MODAL HEADER ─────────────────────────────────── -->
                <div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
                     style="background:<?= $__tint ?>;
                            border-bottom:2px solid <?= $__accent ?>;">
                    <div>
                        <div class="<?= $__accentText ?> text-uppercase fw-semibold mb-1"
                             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
                            <?= __('Events') ?>
                        </div>
                        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2"
                            id="<?= h($__uid) ?>-title">
                            <i class="fas fa-<?= $__unavailable ? 'plug-circle-exclamation' : 'circle-plus' ?> <?= $__accentIcon ?>"
                               style="font-size:1.25rem;"></i>
                            <?= $__unavailable
                                ? __('Event templating is unavailable')
                                : __('Create Event from Template') ?>
                        </h4>
                        <p class="text-muted mb-0" style="font-size:.75rem;">
                            <?= $__unavailable
                                ? __('This MISP instance is missing PHP packages that the event-templating feature depends on.')
                                : __('Pick a guided template — it walks you through the fields and builds the event, its attributes and its objects for you.') ?>
                        </p>
                    </div>
                    <span class="fas fa-wand-magic-sparkles <?= $__accentIcon ?>"
                          style="font-size:2rem; opacity:.5;"></span>
                </div>

                <!-- ── BODY ─────────────────────────────────────────── -->
                <div class="p-4">

                    <?php if ($__unavailable): ?>
                        <div class="fw-bold text-uppercase mb-2 text-primary"
                             style="font-size:.65rem; letter-spacing:.1em;">
                            <?= __('Missing PHP package(s)') ?>
                        </div>
                        <ul class="list-group mb-4">
                            <?php foreach ($__missingDeps as $__package): ?>
                                <li class="list-group-item d-flex align-items-center gap-2 py-2">
                                    <i class="fas fa-cube text-muted" style="font-size:.75rem;"></i>
                                    <code class="text-body"><?= h($__package) ?></code>
                                </li>
                            <?php endforeach; ?>
                        </ul>

                        <div class="fw-bold text-uppercase mb-2 text-primary"
                             style="font-size:.65rem; letter-spacing:.1em;">
                            <?= __('How to fix it') ?>
                        </div>
                        <p class="text-muted" style="font-size:.85rem;">
                            <?= __('MISP\'s standard upgrade flow (git pull + %s) does not install composer packages. An administrator has to run the following on the MISP host, then reload this page.',
                                '<code>cake Admin runUpdates</code>') ?>
                        </p>
                        <div class="border rounded bg-body-tertiary px-3 py-2 d-flex align-items-center
                                    justify-content-between gap-2">
                            <code class="text-body" style="font-size:.8rem;"><?= h($__fixCommand) ?></code>
                            <button type="button" class="btn btn-sm btn-outline-secondary flex-shrink-0"
                                    onclick="copyValueToClipboard(<?= h(json_encode($__fixCommand)) ?>, <?= h(json_encode(__('Command copied'))) ?>)">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>

                        <?php if (empty($isSiteAdmin)): ?>
                            <div class="alert alert-light border mt-3 mb-0" role="alert"
                                 style="font-size:.8rem;">
                                <i class="fas fa-circle-info me-1 text-primary"></i>
                                <?= __('You do not have the privileges to fix this yourself — contact your MISP administrator.') ?>
                            </div>
                        <?php endif; ?>
                    <?php elseif ($__count): ?>
                        <div class="input-group mb-3">
                            <span class="input-group-text bg-body-tertiary border-end-0">
                                <i class="fas fa-magnifying-glass text-muted"></i>
                            </span>
                            <input type="text"
                                   class="form-control border-start-0 ps-0 et-tp-search"
                                   autocomplete="off"
                                   placeholder="<?= h(__('Filter by name, description, or organisation…')) ?>"
                                   aria-label="<?= h(__('Filter templates')) ?>">
                        </div>

                        <div class="et-tp-list row row-cols-1 row-cols-md-2 g-2"
                             style="max-height:52vh; overflow-y:auto;">
                            <?php foreach ($__templates as $__t):
                                $__tpl = $__t['EventTemplate'];
                                $__org = !empty($__t['Organisation']['name'])
                                    ? $__t['Organisation']['name']
                                    : '';
                                $__desc = trim((string)$__tpl['description']);
                                $__modified = !empty($__tpl['modified'])
                                    ? date('Y-m-d', strtotime($__tpl['modified']))
                                    : '';
                                $__haystack = strtolower(
                                    $__tpl['name'] . ' ' . $__desc . ' ' . $__org
                                );
                            ?>
                            <div class="col et-tp-col" data-search="<?= h($__haystack) ?>">
                                <a class="et-tp-item border rounded p-3 h-100 d-flex gap-3
                                          text-decoration-none"
                                   href="<?= h($baseurl . '/event_templates/instantiate/'
                                        . (int)$__tpl['id']) ?>">
                                    <span class="et-tp-icon flex-shrink-0 rounded d-flex
                                                 align-items-center justify-content-center">
                                        <i class="fas fa-clone text-event"></i>
                                    </span>
                                    <span class="flex-grow-1 min-w-0">
                                        <span class="d-block fw-bold text-body"
                                              style="font-size:.875rem; line-height:1.25;">
                                            <?= h($__tpl['name']) ?>
                                        </span>
                                        <?php if ($__desc !== ''): ?>
                                            <span class="et-tp-desc d-block text-muted mt-1"
                                                  style="font-size:.75rem; line-height:1.3;">
                                                <?= h($__desc) ?>
                                            </span>
                                        <?php endif; ?>
                                        <span class="d-flex flex-wrap align-items-center gap-2 mt-2
                                                     text-muted"
                                              style="font-size:.7rem;">
                                            <?php if ($__org !== ''): ?>
                                                <span class="badge rounded-pill border
                                                             bg-body-tertiary text-body-secondary
                                                             fw-normal">
                                                    <i class="fas fa-building me-1"></i><?= h($__org) ?>
                                                </span>
                                            <?php endif; ?>
                                            <?php if ($__modified !== ''): ?>
                                                <span>
                                                    <i class="fas fa-clock me-1"></i><?= h($__modified) ?>
                                                </span>
                                            <?php endif; ?>
                                        </span>
                                    </span>
                                    <i class="fas fa-chevron-right text-muted align-self-center
                                              flex-shrink-0" style="font-size:.7rem;"></i>
                                </a>
                            </div>
                            <?php endforeach; ?>
                        </div>

                        <div class="et-tp-nomatch text-center text-muted py-4 d-none">
                            <i class="fas fa-magnifying-glass d-block mb-2"
                               style="font-size:1.5rem; opacity:.4;"></i>
                            <?= __('No template matches your filter.') ?>
                        </div>
                    <?php else: ?>
                        <div class="d-flex flex-column align-items-center text-muted py-5">
                            <i class="fas fa-wand-magic-sparkles d-block mb-3"
                               style="font-size:2rem; opacity:.35;"></i>
                            <div class="fw-semibold mb-1" style="font-size:.9rem;">
                                <?= __('No active event template is visible to you.') ?>
                            </div>
                            <div style="font-size:.8rem;">
                                <?= __('Templates must be flagged active before they show up here.') ?>
                            </div>
                        </div>
                    <?php endif; ?>

                    <!-- ── FOOTER ───────────────────────────────────── -->
                    <div class="d-flex justify-content-between align-items-center
                                mt-4 pt-3 flex-wrap gap-2"
                         style="border-top:1px solid var(--bs-border-color, #dee2e6);">
                        <div class="text-muted d-flex align-items-center gap-3"
                             style="font-size:.75rem;">
                            <?php if ($__count): ?>
                                <span class="et-tp-count"
                                      data-label-one="<?= h(__('%s template available')) ?>"
                                      data-label-many="<?= h(__('%s templates available')) ?>">
                                    <?= h(sprintf(
                                        $__count === 1
                                            ? __('%s template available')
                                            : __('%s templates available'),
                                        $__count
                                    )) ?>
                                </span>
                            <?php endif; ?>
                            <?php if ($__canManage && !$__unavailable): ?>
                                <a href="<?= h($baseurl . '/event_templates/index') ?>"
                                   class="text-decoration-none">
                                    <i class="fas fa-list me-1"></i><?= __('Manage templates') ?>
                                </a>
                            <?php endif; ?>
                        </div>
                        <div class="d-flex gap-2">
                            <button type="button" class="btn btn-outline-secondary btn-sm"
                                    data-bs-dismiss="modal">
                                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
                            </button>
                            <?php if ($__unavailable && $__canManage): ?>
                                <a href="<?= h($baseurl . '/event_templates/index') ?>"
                                   class="btn btn-primary btn-sm">
                                    <i class="fas fa-circle-info me-1"></i><?= __('More details') ?>
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </div>
</div>

<script>
(function () {
    var node = document.getElementById(<?= json_encode($__uid,
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>);
    if (!node) {
        return;
    }
    document.querySelectorAll('.et-template-picker').forEach(function (other) {
        if (other !== node) { other.remove(); }
    });
    if (node.parentNode !== document.body) { document.body.appendChild(node); }

    var search = node.querySelector('.et-tp-search');
    var cols = Array.prototype.slice.call(node.querySelectorAll('.et-tp-col'));
    var noMatch = node.querySelector('.et-tp-nomatch');
    var list = node.querySelector('.et-tp-list');
    var count = node.querySelector('.et-tp-count');

    function applyFilter() {
        var term = (search ? search.value : '').toLowerCase().trim();
        var visible = 0;
        cols.forEach(function (col) {
            var hit = !term
                || (col.getAttribute('data-search') || '').indexOf(term) !== -1;
            col.classList.toggle('d-none', !hit);
            if (hit) { visible++; }
        });
        if (list) { list.classList.toggle('d-none', visible === 0); }
        if (noMatch) { noMatch.classList.toggle('d-none', visible !== 0); }
        if (count) {
            var label = visible === 1
                ? count.getAttribute('data-label-one')
                : count.getAttribute('data-label-many');
            count.textContent = label.replace('%s', visible);
        }
    }

    if (search) {
        search.addEventListener('input', applyFilter);

        search.addEventListener('keydown', function (e) {
            if (e.key !== 'Enter') { return; }
            e.preventDefault();
            var first = node.querySelector('.et-tp-col:not(.d-none) .et-tp-item');
            if (first) { first.click(); }
        });
    }

    function show() {
        window.bootstrap.Modal.getOrCreateInstance(node).show();
        if (search) { window.setTimeout(function () { search.focus(); }, 200); }
    }

    node.addEventListener('click', function (e) {
        var item = e.target.closest ? e.target.closest('.et-tp-item') : null;
        if (!item || typeof window.openModal !== 'function') { return; }
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) {
            return;
        }
        var url = item.getAttribute('href');
        if (!url) { return; }
        e.preventDefault();

        var inst = (window.bootstrap && window.bootstrap.Modal)
            ? window.bootstrap.Modal.getInstance(node)
            : null;
        if (!inst || !node.classList.contains('show')) {
            window.openModal(url, 'xl');
            return;
        }

        var handedOver = false;
        function handOver() {
            if (handedOver) { return; }
            handedOver = true;
            node.removeEventListener('hidden.bs.modal', handOver);
            window.openModal(url, 'xl');
        }
        node.addEventListener('hidden.bs.modal', handOver);

        var attempts = 0;
        (function closeThenHandOver() {
            if (handedOver) { return; }
            if (!node.classList.contains('show')) { handOver(); return; }
            inst.hide();
            attempts += 1;
            if (attempts < 6) {
                window.setTimeout(closeThenHandOver, 150);
            } else {
                handOver();
            }
        }());
    });

    window.openEventTemplatePicker = function () {
        if (!window.bootstrap || !window.bootstrap.Modal) { return; }
        if (search) { search.value = ''; }
        applyFilter();

        // Opened from the Add Event modal: close that one first so the two
        // never stack (a second backdrop would grey out the picker).
        var main = document.getElementById('mainModal');
        var inst = main ? window.bootstrap.Modal.getInstance(main) : null;
        if (inst && main.classList.contains('show')) {
            main.addEventListener('hidden.bs.modal', function handler() {
                main.removeEventListener('hidden.bs.modal', handler);
                show();
            });
            inst.hide();
            return;
        }
        show();
    };
})();
</script>
