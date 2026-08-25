<?php
$mergeOrgs = $mergeOrgs ?? [];
$sourceId  = $mergeSourceId ?? null;
$targetId  = $mergeTargetId ?? null;
$canMerge  = count($mergeOrgs) >= 2;

$orgOptions = [];
foreach ($mergeOrgs as $org) {
    $orgOptions[$org['id']] = sprintf(
        '%s · #%d · %s',
        $org['name'],
        $org['id'],
        $org['local'] ? __('Local') : __('Remote')
    );
}

$identityCard = function ($side, $accent) {
    ob_start(); ?>
    <div class="border rounded-3 p-3" id="merge<?= $side ?>Panel"
         style="border-left:4px solid var(--bs-<?= $accent ?>) !important; background:var(--bs-body-secondary-bg, var(--bs-secondary-bg));">
        <div class="text-muted small" data-role="placeholder">
            <i class="fas fa-circle-info me-1"></i><?= __('No organisation selected yet.') ?>
        </div>
        <div class="d-none" data-role="details">
            <div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
                <span class="fw-bold text-break" data-role="name"></span>
                <span class="badge" data-role="type"></span>
            </div>
            <div class="d-flex flex-column gap-1" style="font-size:.78rem;">
                <div class="d-flex gap-2">
                    <span class="text-muted" style="min-width:3.5rem;"><?= __('ID') ?></span>
                    <span class="font-monospace" data-role="id"></span>
                </div>
                <div class="d-flex gap-2">
                    <span class="text-muted" style="min-width:3.5rem;"><?= __('UUID') ?></span>
                    <span class="font-monospace text-break" data-role="uuid"></span>
                </div>
                <div class="d-flex gap-2">
                    <span class="text-muted" style="min-width:3.5rem;"><?= __('Users') ?></span>
                    <span data-role="users"></span>
                </div>
            </div>
        </div>
    </div>
    <?php return ob_get_clean();
};
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(220,53,69,.06);
            border-bottom:2px solid var(--bs-danger);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-danger"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Organisations') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-code-merge text-danger" style="font-size:1.25rem;"></i>
            <?= __('Merge Organisations') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Hand over every record of one organisation to another one, then remove the emptied organisation.') ?>
        </p>
    </div>
    <span class="misp-icon misp-icon-organisation misp-simple text-danger"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">

    <?php if (!$canMerge): ?>
        <div class="alert alert-info d-flex align-items-center gap-2 mb-0" role="alert">
            <i class="fas fa-circle-info"></i>
            <div style="font-size:.85rem;">
                <?= __('At least two organisations are required to perform a merge.') ?>
            </div>
        </div>
        <div class="d-flex justify-content-end mt-4 pt-3" style="border-top:1px solid #d8dde3;">
            <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Close') ?>
            </button>
        </div>
    <?php else: ?>

    <?= $this->Form->create('Organisation', [
        'id' => 'OrganisationMergeForm',
        'url' => $baseurl . '/admin/organisations/merge',
        'class' => 'm-0',
        'novalidate' => true,
    ]) ?>

    <div class="alert alert-danger d-flex gap-2 mb-4" role="alert">
        <i class="fas fa-triangle-exclamation mt-1"></i>
        <div style="font-size:.85rem;">
            <div class="fw-semibold"><?= __('This operation is irreversible.') ?></div>
            <?= __('Every user, event, attribute, sharing group membership and log entry belonging to the merged organisation is reassigned, and the organisation itself is then deleted.') ?>
        </div>
    </div>

    <div class="row g-3 align-items-stretch">

        <!-- ── SOURCE ──────────────────────────────────────────── -->
        <div class="col-md-5">
            <div class="d-flex align-items-center gap-2 text-danger fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Organisation to merge') ?>
                <span class="badge bg-danger" style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REMOVED') ?>
                </span>
            </div>
            <?= $this->Form->select('sourceOrg', $orgOptions, [
                'class' => 'form-select tom-select mb-3',
                'id' => 'mergeSourceSelect',
                'empty' => __('Select an organisation…'),
                'default' => $sourceId,
                'data-placeholder' => __('Search an organisation…'),
            ]) ?>
            <?= $identityCard('Source', 'danger') ?>
        </div>

        <!-- ── ARROW ───────────────────────────────────────────── -->
        <div class="col-md-2 d-flex flex-column align-items-center justify-content-center text-muted">
            <i class="fas fa-arrow-right-long d-none d-md-block" style="font-size:1.5rem; opacity:.5;"></i>
            <i class="fas fa-arrow-down-long d-md-none" style="font-size:1.25rem; opacity:.5;"></i>
            <span class="text-uppercase fw-semibold mt-2 text-center"
                  style="font-size:.55rem; letter-spacing:.1em;">
                <?= __('absorbed into') ?>
            </span>
        </div>

        <!-- ── TARGET ──────────────────────────────────────────── -->
        <div class="col-md-5">
            <div class="d-flex align-items-center gap-2 text-success fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Target organisation') ?>
                <span class="badge bg-success" style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('KEPT') ?>
                </span>
            </div>
            <?= $this->Form->select('targetOrg', $orgOptions, [
                'class' => 'form-select tom-select mb-3',
                'id' => 'mergeTargetSelect',
                'empty' => __('Select an organisation…'),
                'default' => $targetId,
                'data-placeholder' => __('Search an organisation…'),
            ]) ?>
            <?= $identityCard('Target', 'success') ?>
        </div>
    </div>

    <div class="alert alert-warning d-none py-2 px-3 mt-3 mb-0"
         id="mergeSameOrgWarning" role="alert" style="font-size:.8rem;">
        <i class="fas fa-triangle-exclamation me-1"></i>
        <?= __('An organisation cannot be merged into itself.') ?>
    </div>

    <!-- ── CONFIRMATION ────────────────────────────────────────── -->
    <div class="form-check mt-3 px-2 ms-2">
        <input class="form-check-input" type="checkbox" id="mergeConfirmCheck">
        <label class="form-check-label" for="mergeConfirmCheck" style="font-size:.82rem;">
            <?= __('I understand that this merge cannot be undone from the interface.') ?>
        </label>
    </div>

    <!-- ── FOOTER ──────────────────────────────────────────────── -->
    <div class="d-flex justify-content-end align-items-center mt-4 pt-3 flex-wrap gap-2"
         style="border-top:1px solid #d8dde3;">
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Cancel') ?>
            </button>
            <button type="submit" class="btn btn-danger btn-sm" id="mergeSubmitBtn" disabled
                    title="<?= h(__('Merge organisations')) ?>">
                <i class="fas fa-code-merge me-1"></i><?= __('Merge organisations') ?>
            </button>
        </div>
    </div>

    <?= $this->Form->end() ?>

    <script type="application/json" id="mergeOrgData"><?= json_encode(
        $mergeOrgs,
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    ) ?></script>
    <script>
    (function () {
        var dataNode = document.getElementById('mergeOrgData');
        var form = document.getElementById('OrganisationMergeForm');
        if (!dataNode || !form) {
            return;
        }
        var orgs = {};
        JSON.parse(dataNode.textContent).forEach(function (org) {
            orgs[String(org.id)] = org;
        });

        var sourceSelect = document.getElementById('mergeSourceSelect');
        var targetSelect = document.getElementById('mergeTargetSelect');
        var confirmCheck = document.getElementById('mergeConfirmCheck');
        var submitBtn = document.getElementById('mergeSubmitBtn');
        var sameOrgWarning = document.getElementById('mergeSameOrgWarning');
        var panels = [
            document.getElementById('mergeSourcePanel'),
            document.getElementById('mergeTargetPanel')
        ];
        var localLabel = <?= json_encode(__('Local'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        var remoteLabel = <?= json_encode(__('Remote'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

        function renderPanel(panel, org) {
            var placeholder = panel.querySelector('[data-role="placeholder"]');
            var details = panel.querySelector('[data-role="details"]');
            if (!org) {
                placeholder.classList.remove('d-none');
                details.classList.add('d-none');
                return;
            }
            placeholder.classList.add('d-none');
            details.classList.remove('d-none');
            panel.querySelector('[data-role="name"]').textContent = org.name;
            panel.querySelector('[data-role="id"]').textContent = org.id;
            panel.querySelector('[data-role="uuid"]').textContent = org.uuid || '-';
            panel.querySelector('[data-role="users"]').textContent = org.user_count;
            var type = panel.querySelector('[data-role="type"]');
            type.textContent = org.local ? localLabel : remoteLabel;
            type.className = 'badge ' + (org.local ? 'text-bg-success' : 'text-bg-secondary');
        }

        function update() {
            var source = orgs[sourceSelect.value] || null;
            var target = orgs[targetSelect.value] || null;
            renderPanel(panels[0], source);
            renderPanel(panels[1], target);

            // Prevent Merging an organisation into itself
            var sameOrg = !!source && !!target && source.id === target.id;
            sameOrgWarning.classList.toggle('d-none', !sameOrg);
            submitBtn.disabled = !(source && target && !sameOrg && confirmCheck.checked);
        }

        sourceSelect.addEventListener('change', update);
        targetSelect.addEventListener('change', update);
        confirmCheck.addEventListener('change', update);
        form.addEventListener('submit', function (event) {
            if (submitBtn.disabled) {
                event.preventDefault();
                return;
            }
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>'
                + '<?= h(__('Merging…')) ?>';
        });
        update();
    })();
    </script>

    <?php endif; ?>
</div>
