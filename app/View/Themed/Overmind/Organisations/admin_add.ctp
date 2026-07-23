<?php
$edit = $this->request->params['action'] === 'admin_edit';
$orgData = $this->request->data['Organisation'] ?? [];
$svgAllowed = (bool)Configure::read('Security.enable_svg_logos');
$isLocal = $edit ? !empty($orgData['local']) : true;

echo $this->Form->create('Organisation', [
    'type' => 'file',
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-primary"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Organisations') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $edit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $edit ? __('Edit Organisation') : __('Add Organisation') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= $edit
                ? __('Update the identity, classification and access rules of this organisation.')
                : __('Register a member organisation of this instance, or a known external entity for use in sharing groups.') ?>
        </p>
    </div>
    <span class="misp-icon misp-icon-organisation misp-simple text-primary"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">

    <?php if (!empty($duplicate_org)): ?>
        <div class="alert alert-warning d-flex align-items-center gap-2 mb-4" role="alert">
            <i class="fas fa-triangle-exclamation"></i>
            <div class="flex-grow-1" style="font-size:.85rem;">
                <?= __('An organisation with this UUID already exists.') ?>
            </div>
            <a href="<?= $baseurl ?>/organisations/view/<?= h($duplicate_org) ?>"
               class="btn btn-sm btn-outline-primary text-nowrap" target="_blank" rel="noopener">
                <i class="fas fa-up-right-from-square me-1"></i><?= __('View organisation') ?>
            </a>
        </div>
    <?php endif; ?>

    <div class="d-flex flex-column gap-4">

        <!-- ── SCOPE ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Scope') ?>
            </div>
            <label class="d-flex align-items-center justify-content-between border rounded-3 p-3 bg-light w-100"
                   style="cursor:pointer;">
                <div class="d-flex align-items-center gap-3">
                    <span class="d-inline-flex align-items-center justify-content-center rounded-circle flex-shrink-0"
                          style="width:2.25rem;height:2.25rem;background:rgba(24,146,177,.12);">
                        <i class="fas fa-house-flag text-primary"></i>
                    </span>
                    <div>
                        <span class="fw-semibold d-block">
                            <?= __('Local organisation') ?>
                        </span>
                        <span class="text-muted small">
                            <?= __('When enabled, this organisation has a presence on this instance. Leave off to register a known external organisation only for use in sharing groups.') ?>
                        </span>
                    </div>
                </div>
                <div class="form-check form-switch m-0 ps-0">
                    <?= $this->Form->checkbox('local', [
                        'class' => 'form-check-input ms-0',
                        'id' => 'OrganisationLocal',
                        'role' => 'switch',
                        'hiddenField' => true,
                        'checked' => $isLocal,
                        'style' => 'width:3rem;height:1.5rem;cursor:pointer;',
                    ]) ?>
                </div>
            </label>
        </div>

        <!-- ── IDENTITY ────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Identity') ?>
                <span class="badge bg-primary" style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <div class="row g-3">
                <!-- NAME -->
                <div class="col-md-6">
                    <?= $this->Form->label('name', __('Organisation identifier'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('name', [
                        'class' => 'form-control',
                        'placeholder' => __('Brief organisation identifier'),
                        'required' => true,
                    ]) ?>
                </div>

                <!-- UUID -->
                <div class="col-md-6">
                    <?= $this->Form->label('uuid', __('UUID'), ['class' => 'form-label fw-semibold']) ?>
                    <div class="input-group">
                        <?= $this->Form->text('uuid', [
                            'class' => 'form-control font-monospace',
                            'id' => 'OrganisationUuid',
                            'placeholder' => __('Paste UUID or click generate'),
                        ]) ?>
                        <button type="button" class="btn btn-outline-secondary" id="generateOrgUuidBtn"
                            title="<?= h(__('Generate a new UUID for the organisation')) ?>">
                            <i class="fas fa-wand-magic-sparkles me-1"></i><?= __('Generate') ?>
                        </button>
                    </div>
                </div>

                <!-- LOGO -->
                <div class="col-12">
                    <?= $this->Form->label('logo', __('Logo (48×48 %s)', $svgAllowed ? 'PNG or SVG' : 'PNG'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->file('logo', ['class' => 'form-control']) ?>
                </div>
            </div>
        </div>

        <!-- ── CLASSIFICATION ──────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Classification') ?>
            </div>
            <div class="row g-3">
                <!-- NATIONALITY -->
                <div class="col-md-4">
                    <?= $this->Form->label('nationality', __('Nationality'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('nationality', $countries, [
                        'class' => 'form-select tom-select',
                        'empty' => false,
                    ]) ?>
                </div>

                <!-- SECTOR -->
                <div class="col-md-4">
                    <?= $this->Form->label('sector', __('Sector'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('sector', [
                        'class' => 'form-control',
                        'placeholder' => __('For example "financial".'),
                    ]) ?>
                </div>

                <!-- TYPE -->
                <div class="col-md-4">
                    <?= $this->Form->label('type', __('Type of organisation'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('type', [
                        'class' => 'form-control',
                        'placeholder' => __('Freetext description of the org.'),
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ── DETAILS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Details') ?>
            </div>
            <div class="d-flex flex-column gap-3">
                <!-- DESCRIPTION -->
                <div>
                    <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control',
                        'rows' => 2,
                        'placeholder' => __('A description of the organisation that is purely informational.'),
                    ]) ?>
                </div>

                <!-- CONTACTS -->
                <div>
                    <?= $this->Form->label('contacts', __('Contact details'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('contacts', [
                        'class' => 'form-control',
                        'rows' => 2,
                        'placeholder' => __('You can add some contact details for the organisation here, if applicable.'),
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ── ACCESS CONTROL ──────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Access Control') ?>
            </div>
            <?= $this->Form->label('restricted_to_domain', __('Bind user accounts to domains (line separated)'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->textarea('restricted_to_domain', [
                'class' => 'form-control font-monospace',
                'rows' => 2,
                'placeholder' => "example.com\npartner.org",
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted" style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('When set, users of this organisation can only be created with email addresses on these domains.') ?>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-end align-items-center mt-4 pt-3 flex-wrap gap-2"
         style="border-top:1px solid #d8dde3;">

        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Cancel') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($edit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($edit ? __('Save changes') : __('Add organisation')),
                [
                    'class' => 'btn btn-primary btn-sm',
                    'escapeTitle' => false,
                    'title' => $edit ? __('Save changes') : __('Add organisation'),
                    'aria-label' => $edit ? __('Save changes') : __('Add organisation'),
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end(); ?>

<script>
var _orgBase = <?= json_encode($baseurl, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
var _orgUuidBtn = document.getElementById('generateOrgUuidBtn');
var _orgUuidInput = document.getElementById('OrganisationUuid');
if (_orgUuidBtn && _orgUuidInput) {
    _orgUuidBtn.addEventListener('click', function () {
        fetch(_orgBase + '/admin/organisations/generateuuid.json', {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data && data.uuid) {
                _orgUuidInput.value = data.uuid;
            } else if (window.crypto && crypto.randomUUID) {
                _orgUuidInput.value = crypto.randomUUID();
            }
        })
        .catch(function () {
            // Offline / endpoint unreachable — fall back to a client-side v4 UUID.
            if (window.crypto && crypto.randomUUID) {
                _orgUuidInput.value = crypto.randomUUID();
            }
        });
    });
}
</script>
