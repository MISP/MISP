<?php
$edit = $this->request->params['action'] === 'admin_edit';

// admin_add sets $dropdownData['options']; admin_edit sets $options. Normalise.
$permOptions = isset($dropdownData['options'])
    ? $dropdownData['options']
    : ($options ?? []);

$roleData = $this->request->data['Role'] ?? [];
$restsearchLimited = array_key_exists('restsearch_limit_result', $roleData)
    && !is_null($roleData['restsearch_limit_result']);

echo $this->Form->create('Role', [
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Roles'),
    'title' => $edit ? __('Edit Role') : __('Add Role'),
    'description' => __('Define what users assigned to this role are allowed to do on this instance.'),
    'icon' => 'fas fa-user-shield',
    'isEdit' => $edit,
]) ?>

<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ── IDENTITY ────────────────────────────────────────── -->
        <div class="w-100">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold text-uppercase mb-2 role-section-label">
                <?= __('Identity') ?>
                <span class="badge bg-primary" style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <div class="row g-3">
                <div class="col-md-6">
                    <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('name', ['class' => 'form-control', 'required' => true]) ?>
                </div>
                <div class="col-md-6">
                    <?= $this->Form->label('permission', __('Data access level'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('permission', $permOptions, [
                        'id' => 'RolePermission',
                        'class' => 'form-select',
                        'value' => $roleData['permission'] ?? '3',
                        'empty' => false,
                    ]) ?>
                </div>
            </div>

            <!-- RESTRICT TO SITE ADMINS -->
            <div class="form-check form-switch mt-3">
                <?= $this->Form->checkbox('restricted_to_site_admin', [
                    'class' => 'form-check-input',
                    'id' => 'RoleRestrictedToSiteAdmin',
                    'checked' => !empty($roleData['restricted_to_site_admin']),
                ]) ?>
                <label class="form-check-label" for="RoleRestrictedToSiteAdmin">
                    <?= __('Restrict to site admins') ?>
                    <i class="fas fa-info-circle text-muted ms-1"
                       title="<?= h(__('Only site admins will be able to assign this role to users.')) ?>"></i>
                </label>
            </div>
        </div>

        <!-- ── RESOURCE LIMITS ─────────────────────────────────── -->
        <div class="w-100">
            <div class="text-primary fw-bold text-uppercase mb-2 role-section-label">
                <?= __('Resource Limits') ?>
            </div>
            <div class="row g-3">
                <div class="col-md-6">
                    <?= $this->Form->label('memory_limit', __('Memory limit (%s)', h($default_memory_limit)), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('memory_limit', ['class' => 'form-control', 'placeholder' => h($default_memory_limit)]) ?>
                </div>
                <div class="col-md-6">
                    <?= $this->Form->label('max_execution_time', __('Maximum execution time (%ss)', h($default_max_execution_time)), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('max_execution_time', ['class' => 'form-control', 'placeholder' => h($default_max_execution_time)]) ?>
                </div>
            </div>

            <!-- ENFORCE RATE LIMIT -->
            <div class="form-check form-switch mt-3 mb-2">
                <?= $this->Form->checkbox('enforce_rate_limit', [
                    'class' => 'form-check-input',
                    'id' => 'RoleEnforceRateLimit',
                    'checked' => !empty($roleData['enforce_rate_limit']),
                ]) ?>
                <?= $this->Form->label('RoleEnforceRateLimit', __('Enforce search rate limit'), ['class' => 'form-check-label']) ?>
            </div>
            <div id="rateLimitCountContainer" class="mb-2 ps-4">
                <?= $this->Form->label('rate_limit_count', __('# of searches / 15 min'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('rate_limit_count', ['class' => 'form-control']) ?>
            </div>

            <!-- LIMIT RESTSEARCH RESULTS -->
            <div class="form-check form-switch mt-3 mb-2">
                <?= $this->Form->checkbox('is_restsearch_limited', [
                    'class' => 'form-check-input',
                    'id' => 'RoleIsRestsearchLimited',
                    'checked' => $restsearchLimited,
                ]) ?>
                <label class="form-check-label" for="RoleIsRestsearchLimited">
                    <?= __('Limit restSearch results') ?>
                    <i class="fas fa-info-circle text-muted ms-1"
                       title="<?= h(__('If unset, will be the default setting for the server. Set 0 to allow unlimited.')) ?>"></i>
                </label>
            </div>
            <div id="restsearchLimitValueContainer" class="mb-1 ps-4">
                <?= $this->Form->label('restsearch_limit_result', __('# of results per search'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('restsearch_limit_result', ['class' => 'form-control']) ?>
            </div>
        </div>

        <!-- ── PERMISSION FLAGS ────────────────────────────────── -->
        <div class="w-100">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold text-uppercase mb-2 role-section-label">
                <?= __('Permission Flags') ?>
                <span class="fw-normal text-muted text-lowercase" style="letter-spacing:normal; font-size:.7rem;">
                    (<?= __('click to grant or deny') ?>)
                </span>
            </div>
            <div class="d-flex flex-wrap gap-2 role-permissions">
                <?php foreach ($permFlags as $k => $flag): ?>
                    <?php
                        $readonlyClass = $flag['readonlyenabled'] ? 'readonlyenabled' : 'readonlydisabled';
                        $siteAdminClass = empty($flag['site_admin_optional']) ? 'site_admin_enforced' : 'site_admin_optional';
                        $granted = !empty($roleData[$k]);
                        $cbId = 'Role' . Inflector::camelize($k);
                    ?>
                    <label class="perm-pill <?= $readonlyClass ?><?= $granted ? ' granted' : '' ?>"
                           for="<?= h($cbId) ?>"
                           title="<?= h($flag['title'] ?? '') ?>">
                        <?= $this->Form->checkbox($k, [
                            'class' => sprintf('d-none perm-pill-input %s %s', $readonlyClass, $siteAdminClass),
                            'checked' => $granted,
                        ]) ?>
                        <i class="fas fa-check perm-pill-check"></i>
                        <span><?= h($flag['text']) ?></span>
                    </label>
                <?php endforeach; ?>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $edit,
        'hint' => __('Permissions can be fine-tuned at any time from the role view.'),
        'cancel' => ['label' => __('Cancel')],
        'submit' => [
            'label' => $edit ? __('Save Changes') : __('Add Role'),
            'icon' => 'fas fa-check',
        ],
    ]) ?>

</div>

<?= $this->Form->end(); ?>

<script>
(function () {

    var modalBody = document.getElementById('mainModalBody');
    var form = (modalBody && modalBody.querySelector('form.needs-validation'))
        || document.querySelector('form.needs-validation');
    if (!form) { return; }

    var permSelect      = form.querySelector('#RolePermission');
    var siteAdminInput  = form.querySelector('#RolePermSiteAdmin');
    var rateSwitch      = form.querySelector('#RoleEnforceRateLimit');
    var rateContainer   = form.querySelector('#rateLimitCountContainer');
    var restrictSwitch  = form.querySelector('#RoleIsRestsearchLimited');
    var restrictContainer = form.querySelector('#restsearchLimitValueContainer');
    var restrictValue   = form.querySelector('#RoleRestsearchLimitResult');

    function syncPill(pill) {
        if (!pill) { return; }
        var input = pill.querySelector('.perm-pill-input');
        pill.classList.toggle('granted', !!(input && input.checked));
    }

    function refreshPerms() {
        var low = permSelect && (permSelect.value === '0' || permSelect.value === '1');
        form.querySelectorAll('.perm-pill').forEach(function (pill) {
            if (pill.classList.contains('readonlydisabled')) {
                var input = pill.querySelector('.perm-pill-input');
                if (low) {
                    if (input) { input.checked = false; }
                    pill.classList.add('d-none');
                } else {
                    pill.classList.remove('d-none');
                }
            }
            syncPill(pill);
        });
        if (siteAdminInput && siteAdminInput.checked) {
            form.querySelectorAll('.perm-pill-input.site_admin_enforced').forEach(function (input) {
                input.checked = true;
                syncPill(input.closest('.perm-pill'));
            });
        }
    }

    function toggleContainer(sw, container) {
        if (sw && container) {
            container.classList.toggle('d-none', !sw.checked);
        }
    }

    // Keep each pill's visual state in sync
    form.querySelectorAll('.perm-pill-input').forEach(function (input) {
        input.addEventListener('change', function () {
            syncPill(input.closest('.perm-pill'));
            if (input === siteAdminInput) { refreshPerms(); }
        });
    });

    if (permSelect)     { permSelect.addEventListener('change', refreshPerms); }
    if (rateSwitch)     { rateSwitch.addEventListener('change', function () { toggleContainer(rateSwitch, rateContainer); }); }
    if (restrictSwitch) { restrictSwitch.addEventListener('change', function () { toggleContainer(restrictSwitch, restrictContainer); }); }

    form.addEventListener('submit', function () {
        if (restrictSwitch && !restrictSwitch.checked && restrictValue) {
            restrictValue.value = '';
        }
    });

    // Initial state
    refreshPerms();
    toggleContainer(rateSwitch, rateContainer);
    toggleContainer(restrictSwitch, restrictContainer);
})();
</script>
