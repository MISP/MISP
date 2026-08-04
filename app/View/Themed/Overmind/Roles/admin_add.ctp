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
    'novalidate' => true
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-3">
                    <?= $edit ? __('Edit Role') : __('Add Role') ?>
                </h3>

                <!-- RESTRICT TO SITE ADMINS -->
                <div class="form-check form-switch mb-3">
                    <?= $this->Form->checkbox('restricted_to_site_admin', [
                        'class' => 'form-check-input readonlyenabled',
                        'id' => 'RoleRestrictedToSiteAdmin',
                        'checked' => !empty($roleData['restricted_to_site_admin']),
                    ]) ?>
                    <?= $this->Form->label('RoleRestrictedToSiteAdmin', __('Restrict to site admins'), ['class' => 'form-check-label']) ?>
                </div>

                <div class="row">
                    <!-- NAME -->
                    <div class="col-md-6 mb-3">
                        <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->text('name', ['class' => 'form-control', 'required' => true]) ?>
                    </div>

                    <!-- PERMISSION -->
                    <div class="col-md-6 mb-3">
                        <?= $this->Form->label('permission', __('Permissions'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->select('permission', $permOptions, [
                            'id' => 'RolePermission',
                            'class' => 'form-select',
                            'value' => $roleData['permission'] ?? '3',
                            'empty' => false,
                        ]) ?>
                    </div>
                </div>

                <div class="row">
                    <!-- MEMORY LIMIT -->
                    <div class="col-md-6 mb-3">
                        <?= $this->Form->label('memory_limit', __('Memory limit (%s)', h($default_memory_limit)), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->text('memory_limit', ['class' => 'form-control']) ?>
                    </div>

                    <!-- MAX EXECUTION TIME -->
                    <div class="col-md-6 mb-3">
                        <?= $this->Form->label('max_execution_time', __('Maximum execution time (%ss)', h($default_max_execution_time)), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->text('max_execution_time', ['class' => 'form-control']) ?>
                    </div>
                </div>

                <!-- ENFORCE RATE LIMIT -->
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('enforce_rate_limit', [
                        'class' => 'form-check-input',
                        'id' => 'RoleEnforceRateLimit',
                        'checked' => !empty($roleData['enforce_rate_limit']),
                    ]) ?>
                    <?= $this->Form->label('RoleEnforceRateLimit', __('Enforce search rate limit'), ['class' => 'form-check-label']) ?>
                </div>
                <div id="rateLimitCountContainer" class="mb-3">
                    <?= $this->Form->label('rate_limit_count', __('# of searches / 15 min'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('rate_limit_count', ['class' => 'form-control']) ?>
                </div>

                <!-- LIMIT RESTSEARCH RESULTS -->
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('is_restsearch_limited', [
                        'class' => 'form-check-input',
                        'id' => 'RoleIsRestsearchLimited',
                        'checked' => $restsearchLimited,
                    ]) ?>
                    <label class="form-check-label" for="RoleIsRestsearchLimited">
                        <?= __('Limit restSearch Results') ?>
                        <i class="fas fa-info-circle text-muted ms-1"
                           title="<?= h(__('If unset, will be the default setting for the server. Set 0 to allow unlimited.')) ?>"></i>
                    </label>
                </div>
                <div id="restsearchLimitValueContainer" class="mb-4">
                    <?= $this->Form->label('restsearch_limit_result', __('# of results per search'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('restsearch_limit_result', ['class' => 'form-control']) ?>
                </div>

                <!-- PERMISSION FLAGS -->
                <div class="fw-semibold mb-2"><?= __('Permission flags') ?></div>
                <div class="row role-permissions">
                    <?php foreach ($permFlags as $k => $flag): ?>
                        <?php
                            $readonlyClass = $flag['readonlyenabled'] ? 'readonlyenabled' : 'readonlydisabled';
                            $siteAdminClass = empty($flag['site_admin_optional']) ? 'site_admin_enforced' : 'site_admin_optional';
                        ?>
                        <div class="col-md-4">
                            <div class="form-check permFlags <?= $readonlyClass ?>">
                                <?= $this->Form->checkbox($k, [
                                    'class' => sprintf('form-check-input %s %s', $readonlyClass, $siteAdminClass),
                                    'checked' => !empty($roleData[$k]),
                                ]) ?>
                                <?= $this->Form->label('Role' . Inflector::camelize($k), h($flag['text']), ['class' => 'form-check-label']) ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3 mt-4">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit') : __('Add')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit') : __('Add'),
                            'aria-label' => $edit ? __('Edit') : __('Add'),
                        ]
                    ) ?>
                </div>

            </div>
        </div>
    </div>
</div>

<?= $this->Form->end(); ?>

<script type="text/javascript">
    $(function() {
        if (typeof checkRolePerms === 'function') {
            checkRolePerms();
        }
        if (typeof checkRoleEnforceRateLimit === 'function') {
            checkRoleEnforceRateLimit();
        }
        if (typeof toggleIsRestsearchLimitedField === 'function') {
            toggleIsRestsearchLimitedField();
        }
        $(".checkbox, #RolePermission, .permFlags input").change(function() {
            if (typeof checkRolePerms === 'function') {
                checkRolePerms();
            }
        });
        $("#RoleEnforceRateLimit").change(function() {
            if (typeof checkRoleEnforceRateLimit === 'function') {
                checkRoleEnforceRateLimit();
            }
        });
        $('#RoleIsRestsearchLimited').change(function () {
            if (typeof toggleIsRestsearchLimitedField === 'function') {
                toggleIsRestsearchLimitedField();
            }
        });
        $('form').submit(function() {
            if (!$('#RoleIsRestsearchLimited').is(':checked')) {
                $('#RoleRestsearchLimitResult').val('');
            }
        });
    });
</script>
