<?php
// Overmind BS5 add/edit form for a scheduled task. Rendered layout-less as a
// modal fragment (opened via openModal). Self-contained: under Overmind only
// mispOvermind.js is loaded, so the legacy misp.js helper taskFormUpdate() is
// re-implemented inline below (the show/hide matrix driven by the Type dropdown).
//
// The field NAMES here match exactly what TasksController::__massageFormInput()
// consumes (server_action / server_id / server_technique / feed_action /
// feed_id / feed_scope / workflow / taxii_server_id / admin_action / ...), so
// the untouched controller write path builds the same type/action/params/timer
// as the legacy form. On edit the controller's afterFind decomposes the stored
// params back into these UI fields for prefill.
$edit = $this->request->params['action'] === 'edit';
$reqTask = $this->request->data['Task'] ?? [];

$typeSel = $reqTask['type'] ?? 'Server';
$serverActionSel = $reqTask['server_action'] ?? 'pull';
$serverIdSel = $reqTask['server_id'] ?? null;
$serverTechSel = $reqTask['server_technique'] ?? 'full';
$feedActionSel = $reqTask['feed_action'] ?? 'fetch';
$feedIdSel = $reqTask['feed_id'] ?? null;
$feedScopeSel = $reqTask['feed_scope'] ?? 'freetext';
$workflowSel = $reqTask['workflow'] ?? null;
$taxiiSel = $reqTask['taxii_server_id'] ?? null;
$adminActionSel = $reqTask['admin_action'] ?? 'updateGalaxies';
$userSel = $reqTask['user_id'] ?? Configure::read('CurrentUserId');
$multiplierVal = $reqTask['time_multiplier'] ?? 1;
$unitSel = $reqTask['time_unit'] ?? 86400;
$nextDateVal = $reqTask['next_execution_date'] ?? '';
$nextTimeVal = $reqTask['next_execution_time'] ?? '';
$descriptionVal = $reqTask['description'] ?? '';

$editId = $edit ? ($reqTask['id'] ?? ($this->request->params['pass'][0] ?? '')) : '';

$typeOptions = [
    'Server' => __('Server'),
    'Feed' => __('Feed'),
    'Workflow' => __('Workflow'),
    'Periodic Summary' => __('Periodic Summary'),
    'TAXII' => __('TAXII'),
    'Admin' => __('Admin'),
];

echo $this->Form->create('Task', array_merge(
    ['url' => $baseurl . '/tasks/' . ($edit ? 'edit/' . h($editId) : 'add')],
    $edit ? ['type' => 'put'] : []
));
?>

<div class="card shadow-sm">
    <div class="card-body p-4">

        <h3 class="mb-2"><?= $edit ? __('Edit scheduled task') : __('Add scheduled task') ?></h3>
        <p class="text-muted">
            <?= __('Scheduled tasks run jobs such as Server pull/push/cache or Feed fetch/cache in the background. Set how frequently each task runs. Note: if the Server does not have pull/push enabled or the Feed is not enabled, the selected action will not be executed.') ?>
        </p>

        <!-- ================= TYPE ================= -->
        <div class="row">
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('type', __('Type'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('type', $typeOptions, [
                    'class' => 'form-select', 'id' => 'TaskType', 'value' => $typeSel, 'empty' => false,
                ]) ?>
            </div>
        </div>

        <!-- ================= SERVER ================= -->
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="ServerAction" style="display:none;">
                <?= $this->Form->label('server_action', __('Action'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('server_action', [
                    'pull' => __('Pull'), 'push' => __('Push'), 'cache' => __('Cache'),
                ], ['class' => 'form-select', 'id' => 'TaskServerAction', 'value' => $serverActionSel, 'empty' => false]) ?>
            </div>
            <div class="col-md-6 mb-3 optionalField" id="Server" style="display:none;">
                <?= $this->Form->label('server_id', __('Server'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('server_id', $dropdownData['servers'], [
                    'class' => 'form-select', 'id' => 'TaskServerId', 'value' => $serverIdSel, 'empty' => false,
                ]) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="ServerTechnique" style="display:none;">
                <?= $this->Form->label('server_technique', __('Technique'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('server_technique', [
                    'full' => __('Full'), 'update' => __('Update'), 'incremental' => __('Incremental'),
                ], ['class' => 'form-select', 'id' => 'TaskServerTechnique', 'value' => $serverTechSel, 'empty' => false]) ?>
            </div>
        </div>

        <!-- ================= FEED ================= -->
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="FeedAction" style="display:none;">
                <?= $this->Form->label('feed_action', __('Action'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('feed_action', [
                    'fetch' => __('Fetch'), 'cache' => __('Cache'),
                ], ['class' => 'form-select', 'id' => 'TaskFeedAction', 'value' => $feedActionSel, 'empty' => false]) ?>
            </div>
            <div class="col-md-6 mb-3 optionalField" id="Feed" style="display:none;">
                <?= $this->Form->label('feed_id', __('Feed'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('feed_id', $dropdownData['feeds'], [
                    'class' => 'form-select', 'id' => 'TaskFeedId', 'value' => $feedIdSel, 'empty' => false,
                ]) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="FeedScope" style="display:none;">
                <?= $this->Form->label('feed_scope', __('Scope'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('feed_scope', [
                    'freetext' => __('Freetext'), 'csv' => __('CSV'), 'misp' => __('MISP'), 'all' => __('All'),
                ], ['class' => 'form-select', 'id' => 'TaskFeedScope', 'value' => $feedScopeSel, 'empty' => false]) ?>
            </div>
        </div>

        <!-- ================= WORKFLOW ================= -->
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="Workflow" style="display:none;">
                <?= $this->Form->label('workflow', __('Ad-hoc Workflow'), ['class' => 'form-label fw-semibold']) ?>
                <?php // 'empty' keeps the select non-zero-option even when no ad-hoc workflows exist,
                      // so CakePHP still locks the field in the SecurityComponent hash (a zero-option
                      // select is rendered but NOT secured, which blackholes every submit). ?>
                <?= $this->Form->select('workflow', $dropdownData['workflows'], [
                    'class' => 'form-select', 'id' => 'TaskWorkflow', 'value' => $workflowSel,
                    'empty' => empty($dropdownData['workflows']) ? __('No ad-hoc workflows available') : false,
                ]) ?>
            </div>
        </div>

        <!-- ================= TAXII ================= -->
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="TaxiiServer" style="display:none;">
                <?= $this->Form->label('taxii_server_id', __('TAXII Server'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('taxii_server_id', $dropdownData['taxii_servers'], [
                    'class' => 'form-select', 'id' => 'TaskTaxiiServerId', 'value' => $taxiiSel, 'empty' => false,
                ]) ?>
            </div>
        </div>

        <!-- ================= ADMIN ================= -->
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="AdminAction" style="display:none;">
                <?= $this->Form->label('admin_action', __('Action'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('admin_action', [
                    'updateGalaxies' => __('Update Galaxies'),
                    'updateTaxonomies' => __('Update Taxonomies'),
                    'updateWarningLists' => __('Update Warninglists'),
                    'updateNoticeLists' => __('Update Noticelists'),
                    'updateObjectTemplates' => __('Update Object Templates'),
                ], ['class' => 'form-select', 'id' => 'TaskAdminAction', 'value' => $adminActionSel, 'empty' => false]) ?>
            </div>
        </div>

        <!-- ================= COMMON ================= -->
        <div class="row">
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('user_id', __('User'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('user_id', $dropdownData['users'], [
                    'class' => 'form-select', 'id' => 'TaskUserId', 'value' => $userSel, 'empty' => false,
                ]) ?>
                <?php if ($edit): ?>
                    <div class="form-text"><?= __('The user cannot be changed when editing a task.') ?></div>
                <?php endif; ?>
            </div>
        </div>

        <div class="row align-items-end">
            <div class="col-md-3 mb-3">
                <?= $this->Form->label('time_multiplier', __('Runs every'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->number('time_multiplier', [
                    'class' => 'form-control', 'id' => 'TaskTimeMultiplier', 'min' => 1, 'value' => $multiplierVal,
                ]) ?>
            </div>
            <div class="col-md-3 mb-3">
                <?= $this->Form->label('time_unit', __('Period'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('time_unit', [
                    1 => __('second(s)'), 60 => __('minute(s)'), 3600 => __('hour(s)'), 86400 => __('day(s)'),
                ], ['class' => 'form-select', 'id' => 'TaskTimeUnit', 'value' => $unitSel, 'empty' => false]) ?>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('next_execution_date', __('Next execution date'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('next_execution_date', [
                    'class' => 'form-control', 'id' => 'TaskNextExecutionDate', 'type' => 'date', 'value' => $nextDateVal,
                    'placeholder' => __('Leave blank for immediate execution'),
                ]) ?>
                <div class="form-text"><?= __('Leave blank for immediate execution.') ?></div>
            </div>
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('next_execution_time', __('Next execution time'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('next_execution_time', [
                    'class' => 'form-control', 'id' => 'TaskNextExecutionTime', 'type' => 'time', 'step' => 1, 'value' => $nextTimeVal,
                    'placeholder' => __('HH:MM:SS'),
                ]) ?>
                <div class="form-text"><?= __('Current server time: %s', date('H:i:s')) ?></div>
            </div>
        </div>

        <div class="mb-3">
            <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->text('description', ['class' => 'form-control', 'value' => $descriptionVal]) ?>
        </div>

        <div class="form-check form-switch mb-3">
            <?= $this->Form->checkbox('enabled', array_merge(
                ['class' => 'form-check-input', 'id' => 'TaskEnabled'],
                $edit ? [] : ['checked' => true]
            )) ?>
            <?= $this->Form->label('TaskEnabled', __('Enabled'), ['class' => 'form-check-label']) ?>
        </div>

        <!-- ACTIONS -->
        <div class="d-flex justify-content-end gap-3 mt-4">
            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Cancel') ?></button>
            <?= $this->Form->button(
                '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add task')),
                ['class' => 'btn btn-primary', 'escapeTitle' => false, 'type' => 'submit']
            ) ?>
        </div>

    </div>
</div>

<?= $this->Form->end(); ?>

<script>
(function () {
    var root = document;
    function el(id) { return root.getElementById(id); }
    function show(id) { var e = el(id); if (e) e.style.display = ''; }
    function hide(id) { var e = el(id); if (e) e.style.display = 'none'; }

    var optional = ['ServerAction', 'Server', 'ServerTechnique', 'FeedAction',
        'Feed', 'FeedScope', 'Workflow', 'TaxiiServer', 'AdminAction'];

    function taskFormUpdate() {
        optional.forEach(hide);
        var type = el('TaskType');
        switch (type ? type.value : '') {
            case 'Server':
                show('ServerAction'); show('Server'); show('ServerTechnique');
                break;
            case 'Feed':
                show('FeedAction'); show('Feed');
                var fa = el('TaskFeedAction');
                var fi = el('TaskFeedId');
                if (fa && fa.value === 'cache' && fi && fi.value === 'all') {
                    show('FeedScope');
                } else {
                    hide('FeedScope');
                }
                break;
            case 'Workflow':
                show('Workflow');
                break;
            case 'TAXII':
                show('TaxiiServer');
                break;
            case 'Admin':
                show('AdminAction');
                break;
        }
    }

    ['TaskType', 'TaskFeedAction', 'TaskFeedId'].forEach(function (id) {
        var e = el(id);
        if (e) e.addEventListener('change', taskFormUpdate);
    });
    taskFormUpdate();
})();
</script>
