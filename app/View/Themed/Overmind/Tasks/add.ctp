<?php
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

// Selectable "type" cards — same icon/colour language as the Action column in
// the index. Selected state uses the primary accent (like the event cards).
$typeCards = [
    'Server'           => ['icon' => 'server',            'color' => '#1892B1', 'sub' => __('Pull / push / cache a server')],
    'Feed'             => ['icon' => 'rss',               'color' => '#0dcaf0', 'sub' => __('Fetch or cache a feed')],
    'Workflow'         => ['icon' => 'diagram-project',   'color' => '#198754', 'sub' => __('Run an ad-hoc workflow')],
    'TAXII'            => ['icon' => 'share-nodes',        'color' => '#c79100', 'sub' => __('Push to a TAXII server')],
    'Periodic Summary' => ['icon' => 'envelope',          'color' => '#6c757d', 'sub' => __('Send a periodic summary')],
    'Admin'            => ['icon' => 'screwdriver-wrench', 'color' => '#212529', 'sub' => __('Update galaxies, taxonomies…')],
];

$sectionTitle = function ($label, $required = false) {
    $badge = $required
        ? ' <span class="badge bg-primary" style="font-size:.55rem; opacity:.85; font-weight:700;">' . __('REQUIRED') . '</span>'
        : '';
    return '<div class="d-flex align-items-center gap-2 text-primary fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">'
        . h($label) . $badge . '</div>';
};

echo $this->Form->create('Task', array_merge(
    ['url' => $baseurl . '/tasks/' . ($edit ? 'edit/' . h($editId) : 'add'), 'novalidate' => true],
    $edit ? ['type' => 'put'] : []
));
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--bs-primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Scheduled Tasks') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $edit ? 'pen-to-square' : 'circle-plus' ?> text-primary" style="font-size:1.25rem;"></i>
            <?= $edit ? __('Edit scheduled task') : __('Add scheduled task') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Runs a background job (server, feed, workflow, TAXII, summary or admin update) on a recurring schedule.') ?>
        </p>
    </div>
    <i class="fas fa-clock text-primary" style="font-size:2rem; opacity:.5;"></i>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ══ TYPE ══════════════════════════════════════════════ -->
        <div class="w-100 px-2">
            <?= $sectionTitle(__('Type'), true) ?>

            <?php // Hidden real select drives the SecurityComponent hash + the
                  // show/hide matrix; the cards below just set its value. ?>
            <?= $this->Form->select('type', $typeOptions, [
                'class' => 'form-select', 'id' => 'TaskType', 'value' => $typeSel,
                'empty' => false, 'style' => 'display:none;',
            ]) ?>

            <div class="row row-cols-2 row-cols-md-3 g-2" id="taskTypeCardRow">
                <?php foreach ($typeCards as $tName => $tc):
                    $sel = ($tName === $typeSel);
                    $bdr = $sel
                        ? 'border-color:var(--bs-primary) !important;background:rgba(24,146,177,.08);'
                        : 'border-color:#d8dde3;';
                ?>
                <div class="col type-card-col" style="cursor:pointer;" data-value="<?= h($tName) ?>">
                    <div class="border rounded p-2 d-flex align-items-center gap-2 h-100"
                         style="transition:border-color .15s,background .15s; <?= $bdr ?>">
                        <span class="d-inline-flex align-items-center justify-content-center rounded-circle flex-shrink-0"
                              style="width:1.9rem;height:1.9rem;
                                     background:<?= h($tc['color']) ?>1f;
                                     border:1px solid <?= h($tc['color']) ?>40;">
                            <i class="fas fa-<?= h($tc['icon']) ?>" style="color:<?= h($tc['color']) ?>;font-size:.75rem;"></i>
                        </span>
                        <span class="d-flex flex-column">
                            <span class="fw-bold lh-sm" style="font-size:.8rem;"><?= h($typeOptions[$tName]) ?></span>
                            <span class="text-muted lh-sm" style="font-size:.68rem;"><?= h($tc['sub']) ?></span>
                        </span>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- ══ ACTION & PARAMETERS ═══════════════════════════════ -->
        <div class="w-100 px-2">
            <?= $sectionTitle(__('Action & parameters')) ?>

            <div class="row g-3">
                <!-- SERVER -->
                <div class="col-md-6 optionalField" id="ServerAction" style="display:none;">
                    <?= $this->Form->label('server_action', __('Action'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('server_action', [
                        'pull' => __('Pull'), 'push' => __('Push'), 'cache' => __('Cache'),
                    ], ['class' => 'form-select bg-light', 'id' => 'TaskServerAction', 'value' => $serverActionSel, 'empty' => false]) ?>
                </div>
                <div class="col-md-6 optionalField" id="Server" style="display:none;">
                    <?= $this->Form->label('server_id', __('Server'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('server_id', $dropdownData['servers'], [
                        'class' => 'form-select bg-light', 'id' => 'TaskServerId', 'value' => $serverIdSel, 'empty' => false,
                    ]) ?>
                </div>
                <div class="col-md-6 optionalField" id="ServerTechnique" style="display:none;">
                    <?= $this->Form->label('server_technique', __('Technique'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('server_technique', [
                        'full' => __('Full'), 'update' => __('Update'), 'incremental' => __('Incremental'),
                    ], ['class' => 'form-select bg-light', 'id' => 'TaskServerTechnique', 'value' => $serverTechSel, 'empty' => false]) ?>
                </div>

                <!-- FEED -->
                <div class="col-md-6 optionalField" id="FeedAction" style="display:none;">
                    <?= $this->Form->label('feed_action', __('Action'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('feed_action', [
                        'fetch' => __('Fetch'), 'cache' => __('Cache'),
                    ], ['class' => 'form-select bg-light', 'id' => 'TaskFeedAction', 'value' => $feedActionSel, 'empty' => false]) ?>
                </div>
                <div class="col-md-6 optionalField" id="Feed" style="display:none;">
                    <?= $this->Form->label('feed_id', __('Feed'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('feed_id', $dropdownData['feeds'], [
                        'class' => 'form-select bg-light', 'id' => 'TaskFeedId', 'value' => $feedIdSel, 'empty' => false,
                    ]) ?>
                </div>
                <div class="col-md-6 optionalField" id="FeedScope" style="display:none;">
                    <?= $this->Form->label('feed_scope', __('Scope'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('feed_scope', [
                        'freetext' => __('Freetext'), 'csv' => __('CSV'), 'misp' => __('MISP'), 'all' => __('All'),
                    ], ['class' => 'form-select bg-light', 'id' => 'TaskFeedScope', 'value' => $feedScopeSel, 'empty' => false]) ?>
                </div>

                <!-- WORKFLOW -->
                <div class="col-md-6 optionalField" id="Workflow" style="display:none;">
                    <?= $this->Form->label('workflow', __('Ad-hoc Workflow'), ['class' => 'form-label fw-semibold']) ?>
                    <?php // 'empty' keeps the select non-zero-option even when no ad-hoc workflows exist,
                          // so CakePHP still locks the field in the SecurityComponent hash (a zero-option
                          // select is rendered but NOT secured, which blackholes every submit). ?>
                    <?= $this->Form->select('workflow', $dropdownData['workflows'], [
                        'class' => 'form-select bg-light', 'id' => 'TaskWorkflow', 'value' => $workflowSel,
                        'empty' => empty($dropdownData['workflows']) ? __('No ad-hoc workflows available') : false,
                    ]) ?>
                </div>

                <!-- TAXII -->
                <div class="col-md-6 optionalField" id="TaxiiServer" style="display:none;">
                    <?= $this->Form->label('taxii_server_id', __('TAXII Server'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('taxii_server_id', $dropdownData['taxii_servers'], [
                        'class' => 'form-select bg-light', 'id' => 'TaskTaxiiServerId', 'value' => $taxiiSel, 'empty' => false,
                    ]) ?>
                </div>

                <!-- ADMIN -->
                <div class="col-md-6 optionalField" id="AdminAction" style="display:none;">
                    <?= $this->Form->label('admin_action', __('Action'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('admin_action', [
                        'updateGalaxies' => __('Update Galaxies'),
                        'updateTaxonomies' => __('Update Taxonomies'),
                        'updateWarningLists' => __('Update Warninglists'),
                        'updateNoticeLists' => __('Update Noticelists'),
                        'updateObjectTemplates' => __('Update Object Templates'),
                        'checkUserValidity' => __('Check User Validity (report only)'),
                        'blockInvalidUsers' => __('Check User Validity (disable invalid users)'),
                    ], ['class' => 'form-select bg-light', 'id' => 'TaskAdminAction', 'value' => $adminActionSel, 'empty' => false]) ?>
                </div>

                <!-- PERIODIC SUMMARY (no extra parameters) -->
                <div class="col-12 optionalField" id="PeriodicSummaryInfo" style="display:none;">
                    <div class="alert alert-light border d-flex align-items-center gap-2 mb-0" role="alert">
                        <i class="fas fa-circle-info text-primary"></i>
                        <span class="small text-muted">
                            <?= __('This task sends the periodic summary for the selected user. No additional parameters are required.') ?>
                        </span>
                    </div>
                </div>

                <!-- DESCRIPTION -->
                <div class="col-12">
                    <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light', 'rows' => 2, 'value' => $descriptionVal,
                        'placeholder' => __('Optional note describing what this task is for…'),
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ══ ENABLED (galaxy-style toggle card) ════════════════ -->
        <div class="w-100 px-2">
            <label class="d-flex align-items-center justify-content-between border rounded-3 p-3 bg-light w-100 m-0"
                   style="cursor:pointer;">
                <div class="d-flex align-items-center gap-3">
                    <span class="d-inline-flex align-items-center justify-content-center rounded-circle flex-shrink-0"
                          style="width:2.25rem;height:2.25rem;background:rgba(24,146,177,.12);">
                        <i class="fas fa-power-off text-primary"></i>
                    </span>
                    <div>
                        <span class="fw-semibold d-block"><?= __('Enabled') ?></span>
                        <span class="text-muted small">
                            <?= __('Run this task on the schedule below. Disable to keep it configured but paused.') ?>
                        </span>
                    </div>
                </div>
                <div class="form-check form-switch m-0 ps-0">
                    <?php
                    $enabledOpts = [
                        'class' => 'form-check-input ms-0',
                        'id' => 'TaskEnabled',
                        'role' => 'switch',
                        'hiddenField' => true,
                        'style' => 'width:3rem;height:1.5rem;cursor:pointer;',
                    ];
                    if (!$edit) {
                        $enabledOpts['checked'] = true;
                    }
                    echo $this->Form->checkbox('enabled', $enabledOpts);
                    ?>
                </div>
            </label>
        </div>

        <!-- ══ SCHEDULE ══════════════════════════════════════════ -->
        <div class="w-100 px-2">
            <?= $sectionTitle(__('Schedule')) ?>

            <div class="row g-3">
                <div class="col-md-3">
                    <?= $this->Form->label('time_multiplier', __('Runs every'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->number('time_multiplier', [
                        'class' => 'form-control bg-light', 'id' => 'TaskTimeMultiplier', 'min' => 1, 'value' => $multiplierVal,
                    ]) ?>
                </div>
                <div class="col-md-3">
                    <?= $this->Form->label('time_unit', __('Period'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('time_unit', [
                        1 => __('second(s)'), 60 => __('minute(s)'), 3600 => __('hour(s)'), 86400 => __('day(s)'),
                    ], ['class' => 'form-select bg-light', 'id' => 'TaskTimeUnit', 'value' => $unitSel, 'empty' => false]) ?>
                </div>

                <div class="w-100"></div>

                <div class="col-md-6">
                    <?= $this->Form->label('next_execution_date', __('Next execution date'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('next_execution_date', [
                        'class' => 'form-control bg-light', 'id' => 'TaskNextExecutionDate', 'type' => 'date', 'value' => $nextDateVal,
                    ]) ?>
                    <div class="form-text"><?= __('Leave blank for immediate execution.') ?></div>
                </div>
                <div class="col-md-6">
                    <?= $this->Form->label('next_execution_time', __('Next execution time'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('next_execution_time', [
                        'class' => 'form-control bg-light', 'id' => 'TaskNextExecutionTime', 'type' => 'time', 'step' => 1, 'value' => $nextTimeVal,
                        'placeholder' => __('HH:MM:SS'),
                    ]) ?>
                    <div class="form-text"><?= __('Server time: %s', date('H:i:s')) ?></div>
                </div>
            </div>
        </div>

        <!-- ══ USER ══════════════════════════════════════════════ -->
        <div class="w-100 px-2">
            <?= $sectionTitle(__('User')) ?>

            <div class="row g-3">
                <div class="col-md-6">
                    <?= $this->Form->select('user_id', $dropdownData['users'], [
                        'class' => 'form-select bg-light', 'id' => 'TaskUserId', 'value' => $userSel, 'empty' => false,
                    ]) ?>
                    <div class="form-text">
                        <?= $edit
                            ? __('The user cannot be changed when editing a task.')
                            : __('The task runs with this user\'s permissions.') ?>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-end align-items-center mt-4 pt-3 flex-wrap gap-2 border-top">
        <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
            <i class="fas fa-times me-1"></i><?= __('Discard') ?>
        </button>
        <?= $this->Form->button(
            '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add task')),
            ['class' => 'btn btn-primary btn-sm', 'escapeTitle' => false, 'type' => 'submit']
        ) ?>
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
        'Feed', 'FeedScope', 'Workflow', 'TaxiiServer', 'AdminAction', 'PeriodicSummaryInfo'];

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
            case 'Periodic Summary':
                show('PeriodicSummaryInfo');
                break;
        }
    }

    // Type cards → drive the hidden <select> + re-render the highlight.
    var cardRow = el('taskTypeCardRow');
    if (cardRow) {
        cardRow.querySelectorAll('.type-card-col').forEach(function (card) {
            card.addEventListener('click', function () {
                cardRow.querySelectorAll('.type-card-col > div').forEach(function (d) {
                    d.style.borderColor = '#d8dde3';
                    d.style.background = '';
                });
                var inner = card.querySelector('div');
                if (inner) {
                    inner.style.borderColor = 'var(--bs-primary)';
                    inner.style.background = 'rgba(24,146,177,.08)';
                }
                var sel = el('TaskType');
                if (sel) sel.value = card.dataset.value;
                taskFormUpdate();
            });
        });
    }

    ['TaskType', 'TaskFeedAction', 'TaskFeedId'].forEach(function (id) {
        var e = el(id);
        if (e) e.addEventListener('change', taskFormUpdate);
    });
    taskFormUpdate();
})();
</script>
