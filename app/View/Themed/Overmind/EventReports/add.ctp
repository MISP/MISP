<?php
$isEdit = $action === 'edit';

$reportData = $this->request->data['EventReport'] ?? [];

$currentDist = isset($reportData['distribution'])
    ? (int)$reportData['distribution']
    : (int)$initialDistribution;

echo $this->Form->create('EventReport', ['novalidate' => true]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(77,161,103,.06);
            border-bottom:2px solid var(--bs-report);">
    <div>
        <div class="text-report text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Event Reports') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-report"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Event Report') : __('Add Event Report') ?>
        </h4>
    </div>
    <span class="misp-icon misp-icon-report misp-simple text-report"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── REPORT NAME ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-report fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Report Name') ?>
                <span class="badge bg-report"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id'          => 'EventReportName',
                'class'       => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style'       => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('Enter a descriptive name for this report…'),
            ]) ?>
        </div>

        <!-- ── DISTRIBUTION / SHARING GROUP ───────────────────── -->
        <div class="w-100 px-2">
            <div class="text-report fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Distribution') ?>
            </div>
            <div class="d-flex gap-3">

                <div class="flex-fill">
                    <?= $this->Form->select('distribution', $distributionLevels, [
                        'id'    => 'EventReportDistribution',
                        'class' => 'form-select',
                        'value' => $currentDist,
                    ]) ?>
                </div>

                <div class="flex-fill"
                     id="er-sg-container"
                     style="<?= $currentDist !== 4 ? 'display:none;' : '' ?>">
                    <?= $this->Form->select('sharing_group_id', $sharingGroups, [
                        'id'    => 'EventReportSharingGroupId',
                        'empty' => __('Select a sharing group…'),
                        'class' => 'form-select',
                    ]) ?>
                </div>

            </div>
        </div>

        <!-- ── CONTENT ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-report fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Content') ?>
            </div>
            <?= $this->Form->textarea('content', [
                'id'          => 'EventReportContent',
                'class'       => 'w-100 rounded-2 p-3',
                'style'       => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.875rem; min-height:200px;'
                    . ' color:inherit; font-family:monospace;',
                'rows'        => 10,
                'placeholder' => __('Write the report content in Markdown…'),
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Supports Markdown and MISP element references (e.g. @[attribute](uuid)).') ?>
            </div>
        </div>

        <?= $this->Form->hidden('event_id', ['value' => $event_id]) ?>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?= __('Event') ?>:
            <strong class="text-body">#<?= h($event_id) ?></strong>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Report')),
                [
                    'class'       => 'btn btn-report btn-sm text-white',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var sgContainer = document.getElementById('er-sg-container');

    function toggleSharingGroup(val) {
        if (sgContainer) {
            sgContainer.style.display = parseInt(val) === 4 ? '' : 'none';
        }
    }

    initDistributionSelect('EventReportDistribution', toggleSharingGroup);
})();
</script>
