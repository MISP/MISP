<?php
$isEdit = $action === 'edit';

$reportData = $this->request->data['EventReport'] ?? [];

$currentDist = isset($reportData['distribution'])
    ? (int)$reportData['distribution']
    : (int)$initialDistribution;

echo $this->Form->create('EventReport', ['novalidate' => true]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'report',
    'eyebrow' => __('Event Reports'),
    'title' => $isEdit ? __('Edit Event Report') : __('Add Event Report'),
    'icon' => 'misp-icon misp-icon-report misp-simple',
    'isEdit' => $isEdit,
]) ?>

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
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'report',
                'label' => __('Distribution'),
            ]) ?>
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
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'report',
                'label' => __('Content'),
            ]) ?>
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
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Supports Markdown and MISP element references (e.g. @[attribute](uuid)).'),
            ]) ?>
        </div>

        <?= $this->Form->hidden('event_id', ['value' => $event_id]) ?>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'report',
        'isEdit' => $isEdit,
        'meta' => [['label' => __('Event'), 'id' => $event_id]],
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Report')],
    ]) ?>

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
