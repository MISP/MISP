<?php
/**
 * @var array $distributionLevels
 * @var array $sharingGroups
 * @var int $defaultDistribution
 * @var array $collections [{type, uuid, label}]
 * @var int $transferLimit
 */
$color = 'info';

$targets = ['' => __("Keep each workspace's own target")];
foreach ($collections as $collection) {
    $targets[$collection['type'] . ':' . $collection['uuid']] = __('Collection: %s', $collection['label']);
}

echo $this->Form->create('Workspace', [
    'url' => $baseurl . '/workspaces/import',
    'type' => 'file',
    'novalidate' => true,
    'id' => 'analystGraphImportForm',
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => $color,
    'eyebrow' => __('Workspaces'),
    'title' => __('Import workspaces'),
    'description' => __("A file exported from this or another instance. Each workspace keeps its uuid and becomes your organisation's; one this instance already holds is refused."),
    'icon' => 'fas fa-file-import',
    'titleIcon' => 'fas fa-file-import',
]) ?>

<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4 px-2">

        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => $color,
                'label' => __('Export file'),
            ]) ?>
            <?= $this->Form->file('Workspace.import.file', [
                'class' => 'form-control',
                'accept' => '.json,application/json',
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Or paste its contents below. One workspace or several, at most %s.', $transferLimit),
                'class' => 'mt-2',
            ]) ?>
            <?= $this->Form->textarea('Workspace.import.json', [
                'class' => 'form-control font-monospace mt-2',
                'rows' => 5,
                'spellcheck' => 'false',
                'placeholder' => '{"Workspace": {"name": "…", "content": {"nodes": […]}}}',
            ]) ?>
        </div>

        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => $color,
                'label' => __('Target'),
            ]) ?>
            <?= $this->Form->select('Workspace.import.target', $targets, [
                'class' => 'form-select',
                'empty' => false,
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('A workspace hangs off a collection, an event or a galaxy cluster. Pick a collection to put every imported workspace on it.'),
                'class' => 'mt-2',
            ]) ?>
        </div>

        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                'field' => 'Workspace.import.distribution',
                'accent' => $color,
                'levels' => $distributionLevels,
                'sharingGroups' => $sharingGroups,
                'value' => $defaultDistribution,
                'id' => 'analyst-graph-import-distribution',
                'hint' => __('Applies to every imported workspace.'),
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => $color,
        'hint' => __('Nodes resolve to the records this instance holds; the others stay out of sight.'),
        'submit' => ['label' => __('Import'), 'icon' => 'fas fa-file-import'],
    ]) ?>
</div>

<?= $this->Form->end() ?>
