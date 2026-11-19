<?php
/**
 * The collection drawn full width: the working view for whoever has it as
 * their workspace, every member with an automatic layout for anyone else, or
 * one of its saved graphs picked from the head. intel-graph-working.js
 * mounts it when the tab is first shown.
 */
$canEdit = ClassRegistry::init('Collection')->canModify($me, $data['Collection']);
$pivotLabels = ClassRegistry::init('AnalystProfile')->pivotLabels($me);
$explorer = [
    'labelPlan' => $pivotLabels['plan'],
    'permitted' => $pivotLabels['permitted'],
];

echo $this->element('intel_graph_working_text');
// A reader with no navbar slot has no IntelGraph from the layout.
if (empty($intelGraph)) {
    echo $this->element('intel_graph_boot', ['intelGraph' => ['active' => null], 'withDock' => false]);
    echo $this->element('genericElements/assetLoader', [
        'js' => ['intel-graph-way-out', 'intel-graph-working'],
        'css' => ['intel-graph-working', 'intel-graph-way-out'],
    ]);
}
?>
<div class="card shadow-sm mb-3 igw-page-card" data-igw-page
     data-igw-collection="<?= h($data['Collection']['uuid']) ?>"
     data-igw-name="<?= h($data['Collection']['name']) ?>"
     data-igw-type="<?= h($data['Collection']['type']) ?>"
     data-igw-can-edit="<?= $canEdit ? '1' : '0' ?>"
     data-igw-explorer="<?= h(json_encode($explorer)) ?>">
    <div class="igw-page-head" data-igw-head>
        <div class="igw-page-what" data-igw-what></div>
        <div class="igw-page-state" data-igw-state aria-live="polite"></div>
    </div>
    <div class="igw-page-slot" data-igw-slot></div>
</div>
