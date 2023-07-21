<?php
$iconCount = ['icon' => [], 'icon_path' => []];
foreach ($workflowBlueprint['data'] as $node) {
    $moduleData = $node['data']['module_data'];
    if (!empty($moduleData['icon'])) {
        if (!isset($iconCount['icon'][$moduleData['icon']])) {
            $iconClasses = sprintf('%s %s', $this->FontAwesome->getClass($moduleData['icon']), $moduleData['icon_class'] ?? '');
            $iconCount['icon'][$iconClasses]['count'] = 0;
            $iconCount['icon'][$iconClasses]['id'] = $node['data']['id'];
        }
        $iconCount['icon'][$iconClasses]['count'] += 1;
    } elseif (!empty($moduleData['icon_path'])) {
        if (!isset($iconCount['icon_path'][$moduleData['icon_path']])) {
            $iconCount['icon_path'][$moduleData['icon_path']]['count'] = 0;
            $iconCount['icon_path'][$moduleData['icon_path']]['id'] = $node['data']['id'];
        }
        $iconCount['icon_path'][$moduleData['icon_path']]['count'] += 1;
    }
}
?>
<div id="<?= h($workflowBlueprint['id']) ?>" class="sidebar-workflow-blueprints" style="user-select: none;" data-blueprintid="<?= h($workflowBlueprint['id']) ?>" title="<?= h($workflowBlueprint['description']) ?>">
    <div style="width: 100%;">
        <div style="display: flex;">
            <strong class="name">
                <?= h($workflowBlueprint['name']) ?>
            </strong>
            <span class="timestamp">v<?= h($workflowBlueprint['timestamp']) ?></span>
        </div>
        <div><small class="muted"><?= h($workflowBlueprint['uuid']) ?></small></div>
        <div><?= __('Default: %s', sprintf('<i class="%s"></i>', $this->FontAwesome->getClass(!empty($workflowBlueprint['default']) ? 'check' : 'times'))) ?></div>
        <div><?= __('Blueprint Content: %s', sprintf('<strong>%s</strong>', __n('%s node', '%s nodes', count($workflowBlueprint['data']), count($workflowBlueprint['data'])))) ?></div>
        <div>
            <?php foreach ($iconCount['icon'] as $icon => $data) : ?>
                <span class="input-prepend input-append" title="<?= h($data['id']) ?>" style="margin-left: 3px; margin-bottom: 6px; ">
                    <span class="add-on" style="height: 14px; line-height: 14px;">
                        <i class="<?= h($icon) ?> fa-fw"></i>
                    </span>
                    <span class="add-on" style="height: 14px; line-height: 14px;"><?= h($data['count']) ?></span>
                </span>
            <?php endforeach; ?>
            <?php foreach ($iconCount['icon_path'] as $icon_path => $data) : ?>
                <span class="input-prepend input-append" title="<?= h($data['id']) ?>" style="margin-left: 3px; margin-bottom: 6px; ">
                    <span class="add-on" style="height: 14px; line-height: 14px;">
                        <img src="<?= sprintf('%s/%s/%s', $baseurl, 'img', h($icon_path)) ?>" alt="Icon of <?= h($data['id']) ?>" title="<?= h($data['id']) ?>" style="width: 14px; filter: grayscale(1); vertical-align: baseline;">
                    </span>
                    <span class="add-on" style="height: 14px; line-height: 14px;"><?= h($data['count']) ?></span>
                </span>
            <?php endforeach; ?>
        </div>
        <div class="muted"><?= h($workflowBlueprint['description']) ?></div>
    </div>
</div>