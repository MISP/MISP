<?php
$eventId = (int)($data['Event']['id'] ?? 0);
$suffix = $extensionSuffix ?? '';
// An event held elsewhere brings its overview along, drawn in place and read-only.
$overview = $overview ?? null;
$loader = '<div class="text-center text-muted py-5"><div class="misp-loader misp-loader-sm" role="status"></div></div>';
$fragment = function ($action) use ($baseurl, $eventId, $suffix, $overview) {
    if ($overview !== null) {
        return '';
    }
    return ' data-eo-fragment="' . h($baseurl . '/events/' . $action . '/' . $eventId . $suffix) . '"';
};
?>
<div class="row g-3 mb-3 eo-row">
    <div class="col-12 col-xl-7 d-flex">
        <div class="card shadow-sm eo-card w-100" id="eo-context-card"<?= $fragment('viewEventContext') ?>>
            <?= $overview === null ? $loader : $this->element('Events/View/overview_context', [
                'rows' => $overview['context'],
                'inObjects' => $overview['inObjects'],
                'rolledUp' => true,
                'profileName' => $overview['profileName'],
                'profileId' => $overview['profileId'],
                'readOnly' => true,
            ]) ?>
        </div>
    </div>
    <div class="col-12 col-xl-5 d-flex">
        <div class="card shadow-sm eo-card w-100" id="eo-inventory-card"<?= $fragment('viewEventInventory') ?>>
            <?= $overview === null ? $loader : $this->element('Events/View/overview_inventory', [
                'inventory' => $overview['inventory'],
                'readOnly' => true,
            ]) ?>
        </div>
    </div>
</div>
<?php if ($overview === null): ?>
    <?php // What the objects describe: empty until it has something to draw. ?>
    <div id="eo-object-views"<?= $fragment('viewEventObjectViews') ?>></div>
<?php endif; ?>
