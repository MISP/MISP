<?php
    $widgetHtml = $this->element('/dashboard/Widgets/' . $config['render']);
    $scopedHtml = $this->ScopedCSS->createScopedCSS($widgetHtml);
?>
<div id="widgetContentInner_<?= h($widget_id) ?>" class="widgetContentInner">
    <?= $scopedHtml['bundle']; ?>
</div>
<?php if ($config['autoRefreshDelay']): ?>
<script>
    $(function() {
        setTimeout(function() {
            updateDashboardWidget("#widget_<?= h($widget_id) ?>")},
            <?= $config['autoRefreshDelay'] ?: 1 ?> * 1000
        );
    });
</script>
<?php endif; ?>
