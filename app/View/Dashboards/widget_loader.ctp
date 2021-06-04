<?php
    $widgetHtml = $this->element('/dashboard/Widgets/' . $config['render']);
    $scopedHtml = $this->ScopedCSS->createScopedCSS($widgetHtml);
?>
<div id="widgetContentInner_<?= h($widget_id) ?>" class="widgetContentInner">
    <?php
        echo $scopedHtml['bundle'];
    ?>
</div>
<script type="text/javascript">
    $(function() {
        if (<?= $config['autoRefreshDelay'] ? 'true' : 'false' ?>) {
            setTimeout( function(){
                updateDashboardWidget("#widget_<?= h($widget_id) ?>")},
                <?= $config['autoRefreshDelay'] ? $config['autoRefreshDelay'] : 1 ?> * 1000
            );
        }
    });
</script>
