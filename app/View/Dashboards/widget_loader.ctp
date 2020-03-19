<?php
    $widgetHtml = $this->element('/dashboard/Widgets/' . $config['render']);
    $result = $this->ScopedCSS->createScopedCSS($widgetHtml);
    $seed = $result['seed'];
    $widgetHtml = $result['html'];
    $widgetCSS = $result['css'];
?>
<div id="widgetContentInner_<?= h($widget_id) ?>" <?php echo !empty($seed) ? sprintf("data-scoped=\"%s\" ", $seed) : "" ?>>
    <?php
        echo $widgetHtml;
        echo $widgetCSS;
    ?>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        if (<?= $config['autoRefreshDelay'] ? 'true' : 'false' ?>) {
            setTimeout( function(){
                updateDashboardWidget("#widget_<?= h($widget_id) ?>")},
                <?= $config['autoRefreshDelay'] ? $config['autoRefreshDelay'] : 1 ?> * 1000
            );
        }
    });
</script>
