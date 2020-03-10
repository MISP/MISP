<div id="widgetContentInner_<?= h($widget_id) ?>">
    <?php
        echo $this->element('/dashboard/Widgets/' . $config['render']);
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
