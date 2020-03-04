<?php
    $randomId = rand();
?>
<div id="widgetContentInner<?= $randomId ?>">
    <?php
        echo $this->element('/dashboard/Widgets/' . $config['render']);
    ?>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        if (<?= $config['autoRefreshDelay'] ?>) {
            setTimeout( function(){
                updateDashboardWidget($("#widgetContentInner<?= $randomId ?>").closest('.grid-stack-item'))},
                <?= $config['autoRefreshDelay'] ?> * 1000
            );
        }
    });
</script>
