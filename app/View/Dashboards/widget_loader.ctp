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
        <?php
            if ($config['autoRefreshDelay']) {
                echo sprintf(
                    'setTimeout( function(){ updateDashboardWidget($("#widgetContentInner%s").parent().parent().parent())}, %s);',
                    $randomId,
                    $config['autoRefreshDelay'] . '000'
                );
            }
        ?>
    });
</script>
