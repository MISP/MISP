<?php if (!empty($csv)): ?>
<div id="spark_<?php echo (isset($scope) ? h($scope) . '_' : ''); ?><?php echo h($id); ?>" data-csv="<?= $csv ?>"></div>
<script>
    sparkline('#spark_<?php echo (isset($scope) ? h($scope) . '_' : ''); ?><?php echo h($id); ?>');
</script>
<?php endif; ?>
