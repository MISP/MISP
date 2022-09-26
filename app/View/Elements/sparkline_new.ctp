<?php if (!empty($csv)): ?>
<div id="spark_<?php echo (isset($scope) ? h($scope) . '_' : ''); ?><?php echo h($id); ?>"></div>
<script>
    sparkline('#spark_<?php echo (isset($scope) ? h($scope) . '_' : ''); ?><?php echo h($id); ?>', "<?= $csv ?>");
</script>
<?php endif; ?>
