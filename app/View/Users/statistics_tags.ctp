<?= $this->element('genericElements/assetLoader', [
    'css' => ['cal-heatmap'],
    'js' => ['d3', 'cal-heatmap'],
]);
?>
<div class = "index">
<h2><?php echo __('Statistics');?></h2>
<?php
    echo $this->element('Users/statisticsMenu');
?>
<p><?php echo __('A treemap of the currently used event tags. Click on any of the taxonomies to hide it and click it again to show it.');?></p>
<div id="treemapdiv" class="treemapdiv"></div>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
<script type="text/javascript">
$(document).ready(function () {
    loadTagTreemap();
});
</script>
