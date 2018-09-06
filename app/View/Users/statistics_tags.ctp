<?php
    echo $this->Html->script('d3');
    echo $this->Html->script('cal-heatmap');
    echo $this->Html->css('cal-heatmap');
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
    echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
<script type="text/javascript">
$(document).ready(function () {
    loadTagTreemap();
});
</script>
