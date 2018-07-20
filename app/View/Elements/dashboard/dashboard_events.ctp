<div class="dashboard_element w-2 h-1 dashboard_notifications">
    <h4><?php echo __('Changes since last visit'); ?></h4>
    <p>
        <b><?php echo __('Events updated: '); ?></b><span class="bold <?php echo $events['changed'] ? 'red' : 'green'; ?>"><?php echo h($events['changed']);?></span> (<a href="<?php echo $baseurl;?>/events/index"><?php echo __('View'); ?></a>)<br />
        <b><?php echo __('Events published: '); ?></b><span class="bold <?php echo $events['published'] ? 'red' : 'green'; ?>"><?php echo h($events['published']);?></span> (<a href="<?php echo $baseurl;?>/events/index"><?php echo __('View'); ?></a>)<br />
    </p>
    <?php echo $this->Form->postLink('Reset', $baseurl . '/users/updateLoginTime', array('div' => false));?>
</div>
<script type="text/javascript">
$(document).ready(function() {
    var elem = $('.dashboard_notifications').width();
    $('.dashboard_notifications').css({'height':elem+'px'});
});
</script>
