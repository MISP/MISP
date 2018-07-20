<div class="dashboard_element dashboard_notifications">
    <h4><?php echo __('Notifications'); ?></h4>
    <p>
        <b><?php echo __('Proposals: '); ?></b><span class="bold <?php echo $notifications['proposalCount'] ? 'red' : 'green'; ?>"><?php echo h($notifications['proposalCount']);?></span> (<a href="<?php echo $baseurl;?>/shadow_attributes/index"><?php echo __('View'); ?></a>)<br />
        <b><?php echo __('Events with proposals: '); ?></b><span class="bold <?php echo $notifications['proposalEventCount'] ? 'red' : 'green'; ?>"><?php echo h($notifications['proposalEventCount']);?></span> (<a href="<?php echo $baseurl;?>/events/proposalEventIndex"><?php echo __('View'); ?></a>)<br />
        <?php
            if (isset($notifications['delegationCount'])):
        ?>
            <b><?php echo __('Delegation requests: '); ?></b><span class="bold <?php echo $notifications['delegationCount'] ? 'red' : 'green'; ?>"><?php echo h($notifications['delegationCount']);?></span> (<a href="<?php echo $baseurl;?>/events/delegation_index"><?php echo __('View'); ?></a>)
        <?php
            endif;
        ?>
    </p>
</div>
<script type="text/javascript">
$(document).ready(function() {
    var elem = $('.dashboard_notifications').width();
    $('.dashboard_notifications').css({'height':elem+'px'});
});
</script>
