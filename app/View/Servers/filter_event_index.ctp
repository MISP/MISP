<div class="events">
    <?php echo $this->Form->create('Event', array('id' => 'test', 'url' => '/events/index'));?>
    <fieldset>
        <legend><?php echo __('Filter Event Index');?></legend>
        <div class="overlay_spacing">
        <p><?php echo __('Please enter the url parameters that are to be used for the request. Valid parameters are: ');?></p>
        <p><?php echo h(implode(', ', $validFilters)); ?></p>
        <p><?php echo __('Example:');?></p>
        <p><code>/searchdistribution:2/searchorg:Org1|!Org2/searchpublished:1</code></p>
        <?php
                echo $this->Form->input('filter', array(
                        'label' => false,
                        'class' => 'input-large',
                        'style' => 'width:665px;',
                        'div' => false,
                        'default' => h($filter),
                ));
        ?>
        </div>
        <div class="overlay_spacing">
        <span role="button" tabindex="0" aria-label="<?php echo __('Apply filters to the remote instance's index');?>" title="<?php echo __('Apply filters to the remote instance's index');?>" class="btn btn-primary" onClick="remoteIndexApplyFilters(actionUrl);"><?php echo __('Apply');?></span>
        <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" onClick="cancelPopoverForm();" style="float:right;"><?php echo __('Cancel');?></span>
        </div>
    </fieldset>
    <?php echo $this->Form->end();?>
</div>

<script type="text/javascript">
var filterContext = "event";
var actionUrl = "<?php echo '/servers/previewIndex/' . h($id); ?>"
$(document).ready(function() {
    $('.datepicker').datepicker().on('changeDate', function(ev) {
        $('.dropdown-menu').hide();
    });
});

</script>
<?php echo $this->Js->writeBuffer();
