<div class="events">
	<?php echo $this->Form->create('Event', array('id' => 'test', 'url' => '/events/index'));?>
	<fieldset>
		<legend>Filter Event Index</legend>
		<div class="overlay_spacing">
		<p>Please enter the url parameters that are to be used for the request. Valid parameters are: </p>
		<p><?php echo h(implode(', ', $validFilters)); ?></p>
		<p>Example:</p>
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
		<span role="button" tabindex="0" aria-label="Apply filters to the remote instance's index" title="Apply filters to the remote instance's index" class="btn btn-primary" onClick="remoteIndexApplyFilters(actionUrl);">Apply</span>
		<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" onClick="cancelPopoverForm();" style="float:right;">Cancel</span>
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
