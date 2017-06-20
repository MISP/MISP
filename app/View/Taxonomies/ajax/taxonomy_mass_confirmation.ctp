<div class="confirmation">
<?php
	echo $this->Form->create('Taxonomy', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/taxonomies/addTag'));
?>
	<div class="hidden">
<?php
	echo $this->Form->input('nameList', array('value' => '{}'));
?>
	</div>
<?php
	echo $this->Form->input('taxonomy_id', array('type' => 'hidden', 'value' => $id));
?>
<legend>Create Tags</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p>Are you sure you want to create / update all selected tags?</p>
	<table>
		<tr>
			<td style="vertical-align:top">
				<span id="PromptYesButton" role="button" tabindex="0" aria-label="Create / update all selected taxonomy entries as tags" title="Create / update all taxonomy entries as tags" class="btn btn-primary" onClick="submitMassTaxonomyTag();">Yes</span>
			</td>
			<td style="width:540px;">
			</td>
			<td style="vertical-align:top;">
				<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
			</td>
		</tr>
	</table>
</div>
<script type="text/javascript">
	$(document).ready(function(){
		getSelectedTaxonomyNames();
	});
</script>
<?php
	echo $this->Form->end();
?>
</div>
