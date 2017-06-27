<div class="users form">
	<fieldset>
		<legend><?php echo __('New Sharing Group'); ?></legend>
		<div class="tabMenuFixedContainer">
			<span id="page1_tab" role="button" tabindex="0" aria-label="General tab" title="General tab" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer tabMenuActive" onClick="simpleTabPage(1);">General</span>
			<span id="page2_tab" role="button" tabindex="0" aria-label="Organisations tab" title="Organisations tab" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="simpleTabPage(2);">Organisations</span>
			<span id="page3_tab" role="button" tabindex="0" aria-label="MISP instances tab" title="MISP instances tab" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="simpleTabPage(3);">MISP Instances</span>
			<span id="page4_tab" role="button" tabindex="0" aria-label="Sharing group summary" title="Sharing group summary" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="simpleTabPage(4);">Summary and Save</span>
		</div>
		<div id="page1_content" class="multi-page-form-div tabContent" style="width:544px;">
			<label for="SharingGroupName">Name</label>
			<input type="text" class="input-xxlarge" placeholder="Example: Multinational sharing group" id="SharingGroupName"></input>
			<label for="SharingGroupReleasability">Releasable to</label>
			<input type="text" class="input-xxlarge" placeholder="Example: Community1, Organisation1, Organisation2" id="SharingGroupReleasability"></input>
			<label for="SharingGroupDescription">Description</label>
			<textarea class="input-xxlarge" placeholder="A description of the sharing group." cols="30" rows="6" id="SharingGroupDescription"></textarea>
			<div style="display:block;">
				<input type="checkbox" style="float:left;" title="Active sharing groups can be selected by users of the local instance when creating events. Generally, sharing groups received through synchronisation will have this disabled until manually enabled." value="1" id="SharingGroupActive" checked></input>
				<label for="SharingGroupActive" style="padding-left:20px;">Make the sharing group selectable (active)</label>
			</div>
			<span role="button" tabindex="0" aria-label="Next page" title="Next page" class="btn btn-inverse" onClick="simpleTabPage(2);">Next page</span>
		</div>
		<div id="page2_content" class="multi-page-form-div tabContent" style="display:none;width:544px;">
			<div class="tabMenuFixedContainer">
				<span role="button" tabindex="0" aria-label="Add local organisation(s) to the sharing group" title="Add local organisation(s) to the sharing group" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="sharingGroupAdd('organisation', 'local');">Add local organisation</span>
				<span role="button" tabindex="0" aria-label="Add remote organisations to the sharing group" title="Add remote organisations to the sharing group" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="sharingGroupAdd('organisation', 'remote');">Add remote organisation</span>
			</div>
			<table id="organisations_table" class="table table-striped table-hover table-condensed">
				<tr id="organisations_table_header">
					<th>Type</th>
					<th>Name</th>
					<th>UUID</th>
					<th>Extend</th>
					<th>Actions</th>
				</tr>
			</table>
				<span role="button" tabindex="0" aria-label="Previous page" title="Previous page" class="btn btn-inverse" onClick="simpleTabPage(1);">Previous page</span>
				<span role="button" tabindex="0" aria-label="Next page" title="Next page" class="btn btn-inverse" onClick="simpleTabPage(3);">Next page</span>
		</div>
		<div id="page3_content" class="multi-page-form-div tabContent" style="display:none;width:544px;">
			<div style="display:block;">
				<input type="checkbox" style="float:left;" title="Enable roaming mode for this sharing group. Roaming mode will allow the sharing group to be passed to any instance where the remote recipient is contained in the organisation list. It is preferred to list the recipient instances instead." value="1" id="SharingGroupRoaming"></input>
				<label for="SharingGroupRoaming" style="padding-left:20px;"><b>Enable roaming mode</b> for this sharing group (pass the event to any connected instance where the sync connection is tied to an organisation contained in the SG organisation list).</label>
			</div>
			<div id="serverList">
				<div class="tabMenuFixedContainer">
					<span role="button" tabindex="0" aria-label="Add instance" title="Add instance" class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer" onClick="sharingGroupAdd('server');">Add instance</span>
				</div>
				<table id="servers_table" class="table table-striped table-hover table-condensed">
					<tr>
						<th>Name</th>
						<th>URL</th>
						<th>All orgs</th>
						<th>Actions</th>
					</tr>
				</table>
			</div>
				<span role="button" tabindex="0" aria-label="Previous page" title="Previous page" class="btn btn-inverse" onClick="simpleTabPage(2);">Previous page</span>
				<span role="button" tabindex="0" aria-label="Next page" title="Next page" class="btn btn-inverse" onClick="simpleTabPage(4);">Next page</span>
		</div>
	</fieldset>
	<div id="page4_content" class="multi-page-form-div tabContent" style="display:none;width:544px;">
		<p><span class="bold">General: </span>You are about to create the <span id="summarytitle" class="red bold"></span> sharing group, which is intended to be releasable to <span id="summaryreleasable" class="red bold"></span>. </p>
		<p id="localText"><span class="bold">Local organisations: </span>It will be visible to <span id="summarylocal" class="red bold"></span>, from which <span id="summarylocalextend" class="red bold"></span> can extend the sharing group. </p>
		<p id="externalText"><span class="bold">External organisations: </span>It will also be visible to <span id="summaryexternal" class="red bold"></span>, out of which <span id="summaryexternalextend" class="red bold"></span> can extend the sharing group.</p>
		<p id="synchronisationText"><span class="bold">Synchronisation: </span>Furthermore, events are automatically pushed to: <span id="summaryservers" class="red bold"></span></p>
		<p>You can edit this information by going back to one of the previous pages, or if you agree with the above mentioned information, click Submit to create the Sharing group.</p>
		<?php
			echo $this->Form->create('SharingGroup');
			echo $this->Form->input('json', array('style' => 'display:none;', 'label' => false, 'div' => false));
			//echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
			echo $this->Form->end();
		?>
		<span role="button" tabindex="0" aria-label="Previous page" title="Previous page" class="btn btn-inverse" onClick="simpleTabPage(3);">Previous page</span>
		<span role="button" tabindex="0" aria-label="Submit and create sharing group" title="Submit and create sharing group" class="btn btn-primary" onClick="sgSubmitForm('Add');">Submit</span>
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'addSG'));
?>
<script type="text/javascript">
	var lastPage = 4;
	var roaming = false;
	var organisations = [{
		id: '<?php echo h($user['Organisation']['id'])?>',
		type: 'local',
		name: '<?php echo h($user['Organisation']['name'])?>',
		extend: true,
		uuid: '',
		removable: 0
	}];
	var orgids = ['<?php echo h($user['Organisation']['id'])?>'];
	var servers = [{
		id: '0',
		name: 'Local instance',
		url: '<?php echo h($localInstance); ?>',
		all_orgs: false,
		removable: 0
	}];
	var serverids = [0];
	$(function() {
		if ($('#SharingGroupJson').val()) sharingGroupPopulateFromJson();
		sharingGroupPopulateOrganisations();
		sharingGroupPopulateServers();
	});
	$('#SharingGroupRoaming').change(function() {
		if ($(this).is(":checked")) {
			$('#serverList').hide();
		} else {
			$('#serverList').show();
		}
	});

</script>
