<div class="warninglist view">
<h2><?php echo h(strtoupper($warninglist['Warninglist']['name'])); ?></h2>
	<dl>
		<dt>Id</dt>
		<dd>
			<?php echo h($warninglist['Warninglist']['id']); ?>
			&nbsp;
		</dd>
		<dt>Name</dt>
		<dd>
			<?php echo h($warninglist['Warninglist']['name']); ?>
			&nbsp;
		</dd>
		<dt>Description</dt>
		<dd>
			<?php echo h($warninglist['Warninglist']['description']); ?>
			&nbsp;
		</dd>
		<dt>Version</dt>
		<dd>
			<?php echo h($warninglist['Warninglist']['version']); ?>
			&nbsp;
		</dd>
		<dt>Type</dt>
		<dd>
			<?php echo h($warninglist['Warninglist']['type']); ?>
			&nbsp;
		</dd>
		<dt>Accepted attribute types</dt>
		<dd>
			<?php
				$text = array();
				foreach ($warninglist['WarninglistType'] as $temp) $text[] = $temp['type'];
				$text = implode(', ', $text);
				echo h($text);
			?>
		</dd>
		<dt>Enabled</dt>
		<dd>
			<?php echo $warninglist['Warninglist']['enabled'] ? '<span class="green">Yes</span>&nbsp;&nbsp;' : '<span class="red">No</span>&nbsp;&nbsp;';
				if ($isSiteAdmin) {
					if ($warninglist['Warninglist']['enabled']) {
						echo $this->Form->postLink('(disable)', array('action' => 'enableWarninglist', h($warninglist['Warninglist']['id'])), array('title' => 'Disable'));
					} else {
						echo $this->Form->postLink('(enable)', array('action' => 'enableWarninglist', h($warninglist['Warninglist']['id']), 'true') ,array('title' => 'Enable'));
					}
				}
			?>

			&nbsp;
		</dd>
	</dl>
	<br />
	<h3>Values</h3>
	<div><?php
		foreach ($warninglist['WarninglistEntry'] as $entry) echo h($entry['value']) . '<br />';
	?></div>
</div>
<script type="text/javascript">
	$(document).ready(function(){
		$('input:checkbox').removeAttr('checked');
		$('.mass-select').hide();
		$('.select_taxonomy, .select_all').click(function(){
			taxonomyListAnyCheckBoxesChecked();
		});
	});
</script>
<?php
	echo $this->element('side_menu', array('menuList' => 'warninglist', 'menuItem' => 'view'));
?>
