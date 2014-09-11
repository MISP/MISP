<table class="table table-hover table-condensed">
<tr>
		<th>Priority</th>
		<th>Setting</th>
		<th>Value</th>
		<th>Description</th>
		<th>Error Message</th>
		<th>Actions</th>
</tr>
<?php
	foreach ($finalSettings as $k => $setting):
		$bgColour = '';
		if (isset($setting['error']) && $setting['level'] < 3) {
			$bgColour = 'background-color:' . $priorityErrorColours[$setting['level']] . ';';
			if ($setting['level'] == 0 || $setting['level'] == 2) $bgColour .= 'color:white;';
		}
		if ($setting['level'] == 3) $bgColour = 'background-color:gray;color:white;';
		if ($setting['type'] == 'boolean') $setting['value'] = ($setting['value'] === true ? 'true' : 'false');
		if (isset($setting['options'])) $setting['value'] = ($setting['options'][$setting['value']]);
?>
<tr>
	<td class="short" style="<?php echo $bgColour; ?>"><?php echo h($priorities[$setting['level']]);?></td>
	<td class="short" style="<?php echo $bgColour; ?>"><?php echo h($setting['setting']);?></td>
	<?php if ((isset($setting['editable']) && !$setting['editable']) || $setting['level'] == 3): ?>
		<td id="setting_<?php echo $k; ?>_passive" class="short inline-field-solid" style="<?php echo $bgColour; ?>width:300px;"><?php echo h($setting['value']);?></td>
	<?php else: ?>
		<td id="setting_<?php echo $k; ?>_solid" class="short inline-field-solid" onClick="serverSettingsActivateField('<?php echo $setting['setting'];?>', '<?php echo $k;?>')" style="<?php echo $bgColour; ?>width:300px;"><?php echo h($setting['value']);?></td>
		<td id="setting_<?php echo $k; ?>_placeholder" class="short hidden inline-field-placeholder" style="<?php echo $bgColour; ?>width:300px;"></td>
	<?php endif; ?>
	<td style="<?php echo $bgColour; ?>"><?php echo h($setting['description']);?></td>
	<td style="<?php echo $bgColour; ?>"><?php if (isset($setting['error']) && $setting['level'] != 3) echo h($setting['errorMessage']); ?></td>
	<td class="short" style="<?php echo $bgColour; ?>"></td>
</tr>
<?php
	endforeach; ?>
</table>