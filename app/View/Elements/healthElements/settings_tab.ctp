<div class="settingsTableContainerOutline">
<?php
	foreach ($finalSettings as $subGroup => &$settings):
?>
	<div>
		<table class="table table-hover table-condensed settingsTableContainer">
			<?php if ($subGroup != 'general'): ?>
				<tr>
					<th class="useCursorPointer" role="button" tabindex="0" aria-label="Toggle subgroup <?php echo h($subGroup); ?>" title="Toggle subgroup" style="border-right: 1px solid #dddddd;color: #0088cc;" onClick="toggleSettingSubGroup('<?php echo h($subGroup);?>')"><?php echo h($subGroup);?></th>
				</tr>
			<?php endif;?>
			<tr class="subGroup_<?php echo h($subGroup);?> hidden">
					<th>Priority</th>
					<th>Setting</th>
					<th>Value</th>
					<th>Description</th>
					<th>Error Message</th>
			</tr>
			<?php
				foreach ($settings as $k => $setting):
					$bgColour = '';
					if (isset($setting['error']) && $setting['level'] < 3) {
						$bgColour = 'background-color:' . $priorityErrorColours[$setting['level']] . ';';
						if ($setting['level'] == 0 || $setting['level'] == 2) $bgColour .= 'color:white;';
					}
					if ($setting['level'] == 3) $bgColour = 'background-color:gray;color:white;';
					if ($setting['type'] == 'boolean') $setting['value'] = ($setting['value'] === true ? 'true' : 'false');;
					if (isset($setting['options'])) {
						$setting['value'] = $setting['options'][$setting['value']];
					}
					if ($setting['setting'] == 'Security.salt' && !isset($setting['error'])) {
						continue;
					}
					if (!empty($setting['redacted'])) {
						$setting['value'] = '*****';
					}
			?>
			<tr id ="<?php echo h($subGroup) . '_' . $k; ?>_row" class="subGroup_<?php echo h($subGroup);?> hidden">
				<td class="short" style="<?php echo $bgColour; ?>"><?php echo h($priorities[$setting['level']]);?></td>
				<td class="short" style="<?php echo $bgColour; ?>"><?php echo h($setting['setting']);?></td>
				<?php if ((isset($setting['editable']) && !$setting['editable']) || $setting['level'] == 3): ?>
					<td id="setting_<?php echo h($subGroup) . '_' . $k; ?>_passive" class="inline-field-solid" style="<?php echo $bgColour; ?>width:500px;"><?php echo nl2br(h($setting['value']));?></td>
				<?php else: ?>
					<td id="setting_<?php echo h($subGroup) . '_' . $k; ?>_solid" class="inline-field-solid" ondblclick="serverSettingsActivateField('<?php echo $setting['setting'];?>', '<?php echo $k;?>')" style="<?php echo $bgColour; ?>width:500px;">
						<?php echo h($setting['value']); ?>
					</td>
					<td id="setting_<?php echo h($subGroup) . '_' . $k; ?>_placeholder" class="short hidden inline-field-placeholder" style="<?php echo $bgColour; ?>width:500px;"></td>
				<?php endif; ?>
				<td style="<?php echo $bgColour; ?>"><?php echo h($setting['description']);?></td>
				<td style="<?php echo $bgColour; ?>"><?php if (isset($setting['error']) && $setting['level'] != 3) echo h($setting['errorMessage']); ?></td>
			</tr>
		<?php
			endforeach;
		?>
		</table>
		<div class="subGroup_<?php echo h($subGroup);?> hidden" style="margin-bottom:30px;"></div>
	</div>
<?php
	endforeach;
?>
</div>
<script type="text/javascript">
	$(document).ready(function() {
		$('.subGroup_general').show();
	});
</script>
