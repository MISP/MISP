<div class="index">
	<h2>Freetext Import Results</h2>
	<p>Below you can see the attributes that are to be created based on the results of the free-text import. Make sure that the categories and the types are correct, often several options will be offered based on an inconclusive automatic resolution. </p>
	<?php 
		echo $this->Form->create('Attribute', array('url' => '/events/saveFreeText/' . $event_id));
		echo $this->Form->input('JsonObject', array(
				'label' => false,
				'type' => 'text',
				'style' => 'display:none;',
				'value' => '',
		));
		echo $this->Form->end();
	?>
	<table class="table table-striped table-hover table-condensed">
		<tr>
				<th>Value</th>
				<th>Category</th>
				<th>Type</th>
				<th>IDS<input type="checkbox" id="checkAll" style="margin:0px;margin-left:3px;"/></th>
				<th>Comment</th>
				<th>Actions</th>
		</tr>
		<?php
			$options = array();
			foreach ($resultArray as $k => $item):
		?>
		<tr id="row_<?php echo $k; ?>" class="freetext_row">
			<?php 
				echo $this->Form->input('Attribute' . $k . 'Save', array(
						'label' => false,
						'style' => 'display:none;',
						'value' => 1,
				));
				echo $this->Form->input('Attribute' . $k . 'Value', array(
						'label' => false,
						'type' => 'hidden',
						'value' => h($item['value']),
				));
			?>
			<td>
				<input type="hidden" id="<?php echo 'Attribute' . $k . 'Save'; ?>" value=1 >
				<div id="<?php echo 'Attribute' . $k . 'Value'; ?>"><?php echo h($item['value']); ?></div>
			</td>
			<td class="short">
				<?php 
					if (!isset($item['category'])) {
						$default = array_search($defaultCategories[$item['default_type']], $typeCategoryMapping[$item['default_type']]);
					} else {
						$default = array_search($item['category'], $typeCategoryMapping[$item['default_type']]);
					}
				?>
				<select id="<?php echo 'Attribute' . $k . 'Category'; ?>" style='padding:0px;height:20px;margin-bottom:0px;'>
					<?php 
						foreach ($typeCategoryMapping[$item['default_type']] as $type) {
							echo '<option value="' . $type . '" ';
							if ($type == $default) echo 'selected="selected"';
							echo '>' . $type . '</option>';
						}
					?>
				</select>
			</td>
			<td class="short">
				<?php 
					$divVisibility = '';
					$selectVisibility = '';
					if (count($item['types']) == 1) {
						$selectVisibility = 'display:none;';
					} else {
						$divVisibility = 'style="display:none;"';
						if (!in_array(array_keys($item['types']), $options)) $options[] = array_keys($item['types']);
					}
				?>
				<div id = "<?php echo 'Attribute' . $k . 'TypeStatic'; ?>" <?php echo $divVisibility; ?> ><?php echo h($item['default_type']); ?></div>
				<select id = "<?php echo 'Attribute' . $k . 'Type'; ?>" class='typeToggle' style='padding:0px;height:20px;margin-bottom:0px;<?php echo $selectVisibility; ?>'>
					<?php 
						foreach ($item['types'] as $type) {
							echo '<option value="' . $type . '" ';
							echo ($type == $item['default_type'] ? 'selected="selected"' : '') . '>' . $type . '</option>';
						}
					?>
				</select>
			</td>
			<td class="short" style="width:40px;text-align:center;">
				<input type="checkbox" id="<?php echo 'Attribute' . $k . 'To_ids'; ?>" <?php if ($item['to_ids']) echo 'checked'; ?> class="idsCheckbox" />
			</td>
			<td class="short">
				<input type="text" class="freetextCommentField" id="<?php echo 'Attribute' . $k . 'Comment'; ?>" style="padding:0px;height:20px;margin-bottom:0px;" placeholder="Imported via the freetext import." <?php if (isset($item['comment']) && $item['comment'] !== false) echo 'value="' . $item['comment'] . '"'?>/>
			</td>
			<td class="action short">
				<span class="icon-remove pointer" onClick="freetextRemoveRow('<?php echo $k; ?>', '<?php echo $event_id; ?>');"></span>
			</td>
		</tr>
	<?php
		endforeach;
		$optionsRearranged = array();
		foreach ($options as $group) {
			foreach ($group as $k => $element) {
				$temp = $group;
				unset ($temp[$k]);
				if (!isset($optionsRearranged[$element])) $optionsRearranged[$element] = array();
				$optionsRearranged[$element] = array_merge($optionsRearranged[$element], $temp);
			}
		}
	?>
	</table>
	<span>
		<button class="btn btn-primary" style="float:left;" onClick="freetextImportResultsSubmit('<?php echo h($event_id); ?>', '<?php echo count($resultArray); ?>');">Submit</button>
		<span style="float:right">
			<?php
				if (!empty($optionsRearranged)):
			?>
				<select id="changeFrom" style="margin-left:50px;margin-top:10px;">
					<?php 
						foreach (array_keys($optionsRearranged) as $fromElement):
					?>
							<option><?php echo $fromElement; ?></option>
					<?php 	
						endforeach;
					?>
				</select>
				<span class="icon-arrow-right"></span>
				<select id="changeTo" style="margin-top:10px;">
					<?php 
						$keys = array_keys($optionsRearranged);
						foreach ($optionsRearranged[$keys[0]] as $toElement):
					?>
							<option value="<?php echo $toElement; ?>"><?php echo $toElement; ?></option>
					<?php 	
						endforeach;
					?>
				</select>
				<span class="btn btn-inverse" onClick="changeFreetextImportExecute();">Change all</span><br />
			<?php endif; ?>
			<input type="text" id="changeComments" style="margin-left:50px;margin-top:10px;width:446px;" placeholder="Update all comment fields">
			<span class="btn btn-inverse" onClick="changeFreetextImportCommentExecute();">Change all</span>
		</span>
	</span>
</div>
<?php if (!empty($optionsRearranged)):?>
	<script>
		var options = <?php echo json_encode($optionsRearranged);?>;
		$(document).ready(function(){
			$('#changeFrom').change(function(){
				changeFreetextImportFrom();
			});
			$('#changeFrom').trigger('change');
			$('#checkAll').change(function() {
				$('.idsCheckbox').prop('checked', $('#checkAll').is(':checked'));
			});
		});
	</script>
<?php 
	endif;
	echo $this->element('side_menu', array('menuList' => 'regexp', 'menuItem' => 'index'));
?>
