<div class="index">
	<h2><?php echo h($title); ?></h2>
	<?php $scope = !empty($proposals) ? 'proposals' : 'attributes'; ?>
	<p>Below you can see the <?php echo $scope; ?> that are to be created. Make sure that the categories and the types are correct, often several options will be offered based on an inconclusive automatic resolution. </p>
	<?php
		$instanceDefault = 5;
		if (!empty(Configure::read('MISP.default_attribute_distribution'))) {
			if (Configure::read('MISP.default_attribute_distribution') == 'event') {
				$instanceDefault = 5;
			} else {
				$instanceDefault = Configure::read('MISP.default_attribute_distribution');
			}
		}
		echo $this->Form->create('Attribute', array('url' => '/events/saveFreeText/' . $event['Event']['id'], 'class' => 'mainForm'));
		if ($isSiteAdmin) {
			echo $this->Form->input('force', array(
					'checked' => false,
					'label' => 'Proposals instead of attributes',
			));
		}
		echo $this->Form->input('JsonObject', array(
				'label' => false,
				'type' => 'text',
				'style' => 'display:none;',
				'value' => '',
		));
		echo $this->Form->input('default_comment', array(
				'label' => false,
				'type' => 'text',
				'style' => 'display:none;',
				'value' => $importComment,
		));
		echo $this->Form->end();
	?>
	<table class="table table-striped table-hover table-condensed">
		<tr>
				<th>Value</th>
				<th>Similar Attributes</th>
				<th>Category</th>
				<th>Type</th>
				<th>IDS<input type="checkbox" id="checkAll" style="margin:0px;margin-left:3px;"/></th>
				<th>Distribution</th>
				<th>Comment</th>
				<th>Tags</th>
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
				echo $this->Form->input('Attribute' . $k . 'Data', array(
						'label' => false,
						'type' => 'hidden',
						'value' => isset($item['data']) ? $item['data'] : false,
				));
				echo $this->Form->input('Attribute' . $k . 'DataIsHandled', array(
						'label' => false,
						'type' => 'hidden',
						'value' => isset($item['data_is_handled']) ? h($item['data_is_handled']) : false,
				));
			?>
			<td>
				<?php
					echo $this->Form->input('Attribute' . $k . 'Value', array(
							'label' => false,
							'value' => $item['value'],
							'style' => 'padding:0px;height:20px;margin-bottom:0px;width:90%;min-width:400px;',
							'div' => false
					));
				?>
				<input type="hidden" id="<?php echo 'Attribute' . $k . 'Save'; ?>" value=1 >
			</td>
			<td class="shortish">
				<?php
					foreach ($item['related'] as $relation):
						$popover = array(
							'Event ID' => $relation['Event']['id'],
							'Event Info' => $relation['Event']['info'],
							'Category' => $relation['Attribute']['category'],
							'Type' => $relation['Attribute']['type'],
							'Value' => $relation['Attribute']['value'],
							'Comment' => $relation['Attribute']['comment'],
						);
						$popoverHTML = '';
						foreach ($popover as $key => $popoverElement) {
							$popoverHTML .= '<span class=\'bold\'>' . $key . '</span>: <span class=\'blue bold\'>' . $popoverElement . '</span><br />';
						}
				?>
						<a href="<?php echo $baseurl; ?>/events/view/<?php echo h($relation['Event']['id']);?>" data-toggle="popover" title="Attribute details" data-content="<?php echo h($popoverHTML); ?>" data-trigger="hover"><?php echo h($relation['Event']['id']);?></a>
				<?php
					endforeach;
					$correlationPopover = array('<span>', );
				?>
			</td>
			<td class="short">
				<?php
					if (!isset($item['categories'])) {
						if (isset($defaultCategories[$item['default_type']])) {
							$default = array_search($defaultCategories[$item['default_type']], $typeCategoryMapping[$item['default_type']]);
						} else {
							reset($typeCategoryMapping[$item['default_type']]);
							$default = key($typeCategoryMapping[$item['default_type']]);
						}
					} else {
						if (isset($item['category_default'])) $default = $item['category_default'];
						else $default = array_search($item['categories'][0], $typeCategoryMapping[$item['default_type']]);

					}
				?>
				<select id="<?php echo 'Attribute' . $k . 'Category'; ?>" style='padding:0px;height:20px;margin-bottom:0px;'>
					<?php
						foreach ($typeCategoryMapping[$item['default_type']] as $category) {
							if (isset($item['categories']) && !in_array($category, $item['categories'])) {
								continue;
							}
							echo '<option value="' . $category . '" ';
							if ($category == $default) echo 'selected="selected"';
							echo '>' . $category . '</option>';
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
						if (!in_array(array_keys($item['types']), $options)) $options[] = array_values($item['types']);
					}
				?>
				<div id = "<?php echo 'Attribute' . $k . 'TypeStatic'; ?>" <?php echo $divVisibility; ?> ><?php echo h($item['default_type']); ?></div>
				<select id = "<?php echo 'Attribute' . $k . 'Type'; ?>" class='typeToggle' style='padding:0px;height:20px;margin-bottom:0px;<?php echo $selectVisibility; ?>'>
					<?php
						if (!empty($item['types'])) {
							foreach ($item['types'] as $type) {
								echo '<option value="' . $type . '" ';
								echo ($type == $item['default_type'] ? 'selected="selected"' : '') . '>' . $type . '</option>';
							}
						}
					?>
				</select>
			</td>
			<td class="short" style="width:40px;text-align:center;">
				<input type="checkbox" id="<?php echo 'Attribute' . $k . 'To_ids'; ?>" <?php if ($item['to_ids']) echo 'checked'; ?> class="idsCheckbox" />
			</td>
			<td class="short" style="width:40px;text-align:center;">
				<select id = "<?php echo 'Attribute' . $k . 'Distribution'; ?>" class='distributionToggle' style='padding:0px;height:20px;margin-bottom:0px;'>
					<?php
						foreach ($distributions as $distKey => $distValue) {
							$default = isset($item['distribution']) ? $item['distribution'] : $instanceDefault;
							echo '<option value="' . $distKey . '" ';
							echo ($distKey == $default ? 'selected="selected"' : '') . '>' . $distValue . '</option>';
						}
					?>
				</select>
				<div style="display:none;">
					<select id = "<?php echo 'Attribute' . $k . 'SharingGroupId'; ?>" class='sgToggle' style='padding:0px;height:20px;margin-top:3px;margin-bottom:0px;'>
						<?php
							foreach ($sgs as $sgKey => $sgValue) {
								echo '<option value="' . $sgKey . '">' . $sgValue . '</option>';
							}
						?>
					</select>
				</div>
			</td>
			<td class="short">
				<input type="text" class="freetextCommentField" id="<?php echo 'Attribute' . $k . 'Comment'; ?>" style="padding:0px;height:20px;margin-bottom:0px;" placeholder="<?php echo h($importComment); ?>" <?php if (isset($item['comment']) && $item['comment'] !== false) echo 'value="' . $item['comment'] . '"'?>/>
			</td>
			<td class="short">
				<input type="text" class="freetextTagField" id="<?php echo 'Attribute' . $k . 'Tags'; ?>" style="padding:0px;height:20px;margin-bottom:0px;"<?php if (isset($item['tags']) && $item['tags'] !== false) echo 'value="' . htmlspecialchars(implode(",",$item['tags'])) . '"'?>/>
			</td>
			<td class="action short">
				<span class="icon-remove pointer" title="Remove resolved attribute" role="button" tabindex="0" aria-label="Remove resolved attribute" onClick="freetextRemoveRow('<?php echo $k; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
			</td>
		</tr>
	<?php
		endforeach;
		$optionsRearranged = array();
		foreach ($options as $group) {
			foreach ($group as $k => $element) {
				$temp = $group;
				unset($temp[$k]);
				if (!isset($optionsRearranged[$element])) $optionsRearranged[$element] = array();
				$optionsRearranged[$element] = array_merge($optionsRearranged[$element], $temp);
			}
		}
	?>
	</table>
	<span>
		<button class="btn btn-primary" style="float:left;" onClick="freetextImportResultsSubmit('<?php echo h($event['Event']['id']); ?>', '<?php echo count($resultArray); ?>');">Submit <?php echo $scope; ?></button>
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
				<span role="button" tabindex="0" aria-label="Apply changes to all applicable resolved attributes" title="Apply changes to all applicable resolved attributes" class="btn btn-inverse" onClick="changeFreetextImportExecute();">Change all</span><br />
			<?php endif; ?>
			<input type="text" id="changeComments" style="margin-left:50px;margin-top:10px;width:446px;" placeholder="Update all comment fields">
			<span role="button" tabindex="0" aria-label="Change all" title="Change all" class="btn btn-inverse" onClick="changeFreetextImportCommentExecute();">Change all</span>
		</span>
	</span>
</div>
	<script>
		var options = <?php echo json_encode($optionsRearranged);?>;
		$(document).ready(function() {
			popoverStartup();
		<?php
			if (!empty($optionsRearranged)):
		?>
				$('#changeFrom').change(function(){
					changeFreetextImportFrom();
				});
				$('#changeFrom').trigger('change');
		<?php
			endif;
		?>
			$('#checkAll').change(function() {
				$('.idsCheckbox').prop('checked', $('#checkAll').is(':checked'));
			});
			$('.distributionToggle').change(function() {
				if ($(this).val() == 4) {
					$(this).next().show();
				} else {
					$(this).next().hide();
				}
			});
		});
	</script>
<?php
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'freetextResults'));
?>
