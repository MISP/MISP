<div class="index">
	<h2>Freetext Import Results</h2>
	<p>Below you can see the attributes that are to be created based on the results of the free-text import. Make sure that the categories and the types are correct, often several options will be offered based on an inconclusive automatic resolution. </p>
	<table class="table table-striped table-hover table-condensed">
		<tr>
				<th>Value</th>
				<th>Category</th>
				<th>Type</th>
				<th>IDS</th>
				<th>Comment</th>
				<th>Actions</th>
		</tr>
		<?php
			$options = array();
			echo $this->Form->create('Attribute', array('url' => '/events/saveFreeText/' . $event_id));
			foreach ($resultArray as $k => $item):
		?>
		<tr id="row_<?php echo $k; ?>" class="freetext_row">
			<?php 
				echo $this->Form->input('Attribute.' . $k . '.save', array(
						'label' => false,
						'style' => 'display:none;',
						'value' => 1,
				));
				echo $this->Form->input('Attribute.' . $k . '.value', array(
						'label' => false,
						'type' => 'hidden',
						'value' => h($item['value']),
				));
			?>
			<td><?php echo h($item['value']); ?></td>
			<td class="short">
				<?php 
					if (!isset($item['category'])) {
						$default = array_search($defaultCategories[$item['default_type']], $typeCategoryMapping[$item['default_type']]);
					} else {
						$default = array_search($item['category'], $typeCategoryMapping[$item['default_type']]);
					}
					echo $this->Form->input('Attribute.' . $k . '.category', array(
							'label' => false,
							'style' => 'padding:0px;height:20px;margin-bottom:0px;',
							'options' => $typeCategoryMapping[$item['default_type']],
							'value' => $default,
					));
				?>
			</td>
			<td class="short">
				<?php 
					if (count($item['types']) == 1) {
						echo h($item['default_type']); 
						echo $this->Form->input('Attribute.' . $k . '.type', array(
								'label' => false,
								'type' => 'hidden',
								'value' => $item['default_type'],
						));
					} else {
						echo $this->Form->input('Attribute.' . $k . '.type', array(
								'label' => false,
								'style' => 'padding:0px;height:20px;margin-bottom:0px;',
								'options' => $item['types'],
								'value' => $item['default_type'],
								'class' => 'typeToggle',
						));
						if (!in_array(array_keys($item['types']), $options)) $options[] = array_keys($item['types']); 
					}
				?>
			</td>
			<td class="short" style="width:30px;">
				<?php 
					echo $this->Form->input('Attribute.' . $k . '.to_ids', array(
							'label' => false,
							'type' => 'checkbox',
							'checked' => $item['to_ids'],
					));
				?>
			</td>
			<td class="short">
				<?php 
					echo $this->Form->input('Attribute.' . $k . '.comment', array(
							'label' => false,
							'style' => 'padding:0px;height:20px;margin-bottom:0px;',
							'type' => 'text',
							'placeholder' => 'Imported via the freetext import.',
					));
				?>
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
	<?php
		echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
		echo $this->Form->end();
		if (!empty($optionsRearranged)):
	?>
		<span style="float:right">
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
					foreach ($optionsRearranged[array_keys($optionsRearranged)[0]] as $toElement):
				?>
						<option value="<?php echo $toElement; ?>"><?php echo $toElement; ?></option>
				<?php 	
					endforeach;
				?>
			</select>
			<span class="btn btn-inverse" onClick="changeFreetextImportExecute();">Change all</span>
		</span>
	<?php endif; ?>
</div>
<?php if (!empty($optionsRearranged)):?>
	<script>
		var options = <?php echo json_encode($optionsRearranged);?>;
		$(document).ready(function(){
			$('#changeFrom').change(function(){
				changeFreetextImportFrom();
			});
			$('#changeFrom').trigger('change');
		});
	</script>
<?php 
	endif;
	echo $this->element('side_menu', array('menuList' => 'regexp', 'menuItem' => 'index'));
?>
