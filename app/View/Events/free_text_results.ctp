<div class="index">
	<h2>Freetext Import Results</h2>
	<p>Below you can see the attributes that are to be created based on the results of the free-text import. Make sure that the categories and the types are correct, often several options will be offered based on an inconclusive automatic resolution. </p>
	<table class="table table-striped table-hover table-condensed">
		<tr>
				<th>Value</th>
				<th>Category</th>
				<th>Type</th>
				<th>IDS</th>
				<th>Actions</th>
		</tr>
		<?php
			echo $this->Form->create('Attribute', array('url' => '/events/saveFreeText/' . $event_id));
			foreach ($resultArray as $k => $item):
		?>
		<tr id="row_<?php echo $k; ?>">
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
						));
					}
				?>
			</td>
			<td class="short">
				<?php 
					echo $this->Form->input('Attribute.' . $k . '.to_ids', array(
							'label' => false,
							'type' => 'checkbox',
							'checked' => $item['to_ids'],
					));
				?>
			</td>
			<td class="action short">
				<span class="icon-remove pointer" onClick="freetextRemoveRow('<?php echo $k; ?>');"></span>
			</td>
		</tr>
	<?php
		endforeach;
	?>
	</table>
	<?php
		echo $this->Form->button('Submit', array('class' => 'btn btn-inverse'));
		echo $this->Form->end();
	?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'regexp', 'menuItem' => 'index'));
?>
