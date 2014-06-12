<li id="id_<?php echo $element_id;?>" class="templateTableRow">
	<div class="templateElementHeader" style="width:100%; position:relative;">
		<div class="templateGlass"></div>
		<div class ="templateElementHeaderText">Attribute</div>
	</div>
	<table style="width:100%">
		<tr style="width:100%">
			<td class="templateTableTDName  templateTableCellFirst templateTableColumnName">Name</td>
			<td class="templateTableTDDescription templateTableCell templateTableColumnName">Description</td>
			<td class="templateTableNormal templateTableCell templateTableColumnName">Category</td>
			<td class="templateTableTDTypes templateTableCell templateTableColumnName">Valid Types</td>
			<td class="templateTableTDShort templateTableCell templateTableColumnName">Req.</td>
			<td class="templateTableTDShort templateTableCell templateTableColumnName">Batch</td>
			<td class="templateTableTDShort templateTableCell templateTableColumnName">IDS</td>
			<td class="templateTableTDActions templateTableCell templateTableColumnName">Actions</td>
		</tr>
		<tr>
			<td class="templateTableTDName  templateTableCellFirst">
				<?php echo h($element['TemplateElementAttribute'][0]['name']); ?>&nbsp;
			</td>
			<td class="templateTableTDDescription templateTableCell">
				<?php echo h($element['TemplateElementAttribute'][0]['description']); ?>&nbsp;
			</td>
			<td class="templateTableNormal templateTableCell">
				<?php echo h($element['TemplateElementAttribute'][0]['category']); ?>&nbsp;
			</td>
			<td class="templateTableTDTypes templateTableCell">
				<?php 
					if ($element['TemplateElementAttribute'][0]['complex']) {
						echo '<span style="color:red;font-weight:bold;">' . h($element['TemplateElementAttribute'][0]['type']) . '</span> ('; 
						foreach ($validTypeGroups[$element['TemplateElementAttribute'][0]['type']]['types'] as $k => $type) {
							if ($k != 0) echo ', ' . h($type);
							else echo h($type);
						} 
						echo ')';
					} else echo h($element['TemplateElementAttribute'][0]['type']);
				?>&nbsp;
			</td>
			<td class="templateTableTDShort templateTableCell">
				<?php 
					if ($element['TemplateElementAttribute'][0]['mandatory']) echo 'Yes';
					else echo 'No';  
				?>&nbsp;
			</td>
			<td class="templateTableTDShort templateTableCell">
				<?php 
					if ($element['TemplateElementAttribute'][0]['batch']) echo 'Yes';
					else echo 'No'; 
				?>&nbsp;
			</td>
			<td class="templateTableTDShort templateTableCell">
				<?php 
					$ids_text = array('No', 'Yes', 'User');
					echo h($ids_text[$element['TemplateElementAttribute'][0]['to_ids']]);
				?>&nbsp;
			</td>
			<td class="templateTableTDActions templateTableCell">
				&nbsp;
			</td>
		</tr>
	</table>
</li>
