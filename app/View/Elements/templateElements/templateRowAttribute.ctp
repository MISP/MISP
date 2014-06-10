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
				<?php echo $element['TemplateElementAttribute'][0]['name']; ?>&nbsp;
			</td>
			<td class="templateTableTDDescription templateTableCell">
				<?php echo $element['TemplateElementAttribute'][0]['description']; ?>&nbsp;
			</td>
			<td class="templateTableNormal templateTableCell">
				<?php echo $element['TemplateElementAttribute'][0]['category']; ?>&nbsp;
			</td>
			<td class="templateTableTDTypes templateTableCell">
				<?php 
					foreach ($element['TemplateElementAttribute'][0]['type'] as $k => $type) {
						if ($k != 0) echo ', ' . $type;
						else echo $type;
					} 
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
					echo $ids_text[$element['TemplateElementAttribute'][0]['to_ids']];
				?>&nbsp;
			</td>
			<td class="templateTableTDActions templateTableCell">
				&nbsp;
			</td>
		</tr>
	</table>
</li>
