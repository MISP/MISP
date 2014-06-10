<li id="id_<?php echo $element_id;?>" class="templateTableRow">
	<div class="templateElementHeader" style="width:100%; position:relative;">
		<div class="templateGlass"></div>
		<div class ="templateElementHeaderText">Text</div>
	</div>
	<table width="100%">
		<tr>
			<td class="templateTableTDName templateTableCellFirst templateTableColumnName">Name</td>
			<td class="templateTableTDText templateTableCell templateTableColumnName">Text</td>
			<td class="templateTableTDActions templateTableCell templateTableColumnName">Actions</td>
		</tr>
		<tr>
			<td class="templateTableTDName  templateTableCellFirst">
				<?php echo $element['TemplateElementText'][0]['name']; ?>&nbsp;
			</td>
			<td class="templateTableTDText templateTableCell">
				<?php echo $element['TemplateElementText'][0]['text']; ?>&nbsp;
			</td>
			<td class="templateTableTDActions templateTableCell">
				&nbsp;
			</td>
		</tr>
	</table>
</li>
