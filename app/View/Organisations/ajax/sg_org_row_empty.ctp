<?php $id = h($id);?>
<tr id="orgRow<?php echo $id;?>" class="orgRow">
	<td id="orgType<?php echo $id;?>" class="short"></td>
	<td id="orgName<?php echo $id;?>"></td>
	<td id="orgUUID<?php echo $id;?>"></td>
<?php if ($removable):
		$checked = '';
		if ($extend) $checked = 'checked';
?>
	<td id="orgExtend<?php echo $id;?>"><input title="Mark organisation as sharing group extender" id="orgExtendInput<?php echo $id;?>" type="checkbox" onClick="sharingGroupExtendOrg(<?php echo $id;?>)" <?php echo h($checked);?>></input></td>
<?php else: ?>
	<td id="orgExtend<?php echo $id;?>" ><span id="orgExtendSpan<?php echo $id;?>" class="icon-ok"></span></td>
<?php endif; ?>
	<td id="orgAction<?php echo $id;?>" class="actions short"></td>
</tr>
