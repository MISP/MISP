<div class="index">
<b>Table of contents</b><br>
1. <?php echo $this->Html->link(__('General Layout', true), array('controller' => 'pages', 'action' => 'display', 'documentation')); ?><br>
2. <?php echo $this->Html->link(__('User Management and Global Actions', true), array('controller' => 'pages', 'action' => 'display', 'user_management')); ?><br>
3. <?php echo $this->Html->link(__('Using the system', true), array('controller' => 'pages', 'action' => 'display', 'using_the_system')); ?><br>
4. <?php echo $this->Html->link(__('Administration', true), array('controller' => 'pages', 'action' => 'display', 'administration')); ?><br>
5. <?php echo $this->Html->link(__('Categories and Types', true), array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?></p>
		</td>
	</tr>
</table>
<hr/><br>
<?php
// Load the Attribute model to extract the documentation from the defintions
App::import('Model', 'Attribute');
$attr = new Attribute();
?>
<h2>Attribute Categories and Types</h2>
<h3>Attribute Categories vs Types</h3>
<table>
<tr>
	<th>Category</th>
	<?php foreach ($attr->categoryDefinitions as $cat => $catDef): ?>
	<th style="width:5%; text-align:center; white-space:normal"><?php echo $cat; ?></th>
	<?php endforeach;?>
</tr>
<?php foreach ($attr->typeDefinitions as $type => $def): ?>
<tr>
	<td><?php echo $type; ?></td>
	<?php foreach ($attr->categoryDefinitions as $cat => $catDef): ?>
	<td style="text-align:center"><?php echo in_array($type, $catDef['types'])? 'X' : ''; ?></td>
	<?php endforeach;?>
<?php endforeach;?>
</tr>
<tr>
	<th>Category</th>
	<?php foreach ($attr->categoryDefinitions as $cat => $catDef): ?>
	<th style="width:5%; text-align:center; white-space:normal"><?php echo $cat; ?></th>
	<?php endforeach;?>
</tr>
</table>
<h3>Categories</h3>
<table>
<tr>
	<th>Category</th>
	<th>Description</th>
</tr>
<?php foreach ($attr->categoryDefinitions as $cat => $def): ?>
<tr>
	<td><?php echo $cat; ?></td>
	<td><?php echo isset($def['formdesc'])? $def['formdesc'] : $def['desc']; ?></td>
<?php endforeach;?>
</tr>
</table>
<h3>Types</h3>
<table>
<tr>
	<th>Type</th>
	<th>Description</th>
</tr>
<?php foreach ($attr->typeDefinitions as $type => $def): ?>
<tr>
	<td><?php echo $type; ?></td>
	<td><?php echo isset($def['formdesc'])? $def['formdesc'] : $def['desc']; ?></td>
<?php endforeach;?>
</tr>
</table>

	
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>


