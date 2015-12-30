<div class="actions <?php echo $debugMode;?>">
	<ol class="nav nav-list">
			<li><?php echo $this->Html->link('Quick Start', array('controller' => 'pages', 'action' => 'display', 'doc', 'quickstart')); ?></li>
			<li><?php echo $this->Html->link('General Layout', array('controller' => 'pages', 'action' => 'display', 'doc', 'general')); ?></li>
			<li><?php echo $this->Html->link('General Concepts', array('controller' => 'pages', 'action' => 'display', 'doc', 'concepts')); ?></li>
			<li><?php echo $this->Html->link('User Management and Global actions', array('controller' => 'pages', 'action' => 'display', 'doc', 'user_management')); ?></li>
			<li><?php echo $this->Html->link('Using the system', array('controller' => 'pages', 'action' => 'display', 'doc', 'using_the_system')); ?></li>
			<li><?php echo $this->Html->link('Administration', array('controller' => 'pages', 'action' => 'display', 'doc', 'administration')); ?></li>
			<li class="active"><?php echo $this->Html->link('Categories and Types', array('controller' => 'pages', 'action' => 'display', 'doc', 'categories_and_types')); ?></li>
	</ol>
</div>
<div class="index">
<h2>Attribute Categories and Types</h2>
<h3>Attribute Categories vs Types</h3>
<table class="table table-striped table-hover table-condensed table-bordered">
	<tr>
		<th>Category</th>
		<?php foreach ($categoryDefinitions as $cat => $catDef):	?>
		<th style="width:5%; text-align:center; white-space:normal">
			<a href="#<?php echo $cat; ?>"><?php echo $cat; ?></a>
		</th>
		<?php endforeach; ?>
		<th>Category</th>
	</tr>
	<?php foreach ($typeDefinitions as $type => $def): ?>
	<tr>
		<th><a href="#<?php echo $type; ?>"><?php echo $type; ?></a></th>
		<?php foreach ($categoryDefinitions as $cat => $catDef): ?>
		<td style="text-align:center">
			<?php echo in_array($type, $catDef['types'])? 'X' : ''; ?>
		</td>
		<?php endforeach; ?>
		<th><a href="#<?php echo $type; ?>"><?php echo $type; ?></a></th>
	<?php endforeach; ?>
	</tr>
<tr>
	<th>Category</th>
	<?php foreach ($categoryDefinitions as $cat => $catDef): ?>
	<th style="width:5%; text-align:center; white-space:normal">
		<a href="#<?php echo $cat; ?>"><?php echo $cat; ?></a>
	</th>
	<?php endforeach; ?>
	<th>Category</th>
</tr>
</table>
<h3>Categories</h3>
<table class="table table-striped table-condensed table-bordered">
	<tr>
		<th>Category</th>
		<th>Description</th>
	</tr>
	<?php foreach ($categoryDefinitions as $cat => $def): ?>
	<tr>
		<th><a id="<?php echo $cat; ?>"></a>
			<?php echo $cat; ?>
		</th>
		<td>
			<?php echo isset($def['formdesc'])? $def['formdesc'] : $def['desc']; ?>
		</td>
	</tr>
	<?php endforeach; ?>
</table>
<h3>Types</h3>
<table class="table table-striped table-condensed table-bordered">
	<tr>
		<th>Type</th>
		<th>Description</th>
	</tr>
	<?php foreach ($typeDefinitions as $type => $def): ?>
	<tr>
		<th><a id="<?php echo $type; ?>"></a>
			<?php echo $type; ?>
		</th>
		<td>
			<?php echo isset($def['formdesc'])? $def['formdesc'] : $def['desc']; ?>
		</td>
	</tr>
	<?php endforeach;?>
</table>
<p><a href="<?php echo $baseurl;?>/pages/display/doc/md/categories_and_types">Click here to get the .md version for gitbook generation.</a></p>
</div>
