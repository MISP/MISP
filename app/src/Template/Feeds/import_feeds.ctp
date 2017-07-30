<div class="feed form">
<?php echo $this->Form->create('Feed');?>
	<fieldset>
		<legend>Paste feed data</legend>
		<p>Paste a MISP feed metadata JSON below to add feeds.</p>
	<div>
	<?php
		echo $this->Form->input('json', array(
				'div' => 'input clear',
				'placeholder' => 'Feed metadata JSON',
				'class' => 'form-control span6',
				'type' => 'textarea',
				'rows' => 18
		));
	?>
	</div>
	</fieldset>
	<?php
		echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
		echo $this->Form->end();
	?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'feeds', 'menuItem' => 'import'));
