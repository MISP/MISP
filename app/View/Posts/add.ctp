<div class="posts form">
<?php echo $this->Form->create('Post');?>
	<fieldset>
		<legend>Add Post</legend>
		<p>You can quote something in your message by enclosing the quote between [QUOTE] and [/QUOTE] tags.</p>
	<?php
		$quote = '';
		// If it is a new thread, let the user enter a subject
		if (empty($thread_id) && empty($target_type)) {
			echo $this->Form->input('title', array(
					'label' => 'Thread Subject',
					'class' => 'input-xxlarge'
				));
		} else {
			echo $this->Form->input('title', array(
					'label' => 'Thread Subject',
					'class' => 'input-xxlarge',
					'disabled' => 'true',
					'default' => $title
			));
		}
		if ($target_type === 'post') {
			echo $this->Form->input('responseTo', array(
					'label' => 'In response to',
					'type' => 'textarea',
					'div' => 'input clear',
					'class' => 'input-xxlarge',
					'disabled' => 'true',
					'default' => h($previous)
			));
			$quote = '[QUOTE]' . $previous . '[/QUOTE]' . "\n";
		}
		echo $this->Form->input('message', array(
				'type' => 'textarea',
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'default' => h($quote)
		));
	?>
	</fieldset>
<?php
echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<?php if (!(empty($thread_id) && empty($target_type))) {
		?>
			<li><?php echo $this->Html->link('View Thread', array('controller' => 'threads', 'action' => 'view', $thread_id));?></li>
			<li class="divider"></li>
		<?php 
		}
		?>
		<li><?php echo $this->Html->link('List Threads', array('controller' => 'threads', 'action' => 'index'));?></li>
		<li class="active"><a href = "<?php echo Configure::read('CyDefSIG.baseurl');?>/posts/add/">New Thread</a></li>
	</ul>
</div>
