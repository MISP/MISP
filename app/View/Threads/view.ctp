<div class="threads view">
	<h3><?php echo $thread_title; ?></h3>
<?php
	echo $this->element('eventdiscussion');
?>
		<div>
			<a href = <?php echo Configure::read('CyDefSIG.baseurl') . '/posts/add/thread/' . $thread_id; ?>><span class="btn btn-primary">Add comment</span></a>
		</div>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li class="active"><?php echo $this->Html->link('View Thread', array('controller' => 'threads', 'action' => 'view', $thread_id));?></li>
		<li><?php echo $this->Html->link('Add Post', array('controller' => 'posts', 'action' => 'add', 'thread', $thread_id));?></li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Threads', array('controller' => 'threads', 'action' => 'index'));?></li>
		<li><a href = "<?php echo Configure::read('CyDefSIG.baseurl');?>/posts/add/">New Thread</a></li>
	</ul>
</div>