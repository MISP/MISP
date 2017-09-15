<div class="task index">
	<h2>Scheduled Tasks</h2>
	<p>Here you can schedule pre-defined tasks that will be executed every x hours. You can alter the date and time of the next scheduled execution and the frequency at which it will be repeated (expressed in hours). If you set the frequency to 0 then the task will not be repeated. To change and of the above mentioned settings just click on the appropriate field and hit update all when you are done editing the scheduled tasks.</p>
	<div class="pagination">
		<ul>
		<?php
		$this->Paginator->options(array(
			'update' => '.span12',
			'evalScripts' => true,
			'before' => '$(".progress").show()',
			'complete' => '$(".progress").hide()',
		));

			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		</ul>
	</div>
	<?php
		echo $this->Form->create('Task', array(
		'url' => 'setTask',
		'controller' => 'Tasks',
		'inputDefaults' => array(
		'label' => false
		)));
	?>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('timer', 'Frequency (h)');?></th>
			<th><?php echo $this->Paginator->sort('scheduled_time');?></th>
			<th><?php echo $this->Paginator->sort('next_execution_time', 'Next Run');?></th>
			<th><?php echo $this->Paginator->sort('description');?></th>
			<th><?php echo $this->Paginator->sort('message');?></th>
	</tr><?php
foreach ($list as $item):?>
	<tr>
		<td class="short"><?php echo h($item['Task']['id']);?>&nbsp;</td>
		<td class="short"><?php echo h($item['Task']['type']);?>&nbsp;</td>
		<td class="short">
			<?php
				echo $this->Form->input($item['Task']['id'] . '.timer', array(
					'style' => 'display:none',
					'class' => 'input-mini',
					'default' => h($item['Task']['timer']),
					'id' => $item['Task']['id'] . '-timer-active'
				));
			?>
			<div id="<?php echo $item['Task']['id'];?>-timer-passive" role="button" tabindex="0" aria-label="<?php echo h($item['Task']['timer']); ?>" title="Set frequency timer for scheduled task" onClick="activate1(<?php echo $item['Task']['id'];?>, 'timer')">
				<?php echo h($item['Task']['timer']); ?>
			</div>
		</td>
		<td class="short">
			<div class="input-append bootstrap-timepicker" id="<?php echo $item['Task']['id'] . '-scheduled_time-active';?>" style="display:none">
				<?php
					echo $this->Form->input($item['Task']['id'] . '.scheduled_time', array(
						'class' => 'input-small',
						'type' => 'text',
						'default' => h($item['Task']['scheduled_time']),
						'id' => 'timepicker' . $item['Task']['id']
					));
				?>
			</div>
			<div id="<?php echo $item['Task']['id'];?>-scheduled_time-passive" role="button" tabindex="0" aria-label="<?php echo h($item['Task']['scheduled_time']); ?>" title="set scheduled time for task" onClick="activate2(<?php echo $item['Task']['id'];?>, 'scheduled_time', '<?php echo h($item['Task']['scheduled_time']);?>')">
				<?php echo h($item['Task']['scheduled_time']); ?>
			</div>
		</td>
		<td style="width:250px;">
			<div class="input-append bootstrap-datepicker" id="<?php echo $item['Task']['id'] . '-next_execution_time-active';?>" style="display:none">
				<?php
					echo $this->Form->input($item['Task']['id'] . '.next_execution_time', array(
							'type' => 'text',
							'class' => 'datepicker',
							'default' => h(date("Y-m-d", $item['Task']['next_execution_time'])),
							'id' => 'datepicker' . $item['Task']['id']
					));
				?>
			</div>
			<div id="<?php echo $item['Task']['id'];?>-next_execution_time-passive" role="button" tabindex="0" aria-label="<?php echo h(date("Y-m-d", $item['Task']['next_execution_time'])); ?>" onClick="activate1(<?php echo $item['Task']['id'];?>, 'next_execution_time')">
				<?php echo h(date("Y-m-d", $item['Task']['next_execution_time'])); ?>
			</div>
		</td>
		<td><?php echo h($item['Task']['description']);?>&nbsp;</td>
		<td><?php echo h($item['Task']['message']); ?></td>
	</tr><?php
endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Form->button('Update all', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
	echo $this->Paginator->counter(array(
	'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
	));
	?>
	</p>
	<div class="pagination">
		<ul>
		<?php
			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		</ul>
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'tasks'));
?>
<script type="text/javascript">
	function activate1(id, type){
		$("#"+id+"-"+type+"-active").show();
		$("#"+id+"-"+type+"-passive").hide();
	}

	function activate2(id, type, defaultValue){
		$("#"+id+"-"+type+"-active").show();
		$("#"+id+"-"+type+"-passive").hide();
		$('#timepicker'+id).timepicker({defaultTime: defaultValue, minuteStep: 1, showMeridian: false});
	}
</script>
