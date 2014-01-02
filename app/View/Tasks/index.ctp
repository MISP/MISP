<div class="task index">
	<h2>Scheduled Tasks</h2>
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
		'action' => 'setTask',
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
			<th><?php echo $this->Paginator->sort('job_id', 'Job ID');?></th>
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
			<div id="<?php echo $item['Task']['id'];?>-timer-passive" onClick="activate1(<?php echo $item['Task']['id'];?>, 'timer')">
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
			<div id="<?php echo $item['Task']['id'];?>-scheduled_time-passive" onClick="activate2(<?php echo $item['Task']['id'];?>, 'scheduled_time', '<?php echo h($item['Task']['scheduled_time']);?>')">
				<?php echo h($item['Task']['scheduled_time']); ?>
			</div>
		</td>
		<td class="short">
			<?php 
				echo h(date("d/m/Y", $item['Task']['next_execution_time']));
			?>
		&nbsp;</td>
		<td><?php echo h($item['Task']['description']);?>&nbsp;</td>
		<td class="short"><?php echo $item['Task']['job_id']; ?></td>
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
	echo $this->element('side_menu', array('menuList' => 'task', 'menuItem' => 'index'));
?>
<script type="text/javascript">
	function activate1(id, type){
		$("#"+id+"-"+type+"-active").show();
		$("#"+id+"-"+type+"-passive").hide();
	} 

	function activate2(id, type, defaultValue){
		$("#"+id+"-"+type+"-active").show();
		$("#"+id+"-"+type+"-passive").hide();
		$('#timepicker'+id).timepicker({defaultTime: defaultValue});
	} 
</script>