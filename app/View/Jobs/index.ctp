<div class="jobs index">
	<h2><?php echo __('Jobs');?></h2>
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
    <script type="text/javascript">
		var intervalArray = new Array();

		function queueInterval(k, id) {
			intervalArray[k] = setInterval(function(){
				$.getJSON('/jobs/getGenerateCorrelationProgress/' + id, function(data) {
					var x = document.getElementById("bar" + id); 
					x.style.width = data+"%";
					if (data > 0 && data < 100) {
						x.innerHTML = data + "%";
					}
					if (data == 100) {
						x.innerHTML = "Completed.";
						clearInterval(intervalArray[k]);
					}
				});
				}, 3000);
		}
	</script>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('process_id');?></th>
			<th><?php echo $this->Paginator->sort('worker');?></th>
			<th><?php echo $this->Paginator->sort('job_type');?></th>
			<th><?php echo $this->Paginator->sort('job_input', 'Input');?></th>
			<th><?php echo $this->Paginator->sort('message');?></th>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th><?php echo $this->Paginator->sort('status');?></th>
			<th><?php echo $this->Paginator->sort('retries');?></th>
			<th><?php echo $this->Paginator->sort('progress');?></th>
	</tr><?php
foreach ($list as $k => $item): ?>
	<tr>
		<td class="short"><?php echo h($item['Job']['id']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['process_id']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['worker']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['job_type']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['job_input']); ?>&nbsp;</td>
		<td><?php echo h($item['Job']['message']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['org']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['status']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['retries']); ?>&nbsp;</td>
		<td style="width:200px;">
			<div class="progress progress-striped active" style="margin-bottom: 0px;">
			  <div id="bar<?php echo h($item['Job']['id']); ?>" class="bar" style="width: <?php echo h($item['Job']['progress']); ?>%;">
			 	 <?php 
			 	 	if ($item['Job']['progress'] > 0 && $item['Job']['progress'] < 100) echo h($item['Job']['progress']) . '%'; 
			 	 	if ($item['Job']['progress'] == 100) echo 'Completed.';
			 	 ?>
			  </div>
			</div>
				<?php if ($item['Job']['progress'] != 100): ?>
					<script type="text/javascript">
						queueInterval("<?php echo $k; ?>", "<?php echo h($item['Job']['id']); ?>");
					</script>
				<?php endif; ?>
		</td>
	</tr><?php
endforeach; ?>
	</table>
	<p>
    <?php
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
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">

	</ul>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'jobs'));
?>
				
