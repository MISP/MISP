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
	<br />
	<div id="attributeList" class="attributeListContainer">
		<div class="tabMenu tabMenuFiltersBlock noPrint" style="padding-right:0px !important;">
			<span id="filter_header" class="attribute_filter_header">Filters: </span>
			<div id="filter_all" title="Show all queues" role="button" tabindex="0" aria-label="Show all queues" class="attribute_filter_text<?php if (!$queue) echo '_active';?>" onClick="window.location='/jobs/index';">All</div>
			<div id="filter_default" title="Show default queue" role="button" tabindex="0" aria-label="Show default queue" class="attribute_filter_text<?php if ($queue === 'default') echo '_active';?>" onClick="window.location='/jobs/index/default';">Default</div>
			<div id="filter_email" title="Show email queue" role="button" tabindex="0" aria-label="Show email queue" class="attribute_filter_text<?php if ($queue === 'email') echo '_active';?>" onClick="window.location='/jobs/index/email';">Email</div>
			<div id="filter_cache" title="Show cache queue" role="button" tabindex="0" aria-label="Show cache queue" class="attribute_filter_text<?php if ($queue === 'cache') echo '_active';?>" onClick="window.location='/jobs/index/cache';">Cache</div>
		</div>
		<table class="table table-striped table-hover table-condensed">
		<tr>
				<th><?php echo $this->Paginator->sort('id');?></th>
				<th><?php echo $this->Paginator->sort('date_created');?></th>
				<th><?php echo $this->Paginator->sort('date_modified');?></th>
				<th><?php echo $this->Paginator->sort('process_id');?></th>
				<th><?php echo $this->Paginator->sort('worker');?></th>
				<th><?php echo $this->Paginator->sort('job_type');?></th>
				<th><?php echo $this->Paginator->sort('job_input', 'Input');?></th>
				<th><?php echo $this->Paginator->sort('message');?></th>
				<th><?php echo $this->Paginator->sort('Org.name');?></th>
				<th><?php echo $this->Paginator->sort('status');?></th>
				<th><?php echo $this->Paginator->sort('retries');?></th>
				<th><?php echo $this->Paginator->sort('progress');?></th>
		</tr>
<?php
	foreach ($list as $k => $item):
		$progress = '100';
		$startRefreshing = false;
		if ($item['Job']['failed'] || $item['Job']['status'] == 3) {
			$item['Job']['job_status'] = 'Failed';
			$progress_message = 'Failed';
			$progress_bar_type = 'progress progress-danger active';
		} else if (!$item['Job']['worker_status'] && $item['Job']['progress'] != 100) {
			$progress_message = 'No worker active';
			$progress_bar_type = 'progress progress-striped progress-warning active';
		} else if ($item['Job']['progress'] == 0) {
			$progress_bar_type = 'progress progress-striped progress-queued active';
			$progress_message = $item['Job']['job_status'] === 'Running' ? 'Running' : 'Queued';
		} else {
			$progress = h($item['Job']['progress']);
			if ($item['Job']['progress'] == 100) {
				$progress_bar_type = 'progress';
				$progress_message = 'Completed';
			} else {
				$progress_bar_type = 'progress progress-striped';
				$progress_message = $item['Job']['progress'] . '%';
				$startRefreshing = true;
			}
		}
?>
		<tr>
			<td class="short"><?php echo h($item['Job']['id']); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Job']['date_created']); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Job']['date_modified']); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Job']['process_id']); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Job']['worker']); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Job']['job_type']); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Job']['job_input']); ?>&nbsp;</td>
			<td><?php echo h($item['Job']['message']); ?>&nbsp;</td>
			<td class="short"><?php echo isset($item['Org']['name']) ? h($item['Org']['name']) : 'SYSTEM'; ?>&nbsp;</td>
			<td class="short">
			<?php
				echo h($item['Job']['job_status']);
				if ($item['Job']['failed']):
			?>
				<div class="icon-search useCursorPointer queryPopover" title="View stacktrace" role="button" tabindex="0" aria-label="Viw stacktrace" data-url="/jobs/getError" data-id="<?php echo h($item['Job']['process_id']); ?>"></div>
			<?php
				endif;
			?>
			</td>
			<td class="short"><?php echo h($item['Job']['retries']); ?>&nbsp;</td>
			<td style="width:200px;">
				<div class="<?php echo $progress_bar_type; ?>" style="margin-bottom: 0px;">
				  <div id="bar<?php echo h($item['Job']['id']); ?>" class="bar" style="width: <?php echo $progress; ?>%;">
					<?php
						echo h($progress_message);
					?>
				  </div>
				</div>
					<?php
						if ($startRefreshing):
					?>
							<script type="text/javascript">
								queueInterval("<?php echo $k; ?>", "<?php echo h($item['Job']['id']); ?>");
							</script>
					<?php
						endif;
					?>
			</td>
		</tr><?php
	endforeach; ?>
		</table>
	</div>
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
