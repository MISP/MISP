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
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('worker');?></th>
			<th><?php echo $this->Paginator->sort('job_type');?></th>
			<th><?php echo $this->Paginator->sort('job_input');?></th>
			<th><?php echo $this->Paginator->sort('status');?></th>
			<th><?php echo $this->Paginator->sort('retries');?></th>
			<th><?php echo $this->Paginator->sort('progress');?></th>
	</tr><?php
foreach ($list as $item): ?>
	<tr>
		<td class="short"><?php echo h($item['Job']['id']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['worker']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['job_type']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['job_input']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['status']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Job']['retries']); ?>&nbsp;</td>
		<td class="short">
			<div class="progress progress-striped active">
			  <div id="bar<?php echo h($item['Job']['id']); ?>" class="bar" style="width: <?php echo h($item['Job']['progress']); ?>%;">
			 	 <?php 
			 	 	if ($item['Job']['progress'] > 0 && $item['Job']['progress'] < 100) echo h($item['Job']['progress']) . '%'; 
			 	 	if ($item['Job']['progress'] == 100) echo 'Completed.';
			 	 ?>
			  </div>
			</div>
				<script type="text/javascript">
				setInterval(function(){
					$.getJSON('/jobs/getGenerateCorrelationProgress/<?php echo h($item['Job']['id']); ?>', function(data) {
						var x = document.getElementById("bar<?php echo h($item['Job']['id']); ?>"); 
						x.style.width = data+"%";
						if (data > 0 && data < 100) {
							x.innerHTML = data + "%";
						}
						if (data == 100) {
							x.innerHTML = "Completed.";
						}
					});
					}, 1000);

				</script>
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
	 	<script type="text/javascript">
			//function startProgressBar($element) {
				//setInterval(function(){getProgress($("#bar<?php echo h($item['Job']['id']); ?>"));}, 1000);
			//});


			function startProgressBar() {
				alert(1);
			//	var test = getAttributeCount();
			//	document.getElementById("progressBarContainer").style.display="block";
			//	setInterval(function(){getProgress(test);}, 500);
			}

			//function getProgress($target) {
			//	$.getJSON('/jobs/getGenerateCorrelationProgress/1', function(data) {
			//		progress(data.count), $target);
			//});
		 	
			//function progress(percent, $element) {
			//	    var progressBarWidth = percent * $element.width() / 100;
			//	    $element.find('div').animate({ width: progressBarWidth }, 500).html(percent + "%&nbsp;");
			//}
			
		</script>
		
