<div class="events">
	<div id="eventIndexTable">
		<h2><?php echo __('Events');?></h2>
		<div>
		<ul class="pagination">
			<?php
			$this->Paginator->options(array(
				'update' => '.span12',
				'evalScripts' => true,
				'before' => '$(".progress").show()',
				'complete' => '$(".progress").hide()',
			));

			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false, 'class' => 'page-link'), null, array('tag' => 'li', 'class' => 'page-link', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'class' => 'page-link', 'currentClass' => 'page-link', 'currentTag' => 'span', 'currentClass' => 'p-active'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false, 'class' => 'page-link'), null, array('tag' => 'li', 'class' => 'page-link', 'escape' => false, 'disabledTag' => 'span', 'disabledClass' => 'page-link'));
			?>
		</ul>
	</div>
		<?php
			$tab = "Center";
			if (!isset($simple)) $simple = false;
			$filtered = false;
			if (!$simple && count($passedArgsArray) > 0) {
				$tab = "Left";
				$filtered = true;
			}
			echo $this->element('Events/eventIndexTable');
		?>
		<p>
		<?php
		echo $this->Paginator->counter(array(
		'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
		));
		?>
		</p>
		<div>
		<ul class="pagination">
			<?php
			$this->Paginator->options(array(
				'update' => '.span12',
				'evalScripts' => true,
				'before' => '$(".progress").show()',
				'complete' => '$(".progress").hide()',
			));

			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false, 'class' => 'page-link'), null, array('tag' => 'li', 'class' => 'page-link', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'class' => 'page-link', 'currentClass' => 'page-link', 'currentTag' => 'span', 'currentClass' => 'p-active'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false, 'class' => 'page-link'), null, array('tag' => 'li', 'class' => 'page-link', 'escape' => false, 'disabledTag' => 'span', 'disabledClass' => 'page-link'));
			?>
		</ul>
	</div>
	</div>
</div>
<?php echo $this->Js->writeBuffer(); ?>
