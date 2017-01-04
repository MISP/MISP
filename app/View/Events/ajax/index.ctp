<div class="events">
	<div id="eventIndexTable">
		<h2>Events</h2>
		<div class="pagination">
			<ul>
			<?php
				$this->Paginator->options(array(
					'update' => '#eventIndexTable',
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
</div>
<?php echo $this->Js->writeBuffer(); ?>