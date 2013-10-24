<div class="logs index">
	<h2>Logs</h2>
	<?php
	if ($isSearch == 1) {
		echo "<h4>Results for all log entries";
		if ($emailSearch != null) {
			echo " for user \"<b>" . h($emailSearch) . "\"</b>";
			$emailSearchReplacePairs = $this->Highlight->build_replace_pairs(h($emailSearch));
		}
		if ($orgSearch != null) {
			echo " of the organisation \"<b>" . h($orgSearch) . "</b>\"";
			$orgSearchReplacePairs = $this->Highlight->build_replace_pairs(h($orgSearch));
		}
		if ($actionSearch != "ALL") {
			echo " of type \"<b>" . h($actionSearch) . "</b>\"";
			$actionSearchReplacePairs = $this->Highlight->build_replace_pairs(h($actionSearch));
		}
		if ($titleSearch != null) {
			echo " with the title \"<b>" . h($titleSearch) . "</b>\"";
			$titleSearchReplacePairs = $this->Highlight->build_replace_pairs(h($titleSearch));
		}
		if ($changeSearch != null) {
			echo " including the change \"<b>" . h($changeSearch) . "</b>\"";
			$changeSearchReplacePairs = $this->Highlight->build_replace_pairs(h($changeSearch));
		}
		echo ":</h4>";
	}
	?>
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
			<th><?php echo $this->Paginator->sort('email');?></th>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th><?php echo $this->Paginator->sort('created');?></th>
			<th><?php echo $this->Paginator->sort('action');?></th>
			<th><?php echo $this->Paginator->sort('title');?></th>
			<th><?php echo $this->Paginator->sort('change');?></th>
		</tr>
		<?php foreach ($list as $item): ?>
		<tr>
			<td class="short"><?php echo h($item['Log']['id']); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($emailSearch) && $emailSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['email']), $emailSearchReplacePairs));
				else echo (h($item['Log']['email'])); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($orgSearch) && $orgSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['org']), $orgSearchReplacePairs));
				else echo (h($item['Log']['org'])); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Log']['created']); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($actionSearch) && $actionSearch != "ALL") echo nl2br($this->Highlight->highlighter(h($item['Log']['action']), $actionSearchReplacePairs));
				else echo (h($item['Log']['action'])); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($titleSearch) && $titleSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['title']), $titleSearchReplacePairs));
				else echo nl2br(h($item['Log']['title'])); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($changeSearch) && $changeSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['change']), $changeSearchReplacePairs));
				else echo nl2br(h($item['Log']['change']));
			?>&nbsp;</td>
		</tr>
		<?php endforeach; ?>
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
<?php
	if ($isSearch == 1){
		$class = 'search';
	} else {
		$class = 'index';
	}
	echo $this->element('side_menu', array('menuList' => 'logs', 'menuItem' => $class));
?>