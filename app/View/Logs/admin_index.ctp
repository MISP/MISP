<div class="logs index">
	<h2>Logs</h2>
	<?php
	if ($isSearch == 1) {
		echo "<h4>Results for all log entries";
		$replaceArray = array(
				'email' => array('text' => 'for user', 'default' => null),
				'org' => array('text' => 'of organisation', 'default' => null),
				'model' => array('text' => 'for model', 'default' => ''),
				'model_id' => array('text' => 'for model ID', 'default' => ''),
				'action' => array('text' => 'of type', 'default' => 'ALL'),
				'title' => array('text' => 'with the title', 'default' => null),
				'change' => array('text' => 'including the change', 'default' => null),
				'ip' => array('text' => 'from IP', 'default' => null)
		);

		foreach ($replaceArray as $type => $replace) {
			if (isset(${$type . 'Search'}) && ${$type . 'Search'} != $replace['default']) {
				echo ' ' . $replace['text'] . ' "<b>' . h(${$type . 'Search'}) . '</b>"';
				${$type . 'SearchReplacePairs'} = $this->Highlight->build_replace_pairs(h(${$type . 'Search'}));
			}
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
	<?php if (!isset($filter)) $filter = false; ?>
	<div class="tabMenuFixedContainer" style="display:inline-block;margin-left:50px;">
		<?php foreach ($validFilters as $filterName => $filterData): ?>
		<span class="tabMenuFixed tabMenuSides useCursorPointer <?php echo $filterName == $filter ? 'background-lightblue' : ''; ?>">
			<span id="myOrgButton" title="Modify filters" role="button" tabindex="0" aria-label="Modify filters" onClick="window.location.href='<?php echo $baseurl; ?>/admin/logs/index/filter:<?php echo h($filterName); ?>';"><?php echo h($filterData['name']);?></span>
		</span>
		<?php endforeach; ?>
	</div>
	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<?php if (Configure::read('MISP.log_client_ip')) echo '<th>' . $this->Paginator->sort('ip', 'IP') . '</th>';?>
			<th><?php echo $this->Paginator->sort('email');?></th>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th><?php echo $this->Paginator->sort('created');?></th>
			<th><?php echo $this->Paginator->sort('model');?></th>
			<th><?php echo $this->Paginator->sort('model_id', 'Model ID');?></th>
			<th><?php echo $this->Paginator->sort('action');?></th>
			<th><?php echo $this->Paginator->sort('title');?></th>
			<th><?php echo $this->Paginator->sort('change');?></th>
		</tr>
		<?php foreach ($list as $item): ?>
		<tr>
			<td class="short"><?php echo h($item['Log']['id']); ?>&nbsp;</td>
			<?php
				if (Configure::read('MISP.log_client_ip')) {
					echo '<td>';
					if (isset($ipSearch) && $ipSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['ip']), $ipSearchReplacePairs));
					else echo h($item['Log']['ip']);
					echo '</td>';
				}
			?>
			<td class="short"><?php
				if (isset($emailSearch) && $emailSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['email']), $emailSearchReplacePairs));
				else echo (h($item['Log']['email'])); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($orgSearch) && $orgSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['org']), $orgSearchReplacePairs));
				else echo (h($item['Log']['org'])); ?>&nbsp;</td>
			<td class="short"><?php echo h($item['Log']['created']); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($modelSearch) && $modelSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['model']), $modelSearchReplacePairs));
				else echo (h($item['Log']['model'])); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($model_idSearch) && $model_idSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['model_id']), $model_idSearchReplacePairs));
				else echo (h($item['Log']['model_id'])); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($actionSearch) && $actionSearch != "ALL") echo nl2br($this->Highlight->highlighter(h($item['Log']['action']), $actionSearchReplacePairs));
				else echo (h($item['Log']['action'])); ?>&nbsp;</td>
			<td class="short"><?php
				if (isset($titleSearch) && $titleSearch != null) echo nl2br($this->Highlight->highlighter(h($item['Log']['title']), $titleSearchReplacePairs));
				else echo nl2br(h($item['Log']['title'])); ?>&nbsp;</td>
			<td><?php
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
