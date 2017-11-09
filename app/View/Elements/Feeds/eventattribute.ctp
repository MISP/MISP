<?php
	$all = false;
	if (isset($this->params->params['paging']['Event']['page'])) {
		if ($this->params->params['paging']['Event']['page'] == 0) $all = true;
		$page = $this->params->params['paging']['Event']['page'];
	} else {
		$page = 0;
	}
	$fieldCount = 8;
?>
	<div class="pagination">
		<ul>
			<?php
				$this->Paginator->options(array(
						'url' => array($feed['Feed']['id'], $event['Event']['uuid']),
						'evalScripts' => true,
						'before' => '$(".progress").show()',
						'complete' => '$(".progress").hide()',
				));
					echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
					echo $this->Paginator->numbers(array('modulus' => 60, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
					echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
			?>
			<li class="all <?php if ($all) echo 'disabled'; ?>">
				<?php
					if ($all):
				?>
					<span class="red">view all</span>
				<?php
					else:
						echo $this->Paginator->link(__('view all'), 'all');
					endif;
				?>
			</li>
		</ul>
	</div>
<br />
<div id="attributeList" class="attributeListContainer">
	<table class="table table-striped table-condensed">
		<tr>
			<th><?php echo $this->Paginator->sort('timestamp', 'Date');?></th>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th>Tags</th>
			<th><?php echo $this->Paginator->sort('comment');?></th>
			<th>Related Events</th>
			<th>Feed hits</th>
			<th title="<?php echo $attrDescriptions['signature']['desc'];?>"><?php echo $this->Paginator->sort('to_ids', 'IDS');?></th>
		</tr>
		<?php
			$elements = array(
				0 => 'attribute',
				3 => 'object'
			);
			$focusedRow = false;
			foreach ($event['objects'] as $k => $object):
				$insertBlank = false;
				echo $this->element('/Feeds/View/row_' . $object['objectType'], array(
					'object' => $object,
					'k' => $k,
					'page' => $page,
					'fieldCount' => $fieldCount
				));
				if (!empty($focus) && ($object['objectType'] == 'object' || $object['objectType'] == 'attribute') && $object['uuid'] == $focus) {
					$focusedRow = $k;
				}
				if ($object['objectType'] == 'object'):
		?>
					<tr class="blank_table_row"><td colspan="<?php echo $fieldCount; ?>"></td></tr>
		<?php
				endif;
			endforeach;
		?>
	</table>
</div>
	<div class="pagination">
		<ul>
		<?php
			$this->Paginator->options(array(
					'url' => array($feed['Feed']['id'], $event['Event']['uuid']),
					'evalScripts' => true,
					'before' => '$(".progress").show()',
					'complete' => '$(".progress").hide()',
			));
			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 60, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
		?>
		<li class="all <?php if ($all) echo 'disabled'; ?>">
			<?php
				if ($all):
			?>
				<span class="red">view all</span>
			<?php
				else:
					echo $this->Paginator->link(__('view all'), 'all');
				endif;
			?>
		</li>
		</ul>
	</div>
<script type="text/javascript">
	var currentUri = "<?php echo isset($currentUri) ? h($currentUri) : '/feeds/previewEvent/' . h($feed['Feed']['id']) . '/' . h($event['Event']['uuid']); ?>";
	var lastSelected = false;
	var deleted = <?php echo (isset($deleted) && $deleted) ? 'true' : 'false';?>;
	$(document).ready(function() {
		<?php
			if ($focusedRow !== false):
		?>
				$('.row_' + '<?php echo h($focusedRow); ?>').focus();
		<?php
			endif;
		?>
		$('.screenshot').click(function() {
			screenshotPopup($(this).attr('src'), $(this).attr('title'));
		});
	});
	$('.hex-value-convert').click(function() {
		var val = $(this).parent().children(':first-child').text();
		if ($(this).parent().children(':first-child').attr('data-original-title') == 'Hexadecimal representation') {
			var bin = [];
			var temp;
			val.split('').forEach(function(entry) {
				temp = parseInt(entry, 16).toString(2);
				bin.push(Array(5 - (temp.length)).join('0') + temp);
			});
			bin = bin.join(' ');
			$(this).parent().children(':first-child').text(bin);
			$(this).parent().children(':first-child').attr('data-original-title', 'Binary representation');
			$(this).parent().children(':nth-child(2)').attr('data-original-title', 'Switch to hexadecimal representation');
			$(this).parent().children(':nth-child(2)').attr('aria-label', 'Switch to hexadecimal representation');
		} else {
			val = val.split(' ');
			hex = '';
			val.forEach(function(entry) {
				hex += parseInt(entry , 2).toString(16).toUpperCase();
			});
			$(this).parent().children(':first-child').text(hex);
			$(this).parent().children(':first-child').attr('data-original-title', 'Hexadecimal representation');
			$(this).parent().children(':nth-child(2)').attr('data-original-title', 'Switch to binary representation');
			$(this).parent().children(':nth-child(2)').attr('aria-label', 'Switch to binary representation');
		}
	});
</script>
<?php
	echo $this->Js->writeBuffer();
?>
