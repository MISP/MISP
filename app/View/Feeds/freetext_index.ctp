<div class="attributes index">
	<h2>Parsed attributes from feed <?php echo h($feed['Feed']['name']);?></h2>
	<?php
		echo $this->Form->create('Feed', array('url' => array('controller' => 'feeds', 'action' => 'fetchSelectedFromFreetextIndex', $feed['Feed']['id'])));
		echo $this->Form->input('data', array('style' => 'display:none;', 'label' => false, 'div' => false));
	?>
		<span id="FetchSelected" class="btn btn-inverse">Fetch selected</span>
	<?php
		echo $this->Form->end();
	?>
	<div class="pagination">
				<ul>
				<?php
					$url = array_merge(array('controller' => 'feeds', 'action' => 'previewIndex', $feed['Feed']['id']), $this->request->named);
					$this->Paginator->options(array(
							'url' => $url,
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
		<th><input class="select_all" type="checkbox" onClick="toggleAllAttributeCheckboxes();" /></th>
		<th>Category</th>
		<th>Type</th>
		<th>Value</th>
		<th>IDS</th>
		<th>Correlations</th>
		<th>Distribution</th>
	</tr>
	<?php
		foreach ($attributes as $key => $attribute):
	?>
	<tr>
		<td style="width:10px;">
			<input class="select_attribute" type="checkbox" data-rowid="<?php echo h($key); ?>" />
		</td>
		<td class="short" id="<?php echo h($key);?>_category"><?php echo h($attribute['category']);?></td>
		<td class="short" id="<?php echo h($key);?>_type"><?php echo h($attribute['default_type']);?></td>
		<td id="<?php echo h($key);?>_value"><?php echo h($attribute['value']);?></td>
		<td class="short" id="<?php echo h($key);?>_to_ids" data-value="<?php echo h($attribute['to_ids']); ?>"><span class="icon-<?php echo $attribute['to_ids'] ? 'ok' : 'remove';?>"></span></td>
		<td class="shortish">
			<?php
				if (isset($attribute['correlations'])):
					foreach ($attribute['correlations'] as $correlation):
			?>
						<a href="<?php echo $baseurl; ?>/events/view/<?php echo h($correlation); ?>" data-toggle="popover" data-content="<?php echo h($correlatingEventInfos[$correlation]);?>" data-trigger="hover"><?php echo h($correlation); ?></a>
			<?php
					endforeach;
				endif;
			?>&nbsp;
		</td>
		<td class="short">
			<?php
				if ($feed['Feed']['distribution'] == 4):
			?>
					<a href="<?php echo $baseurl; ?>/sharing_groups/view/<?php echo h($feed['Feed']['sharing_group_id']); ?>"><?php echo h($feed['SharingGroup']['name']); ?></a>
			<?php
				else:
					echo h($distributionLevels[$feed['Feed']['distribution']]);
				endif;
			?>
		</td>
	</tr>
	<?php
		endforeach;
	?>
	</table>
	<div class="pagination">
			<ul>
			<?php
				$this->Paginator->options(array(
						'url' => $url,
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
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'feeds', 'menuItem' => 'add'));
?>

<script type="text/javascript">

var data = [];
$(document).ready(function() {
	popoverStartup();
});

$('#FetchSelected').click(freetextFeedFetchSelected);

function freetextFeedFetchSelected() {
	var payload = [];
	var checkedIds = [];
	$('.select_attribute').each(function () {
		if (this.checked) {
			var row_id = $(this).data('rowid');
			payload.push({
				'category': $('#' + row_id + '_category').html(),
				'type': $('#' + row_id + '_type').html(),
				'value': $('#' + row_id + '_value').html(),
				'to_ids': $('#' + row_id + '_to_ids').data('value'),
			});
		}
	});
	$('#FeedData').val(JSON.stringify(payload));
	$("#FeedFetchSelectedFromFreetextIndexForm").submit();
}
</script>
