<div class="attributes index">
	<h2>Attributes</h2>
		<?php
if ($isSearch == 1) {
	echo "<h4>Results for all attributes";
	if ($keywordSearch != null) echo " with the value containing \"<b>" . h($keywordSearch) . "</b>\"";
	if ($keywordSearch2 != null) echo " from the events \"<b>" . h($keywordSearch2) . "</b>\"";
	if ($categorySearch != "ALL") echo " of category \"<b>" . h($categorySearch) . "</b>\"";
	if ($typeSearch != "ALL") echo " of type \"<b>" . h($typeSearch) . "</b>\"";
	if (isset($orgSearch) && $orgSearch != '' && $orgSearch != null) echo " created by the organisation \"<b>" . h($orgSearch) . "</b>\"";
	echo ":</h4>";
} ?>
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
			<th><?php echo $this->Paginator->sort('event_id');?></th>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th<?php echo ' title="' . $attrDescriptions['signature']['desc'] . '"';?>>
			<?php echo $this->Paginator->sort('IDS');?></th>
			<th class="actions">Actions</th>
	</tr>
	<?php
	$currentCount = 0;
	if ($isSearch == 1) {

		// sanitize data
		if (isset($keywordArray)) {
			foreach ($keywordArray as &$keywordArrayElement) {
				$keywordArrayElement = h($keywordArrayElement);
			}
		// build the $replacePairs variable used to highlight the keywords
		$replacePairs = $this->Highlight->build_replace_pairs($keywordArray);
		}
	}

foreach ($attributes as $attribute):
	?>
	<tr>
		<td class="short">
			<div onclick="document.location='/events/view/<?php echo $attribute['Event']['id'];?>';">
			<?php
				if ($attribute['Event']['orgc'] == $me['org']) {
					$class='class="SameOrgLink"';
				} else {
					$class='';
				}
				$currentCount++;
			?>
				<a href="/events/view/<?php echo $attribute['Event']['id'];?>" <?php echo $class;?>><?php echo $attribute['Event']['id'];?></a>
			</div>
		</td>
		<td title="<?php echo $categoryDefinitions[$attribute['Attribute']['category']]['desc'];?>" class="short" onclick="document.location='/events/view/<?php echo $attribute['Event']['id'];?>';">
		<?php echo $attribute['Attribute']['category']; ?>&nbsp;</td>
		<td title="<?php echo $typeDefinitions[$attribute['Attribute']['type']]['desc'];?>" class="short" onclick="document.location='/events/view/<?php echo $attribute['Event']['id'];?>';">
		<?php echo $attribute['Attribute']['type']; ?>&nbsp;</td>
		<td class="showspaces" onclick="document.location='/events/view/<?php echo $attribute['Event']['id'];?>';"><?php
			$sigDisplay = nl2br(h($attribute['Attribute']['value']));
			if ($isSearch == 1 && !empty($replacePairs)) {
				// highlight the keywords if there are any
				$sigDisplay = $this->Highlight->highlighter($sigDisplay, $replacePairs);
			}
			if ('attachment' == $attribute['Attribute']['type'] || 'malware-sample' == $attribute['Attribute']['type']) {
				?><a href="/attributes/download/<?php echo $attribute['Attribute']['id'];?>"><?php echo $sigDisplay; ?></a><?php
			} elseif ('link' == $attribute['Attribute']['type']) {
				?><a href="<?php echo nl2br(h($attribute['Attribute']['value']));?>"><?php echo $sigDisplay; ?></a><?php
			} else {
				echo $sigDisplay;
			}
			?></td>
		<td class="short" onclick="document.location ='document.location ='/events/view/<?php echo $attribute['Event']['id'];?>';">
			<?php echo $attribute['Attribute']['to_ids'] ? 'Yes' : 'No'; ?>&nbsp;
		</td>
		<td class="short action-links"><?php
	if ($isAdmin || ($isAclModify && $attribute['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $attribute['Event']['org'] == $me['org'])) {
				?><a href="/attributes/edit/<?php echo $attribute['Attribute']['id'];?>" class="icon-edit" title="Edit"></a><?php
		echo $this->Form->postLink('',array('action' => 'delete', $attribute['Attribute']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this attribute?'));
	}
	?>
			<a href="/events/view/<?php echo $attribute['Attribute']['event_id'];?>" class="icon-list-alt" title="View"></a>
		</td>
	</tr>
	<?php
endforeach;
	?>
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
<div class="actions">
	<ul class="nav nav-list">
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<?php
		if ($isSearch == 1){
			$searchClass = 'class="active"';
			$listClass = '';
		} else {
			$searchClass = '';
			$listClass = 'class="active"';
		}
		?>
		<li <?php echo $listClass;?>><a href="/attributes/index">List Attributes</a></li>
		<li <?php echo $searchClass;?>><a href="/attributes/search">Search Attributes</a></li>
		<?php if ($isSearch == 1): ?>
		<li class="divider"></li>
		<li><a href="/events/downloadSearchResult">Download results as XML</a></li>
		<li><a href="/events/csv/download/search">Download results as CSV</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><a href="/events/export">Export</a></li>
		<?php if ($isAclAuth): ?>
		<li><a href="/events/automation">Automation</a></li>
		<?php endif;?>
	</ul>
</div>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
	$("td, div").tooltip({
		'placement': 'top',
		'container' : 'body',
		delay: { show: 500, hide: 100 }
		});

});
</script>