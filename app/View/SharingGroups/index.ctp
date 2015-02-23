<div class="sharing_groups index">
<h2>Sharing Groups</h2>
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
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th><?php echo $this->Paginator->sort('Creator');?></th>
			<th>Description</th>
			<th>Members</th>
			<th><?php echo $this->Paginator->sort('pushable');?></th>
			<th><?php echo $this->Paginator->sort('extendable');?></th>
			<th><?php echo $this->Paginator->sort('active');?></th>
			<th class="actions">Actions</th>
	</tr>
	<?php
foreach ($sharingGroups as $k => $sharingGroup): 
?>
	<tr>
		<td class="short"><?php echo h($sharingGroup['SharingGroup']['name']); ?></td>
		<td class="short"><a href="/SharingGroup/view/<?php echo h($sharingGroup['Organisation']['id']);?>"><?php echo h($sharingGroup['Organisation']['name']); ?></a></td>
		<td><?php echo h($sharingGroup['SharingGroup']['description']); ?></td>
		<?php 
			$combined = "";
			if ($sharingGroup['SharingGroup']['distribution'] < 2) {
				$combined .= "<a href='/Organisation/view/" . $sharingGroup['Organisation']['id'] . "'>" . h($sharingGroup['Organisation']['name']) . "</a><br />";
			} else {
				if ($sharingGroup['SharingGroup']['distribution'] > 1) {
					$combined .= "<a href='/users/memberslist/'>All members of this instance</a><br />";
					if ($sharingGroup['SharingGroup']['distribution'] > 2) {
						$combined .= "All members of connected instances<br />";
						if ($sharingGroup['SharingGroup']['distribution'] > 3) {
							$combined .= "Everyone else<br />";
						}
					}
				}
			}
			if (count($sharingGroup['SharingGroupElement']) > 0) {
				foreach ($sharingGroup['SharingGroupElement'] as $k2 => $sge) {
					$combined .= "<a href='/Organisation/view/" . $sge['Organisation']['id'] . "'>" . h($sge['Organisation']['name']) . "</a><br />";
				}
			}
		?>
		<td class="short">
			<span <?php if (!$sharingGroup['SharingGroup']['distribution']) echo 'style="color:red;"'?> data-toggle="popover" title="Distribution List" data-content="<?php echo $combined; ?>">
				<?php echo $distributionLevels[$sharingGroup['SharingGroup']['distribution']]; ?>
			</span>
		</td>
		
		<td class="short"><?php echo $sharingGroup['SharingGroup']['pushable'] ? 'Yes' : 'No'; ?></td>
		<td class="short"><?php echo $sharingGroup['SharingGroup']['extendable'] ? 'Yes' : 'No'; ?></td>
		<td class="short"><?php echo $sharingGroup['SharingGroup']['active'] ? 'Yes' : 'No'; ?></td>
		<td class="action">
		<?php if ($isSiteAdmin || $sharingGroup['access'] == 3): ?>
			<?php echo $this->Html->link('', '/SharingGroups/edit/' . $sharingGroup['SharingGroup']['id'], array('class' => 'icon-edit', 'title' => 'Edit')); ?>
			<?php echo $this->Form->postLink('', '/SharingGroups/delete/' . $sharingGroup['SharingGroup']['id'], array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete %s?', h($sharingGroup['SharingGroup']['name']))); ?>
		<?php endif; ?>
		</td>
		
	</tr>
	<?php
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
<script type="text/javascript"> 
	$(document).ready(function(){
		popoverStartup();
	});
</script>
<?php 
	if ($isSiteAdmin) echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'indexOrg'));
	else echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'indexOrg'));
?>
