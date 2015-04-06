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
			<th>Releasable to</th>
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
			$combined .= "Organisations:";
			if (count($sharingGroup['SharingGroupOrg']) == 0) $combined .= "<br />N/A";
			foreach ($sharingGroup['SharingGroupOrg'] as $k2 => $sge) {
				$combined .= "<br /><a href='/Organisation/view/" . $sge['Organisation']['id'] . "'>" . h($sge['Organisation']['name']) . "</a>";
				if ($sge['extend']) $combined .= (' (can extend)');
			}
			$combined .= "<hr style='margin:5px 0;'><br />Instances:";
			if (count($sharingGroup['SharingGroupServer']) == 0) $combined .= "<br />N/A";
			foreach ($sharingGroup['SharingGroupServer'] as $k3 => $sgs) {
				if ($sgs['server_id'] != 0) {
					$combined .= "<br /><a href='/Server/view/" . $sgs['Server']['id'] . "'>" . h($sgs['Server']['name']) . "</a>";
				} else {
					$combined .= "<br />This instance";
				}
				if ($sgs['all_orgs']) $combined .= (' (all organisations)');
				else $combined .= (' (as defined above)');
			}
		?>
		<td>
			<span data-toggle="popover" title="Distribution List" data-content="<?php echo $combined; ?>">
				<?php echo h($sharingGroup['SharingGroup']['releasability']); ?>
			</span>
		</td>
		<td class="short"><?php echo $sharingGroup['SharingGroup']['active'] ? 'Yes' : 'No'; ?></td>
		<td class="action">
		<?php if ($isSiteAdmin || $sharingGroup['editable']): ?>
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
