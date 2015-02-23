<div class="organisations index">
<?php if ($local): ?>
	<h2>Organisations on this instance</h2>
<?php else: ?>
	<h2>Known external organisations</h2>
<?php endif;?>
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
			<th>Logo</th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th><?php echo $this->Paginator->sort('uuid');?></th>
			<th><?php echo $this->Paginator->sort('description');?></th>
			<th><?php echo $this->Paginator->sort('nationality');?></th>
			<th><?php echo $this->Paginator->sort('sector');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('contacts');?></th>
			<?php if ($isSiteAdmin): ?>
				<th>Added by</th>
			<th class="actions">Actions</th>
			<?php endif; ?>
	</tr>
	<?php
foreach ($orgs as $org): ?>
	<tr>
		<td class="short"><?php echo h($org['Organisation']['id']); ?></td>
		<td class="short">
			<?php
				$imgRelativePath = 'orgs' . DS . h($org['Organisation']['name']) . '.png';
				$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
				if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($org['Organisation']['name']) . '.png', array('alt' => h($org['Organisation']['name']), 'title' => h($org['Organisation']['name']), 'style' => 'width:24px; height:24px'));
				else echo $this->Html->tag('span', h($org['Organisation']['name']), array('class' => 'welcome', 'style' => 'float:left;'));
			?>
		</td>
		<td class="short"><?php echo h($org['Organisation']['name']); ?></td>
		<td class="short"><?php echo h($org['Organisation']['uuid']); ?></td>
		<td><?php echo h($org['Organisation']['description']); ?></td>
		<td class="short"><?php echo h($org['Organisation']['nationality']); ?></td>
		<td class="short"><?php echo h($org['Organisation']['sector']); ?></td>
		<td class="short"><?php echo h($org['Organisation']['type']); ?></td>
		<td><?php echo h($org['Organisation']['contacts']); ?></td>
		<?php if ($isSiteAdmin): ?>
			<td class="short"><?php echo h($org_creator_ids[$org['Organisation']['created_by']]); ?></td>
			<td class="short action-links">
				<a href='/admin/organisations/edit/<?php echo $org['Organisation']['id'];?>' class = "icon-edit" title = "Edit"></a>
				<?php
					echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $org['Organisation']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete %s?', $org['Organisation']['name']));
				?>
			</td>
		<?php endif; ?>
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
<?php 
	if ($isSiteAdmin) echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'indexOrg'));
	else echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'indexOrg'));
?>
