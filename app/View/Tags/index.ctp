<div class="tags index">
	<h2>Tags</h2>
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
			<th><?php echo $this->Paginator->sort('name');?></th>
			<?php if ($isAclTagger): ?>
			<th class="actions"><?php echo __('Actions');?></th>
			<?php endif; ?>
	</tr><?php
foreach ($list as $item): ?>
	<tr>
		<td class="short"><?php echo h($item['Tag']['id']); ?>&nbsp;</td>
		<td><a href="/events/index/searchtag:<?php echo $item['Tag']['id']; ?>" class="tag" style="background-color: <?php echo h($item['Tag']['colour']); ?>;color:<?php echo $this->TextColour->getTextColour($item['Tag']['colour']); ?>"><?php echo h($item['Tag']['name']); ?></a></td>
		<?php if ($isAclTagger): ?>
		<td class="short action-links">
			<?php echo $this->Html->link('', array('action' => 'edit', $item['Tag']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));?>
			<?php echo $this->Form->postLink('', array('action' => 'delete', $item['Tag']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete "%s"?', $item['Tag']['name']));?>	
		</td>
		<?php endif; ?>
	</tr><?php
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
	echo $this->element('side_menu', array('menuList' => 'tags', 'menuItem' => 'index'));
?>