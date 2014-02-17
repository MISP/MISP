<div class="servers index">
	<h2>Servers</h2>
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
			<th><?php echo $this->Paginator->sort('push');?></th>
			<th><?php echo $this->Paginator->sort('pull');?></th>
			<th><?php echo $this->Paginator->sort('url');?></th>
			<th>From</th>
			<th><?php echo $this->Paginator->sort('cert_file');?></th>
			<th><?php echo $this->Paginator->sort('self_signed');?></th>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th>Last Pulled ID</th>
			<th>Last Pushed ID</th>
			<th class="actions">Actions</th>
	</tr>
	<?php
foreach ($servers as $server): ?>
	<tr>
		<td class="short" style="text-align: center;"><?php echo ($server['Server']['push'])? 'Yes' : 'No'; ?>&nbsp;</td>
		<td class="short" style="text-align: center;"><?php echo ($server['Server']['pull'])? 'Yes' : 'No'; ?>&nbsp;</td>
		<td><?php echo h($server['Server']['url']); ?>&nbsp;</td>
		<td><?php echo h($server['Server']['organization']); ?>&nbsp;</td>
		<td class="short"><?php echo h($server['Server']['cert_file']); ?>&nbsp;</td>
		<td class="short"><?php echo ($server['Server']['self_signed'] ? 'Yes' : 'No'); ?>&nbsp;</td>
		<td class="short"><?php echo h($server['Server']['org']); ?>&nbsp;</td>
		<td class="short"><?php echo $server['Server']['lastpulledid']; ?></td>
		<td class="short"><?php echo $server['Server']['lastpushedid']; ?></td>
		<td class="short action-links">
			<?php
			if ($server['Server']['pull'])
				echo $this->Html->link('', array('action' => 'pull', $server['Server']['id'], 'full'), array('class' => 'icon-download', 'title' => 'Pull all'));
			if ($server['Server']['push'])
				echo $this->Html->link('', array('action' => 'push', $server['Server']['id'], 'full'), array('class' => 'icon-upload', 'title' => 'Push all'));
			?>
			&nbsp;
			<?php
			$mayModify = ($isSiteAdmin || ($isAdmin && ($server['Server']['org'] == $me['org'])));
			if ($mayModify) echo $this->Html->link('', array('action' => 'edit', $server['Server']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));
			if ($mayModify) echo $this->Form->postLink('', array('action' => 'delete', $server['Server']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete # %s?', $server['Server']['id']));
			?>

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
<?php 
	echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'index'));
?>
