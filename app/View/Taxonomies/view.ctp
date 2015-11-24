<div class="taxonomy view">
<h2><?php echo h(strtoupper($taxonomy['namespace']));?> Taxonomy Library</h2>
	<dl>
		<dt>Id</dt>
		<dd>
			<?php echo h($taxonomy['id']); ?>
			&nbsp;
		</dd>
		<dt>Namespace</dt>
		<dd>
			<?php echo h($taxonomy['namespace']); ?>
			&nbsp;
		</dd>
		<dt>Description</dt>
		<dd>
			<?php echo h($taxonomy['description']); ?>
			&nbsp;
		</dd>
		<dt>Version</dt>
		<dd>
			<?php echo h($taxonomy['version']); ?>
			&nbsp;
		</dd>
		<dt>Enabled</dt>
		<dd>
			<?php echo $taxonomy['enabled'] ? '<span class="green">Yes</span>&nbsp;&nbsp;' : '<span class="red">No</span>&nbsp;&nbsp;'; 
				if ($isSiteAdmin) {
					if ($taxonomy['enabled']) {
						echo $this->Form->postLink('(disable)', array('action' => 'disable', h($taxonomy['id'])), array('title' => 'Disable'), ('Are you sure you want to disable this taxonomy library?'));
					} else {
						echo $this->Form->postLink('(enable)', array('action' => 'enable', h($taxonomy['id'])), array('title' => 'Enable'), ('Are you sure you want to enable this taxonomy library?'));
					}
				}
			?>
			
			&nbsp;
		</dd>
	</dl>
	<div class="pagination">
        <ul>
        <?php
        $this->Paginator->options(array(
			'url' => array($id),
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
				<th><?php echo $this->Paginator->sort('tag');?></th>
				<th><?php echo $this->Paginator->sort('expanded');?></th>
				<th><?php echo $this->Paginator->sort('events');?></th>
				<th><?php echo $this->Paginator->sort('tag');?></th>
		</tr><?php
		foreach ($entries as $k => $item): ?>
		<tr>
			<td class="short"><?php echo h($item['tag']); ?>&nbsp;</td>
			<td><?php echo h($item['expanded']); ?>&nbsp;</td>
			<td class="short">
			<?php 
				if ($item['existing_tag']) {
			?>
				<a href='<?php echo $baseurl."/events/index/searchtag:". h($item['existing_tag']['Tag']['id']);?>'><?php echo count($item['existing_tag']['EventTag']);?></a>
			<?php 
				} else {
					echo 'N/A';
				} 
			?>
			</td>
			<td class="short">
			<?php 
				if ($item['existing_tag']):
					$url = $baseurl . '/events/index/searchtag:' .  h($item['existing_tag']['Tag']['id']);
					if ($isAclTagger) $url = $baseurl . '/tags/edit/' .  h($item['existing_tag']['Tag']['id']);
			?>
					<a href="<?php echo $url;?>" class="<?php echo $isAclTagger ? 'tagFirstHalf' : 'tag' ?>" style="background-color:<?php echo h($item['existing_tag']['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($item['existing_tag']['Tag']['colour']);?>"><?php echo h($item['existing_tag']['Tag']['name']); ?></a>
			<?php 
				else:
					if ($isAclTagger && $taxonomy['enabled']) {
						echo $this->Form->create('Tag', array('id' => 'quick_' . h($k), 'url' => '/tags/quickAdd/', 'style' => 'margin:0px;'));
						echo $this->Form->input('name', array('type' => 'hidden', 'value' => $item['tag']));
					?>
						<span class="icon-plus useCursorPointer" onClick="submitQuickTag('<?php echo 'quick_' . h($k); ?>');"></span>
					<?php 
						echo $this->Form->end();
					} else { 
						echo 'N/A';
					}
				endif;
			?>
			</td>
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
	echo $this->element('side_menu', array('menuList' => 'taxonomies', 'menuItem' => 'view'));
?>

