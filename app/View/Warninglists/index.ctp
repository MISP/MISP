<div class="taxonomies index">
	<h2>Warninglists</h2>
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
			<th><?php echo $this->Paginator->sort('version');?></th>
			<th><?php echo $this->Paginator->sort('description');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th>Valid attributes</th>
			<th><?php echo $this->Paginator->sort('warninglist_entry_count', 'Entries');?></th>
			<th><?php echo $this->Paginator->sort('enabled');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($warninglists as $k => $item): ?>
	<tr>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['id']); ?>&nbsp;</td>
		<td ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['name']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['version']); ?>&nbsp;</td>
		<td ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['description']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['type']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['valid_attributes']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['warninglist_entry_count']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'">
		<div id="#checkbox_div_<?php echo h($item['Warninglist']['id']);?>">
			<?php 
				echo $this->Form->create('Warninglist', array('id' => 'enable_form_' . $item['Warninglist']['id'], 'url' => '/warninglists/toggleEnable/' . $item['Warninglist']['id']));
				echo $this->Form->input('enable', array('id' => 'enable_checkbox_' . $item['Warninglist']['id'], 'checked' => $item['Warninglist']['enabled'], 'label' => false, 'onclick' => 'toggleSetting(event, "warninglist_enable", "' . $item['Warninglist']['id'] . '")'));
				echo $this->Form->end();
			?>
		</div>
		</td>
		<td class="short action-links">
			<?php 
				if ($isSiteAdmin) {

				}
			?>
			<a href='<?php echo $baseurl."/warninglists/view/". h($item['Warninglist']['id']);?>' class = "icon-list-alt" title = "View"></a>
		</td>
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
	echo $this->element('side_menu', array('menuList' => 'taxonomies', 'menuItem' => 'index'));
?>