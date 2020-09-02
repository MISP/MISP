<div class="orgBlocklists index">
    <h2><?php echo __('Organisation Blocklists');?></h2>
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
            <th><?php echo $this->Paginator->sort('org_name', __('Organisation name'));?></th>
            <th><?php echo $this->Paginator->sort('org_uuid', __('UUID'));?></th>
            <th><?php echo $this->Paginator->sort('created');?></th>
            <th><?php echo $this->Paginator->sort('comment');?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr><?php
foreach ($response as $item): ?>
    <tr>
        <td class="short"><?php echo h($item['OrgBlocklist']['id']); ?>&nbsp;</td>
        <td class="short"><?php echo (isset($item['OrgBlocklist']['org_name']) ? h($item['OrgBlocklist']['org_name']) : '&nbsp;'); ?></td>
        <td class="short"><?php echo h($item['OrgBlocklist']['org_uuid']); ?>&nbsp;</td>
        <td><?php echo h($item['OrgBlocklist']['created']); ?>&nbsp;</td>
        <td class="short"><?php echo (isset($item['OrgBlocklist']['comment']) ? h($item['OrgBlocklist']['comment']) : '&nbsp;'); ?></td>
        <td class="short action-links">
            <a href="<?php echo $baseurl;?>/orgBlocklists/edit/<?php echo h($item['OrgBlocklist']['id']); ?>" aria-label="<?php echo __('Edit');?>"><span class="fa fa-edit" title="<?php echo __('Edit');?>">&nbsp;</span></a>
            <?php echo $this->Form->postLink('', array('action' => 'delete', h($item['OrgBlocklist']['id'])), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), __('Are you sure you want to delete the blocklist entry for the organisation UUID %s?', h($item['OrgBlocklist']['org_uuid']))); ?>
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'orgBlocklists'));
