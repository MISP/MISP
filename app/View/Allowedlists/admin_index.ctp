<div class="allowedlist index">
    <h2><?php echo __('Signature Allowedlist');?></h2>
    <p><?php echo __('Regex entries (in the standard php regex /{regex}/{modifier} format) entered below will restrict matching attributes from being included in the IDS flag sensitive exports (such as NIDS exports).');?></p>
    <div class="pagination">
        <ul>
        <?php
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
            <th class="actions"><?php echo __('Actions');?></th>
    </tr><?php
foreach ($list as $item):?>
    <tr>
        <td class="short"><?php echo h($item['Allowedlist']['id']);?>&nbsp;</td>
        <td><?php echo h($item['Allowedlist']['name']);?>&nbsp;</td>
        <td class="short action-links">
            <?php echo $this->Html->link('', array('admin' => true, 'action' => 'edit', $item['Allowedlist']['id']), array('class' => 'fa fa-edit', 'title' => __('Edit'), 'aria-label' => __('Edit')));?>
            <?php echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $item['Allowedlist']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), __('Are you sure you want to delete "%s"?', $item['Allowedlist']['name']));?>
        </td>
    </tr><?php
endforeach;?>
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'allowedlist', 'menuItem' => 'index'));
