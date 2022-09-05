<div class="regexp index">
    <h2><?php echo __('Import Regexp');?></h2>
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
            <th><?php echo $this->Paginator->sort('regexp', __('Regexp'));?></th>
            <th><?php echo $this->Paginator->sort('replacement', __('Replacement'));?></th>
            <th><?php echo $this->Paginator->sort('type');?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr><?php
foreach ($list as $item):?>
    <tr>
        <td class="short"><?php echo h($item['Regexp']['id']);?>&nbsp;</td>
        <td><?php echo h($item['Regexp']['regexp']);?>&nbsp;</td>
        <td><?php echo h($item['Regexp']['replacement']);?>&nbsp;</td>
        <td class="short"><?php echo h($item['Regexp']['type']);?>&nbsp;</td>
        <td class="short action-links">
            <?php echo $this->Html->link('', array('admin' => true, 'action' => 'edit', $item['Regexp']['id']), array('class' => 'fa fa-edit', 'title' => __('Edit'), 'aria-label' => __('Edit')));?>
            <?php echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $item['Regexp']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), __('Are you sure you want to delete %s?', h($item['Regexp']['regexp'])));?>
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'regexp', 'menuItem' => 'index'));
?>
