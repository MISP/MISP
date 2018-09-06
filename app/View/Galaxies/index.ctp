<div class="regexp index">
    <h2><?php echo __('Galaxies');?></h2>
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
            <th><?php echo $this->Paginator->sort('icon');?></th>
            <th><?php echo $this->Paginator->sort('name');?></th>
            <th><?php echo $this->Paginator->sort('version');?></th>
            <th><?php echo $this->Paginator->sort('namespace');?></th>
            <th><?php echo $this->Paginator->sort('description');?></th>
            <th class="actions"><?php echo $this->Paginator->sort('description');?></th>
    </tr><?php
foreach ($list as $item):?>
    <tr>
        <td class="short"><?php echo h($item['Galaxy']['id']);?>&nbsp;</td>
        <td class="short"><span class="fa fa-<?php echo h($item['Galaxy']['icon']); ?>"></span></td>
        <td><?php echo h($item['Galaxy']['name']);?>&nbsp;</td>
        <td class="short"><?php echo h($item['Galaxy']['version']);?>&nbsp;</td>
        <td class="short"><?php echo h($item['Galaxy']['namespace']);?>&nbsp;</td>
        <td><?php echo h($item['Galaxy']['description']);?>&nbsp;</td>
        <td class="short action-links">
            <?php echo $this->Html->link('', array('action' => 'view', $item['Galaxy']['id']), array('class' => 'icon-list-alt', 'title' => 'View'));?>
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
    echo $this->element('side_menu', array('menuList' => 'galaxies', 'menuItem' => 'index'));
?>
