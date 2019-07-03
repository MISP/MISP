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
            <th><?php echo $this->Paginator->sort('icon', __('Icon'));?></th>
            <th><?php echo $this->Paginator->sort('name');?></th>
            <th><?php echo $this->Paginator->sort('version');?></th>
            <th><?php echo $this->Paginator->sort('namespace', __('Namespace'));?></th>
            <th class="description"><?php echo $this->Paginator->sort('description');?></th>
            <th><?php echo __('Actions');?></th>
    </tr>
    <?php
        foreach ($list as $item) {
            $row = sprintf(
                '<tr><td class="short">%s</td>',
                h($item['Galaxy']['id'])
            );
            $row .= sprintf(
                '<td class="short"><span class="%s fa-%s"></span></td>',
                $this->FontAwesome->findNamespace($item['Galaxy']['icon']),
                h($item['Galaxy']['icon'])
            );
            $row .= sprintf(
                '<td class="short">%s</td>',
                h($item['Galaxy']['name'])
            );
            $row .= sprintf(
                '<td class="short">%s</td>',
                h($item['Galaxy']['version'])
            );
            $row .= sprintf(
                '<td class="short">%s</td>',
                h($item['Galaxy']['namespace'])
            );
            $row .= sprintf(
                '<td>%s</td>',
                h($item['Galaxy']['description'])
            );
            $row .= sprintf(
                '<td class="short action-links">%s%s</td></tr>',
                $this->Form->postLink('', array('action' => 'delete', $item['Galaxy']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), sprintf(__('Are you sure you want to delete the Galaxy (%s)?'), $item['Galaxy']['name'])),
                $this->Html->link('', array('action' => 'view', $item['Galaxy']['id']), array('class' => 'fa fa-eye', 'title' => __('View'), 'aria-label' => __('View')))
            );
            echo $row;
        }
    ?>
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'index'));
?>
