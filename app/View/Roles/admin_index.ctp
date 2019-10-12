<div class="roles index">
    <h2><?php echo __('Roles');?></h2>
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
            <th><?php echo __('Default');?></th>
            <th><?php echo $this->Paginator->sort('name');?></th>
            <th><?php echo $this->Paginator->sort('restricted_to_site_admin', __('Restricted to site admins'));?></th>
            <th><?php echo $this->Paginator->sort('permission', __('Permissions'));?></th>
            <?php
                foreach ($permFlags as $k => $flags):
            ?>
                <th title="<?php echo h($flags['title']); ?>"><?php echo $this->Paginator->sort($k, $flags['text']);?></th>
            <?php
                endforeach;
            ?>
            <th><?php echo $this->Paginator->sort('memory_limit', __('Memory limit'));?></th>
            <th><?php echo $this->Paginator->sort('max_execution_time', __('Max execution time'));?></th>
            <th><?php echo $this->Paginator->sort('rate_limit_count', __('Searches / 15 mins'));?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr><?php
foreach ($list as $item): ?>
    <tr>
        <td><?php echo $this->Html->link(h($item['Role']['id']), array('admin' => true, 'action' => 'edit', $item['Role']['id'])); ?>&nbsp;</td>
        <td class="short" style="text-align:center;width:20px;"><input class="servers_default_role_checkbox" type="checkbox" aria-label="<?php echo __('Default role'); ?>" data-id="<?php echo h($item['Role']['id']); ?>" <?php if ($default_role_id && $default_role_id == $item['Role']['id']) echo 'checked'; ?>></td>
        <td><?php echo h($item['Role']['name']); ?>&nbsp;</td>
        <td class="short"><span class="<?php if ($item['Role']['restricted_to_site_admin']) echo 'icon-ok'; ?>" role="img" aria-label="<?php echo $item['Role']['restricted_to_site_admin'] ? __('Yes') : __('No'); ?>"></span>&nbsp;</td>
        <td><?php echo h($options[$item['Role']['permission']]); ?>&nbsp;</td>
        <?php
            foreach ($permFlags as $k => $flags) {
                $flagName = Inflector::Humanize(substr($k, 5));
                echo sprintf(
                    '<td class="short"><span class="%s" role="img" aria-label="%s" title="%s"></span>&nbsp;</td>',
                    ($item['Role'][$k]) ? 'icon-ok' : '',
                    ($item['Role'][$k]) ? __('Yes') : __('No'),
                    sprintf(
                        __('%s permission %s'),
                        h($flagName),
                        $item['Role'][$k] ? 'granted' : 'denied'
                    )

                );
            }
        ?>
        <td class="short">
            <?php
                if (empty($item['Role']['memory_limit'])) {
                    echo h($default_memory_limit);
                } else {
                    echo h($item['Role']['memory_limit']);
                }
            ?>
        </td>
        <td class="short">
            <?php
                if (empty($item['Role']['max_execution_time'])) {
                    echo h($default_max_execution_time);
                } else {
                    echo h($item['Role']['max_execution_time']);
                }
            ?>
        </td>
        <td class="short">
            <?php
                if (empty($item['Role']['rate_limit_count']) || empty($item['Role']['enforce_rate_limit'])) {
                    echo 'N/A';
                } else {
                    echo h(intval($item['Role']['rate_limit_count']));
                }
            ?>
        </td>
        <td class="short action-links">
            <?php echo $this->Html->link('', array('admin' => true, 'action' => 'edit', $item['Role']['id']), array('class' => 'fa fa-edit', 'title' => __('Edit'), 'aria-label' => __('Edit'))); ?>
            <?php echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $item['Role']['id']), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), __('Are you sure you want to delete %s?', $item['Role']['name'])); ?>
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'indexRole'));
