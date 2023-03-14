<div class="logs index">
<h2><?php echo __('Logs');?></h2>
<p><?= __('Showing log entries for data currently stored in the database. Entries about hard-deleted data have been omitted.') ?></p>
    <div class="pagination">
        <ul>
            <?php
            $this->LightPaginator->options(array('url' => $this->passedArgs));
            echo $this->LightPaginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->LightPaginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->LightPaginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            ?>
        </ul>
    </div>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th><?php echo $this->LightPaginator->sort('org');?></th>
            <th><?php echo $this->LightPaginator->sort('email');?></th>
            <th><?php echo $this->LightPaginator->sort('action');?></th>
            <th><?php echo $this->LightPaginator->sort('model');?></th>
            <th><?php echo $this->LightPaginator->sort('title');?></th>
            <th><?php echo $this->LightPaginator->sort('created');?></th>
        </tr>
        <?php foreach ($list as $item): ?>
        <tr>
            <td class="short">
            <?php
                echo $this->OrgImg->getOrgImg(array('name' => $item['Log']['org'], 'size' => 24));
            ?>
            &nbsp;
            </td>
            <td class="short"><?php echo h($item['Log']['email']); ?>&nbsp;</td>
            <td class="short"><?php echo h($item['Log']['action']); ?>&nbsp;</td>
            <td class="short"><?php
                if ($item['Log']['model'] !== 'ShadowAttribute') echo h($item['Log']['model']);
                else echo __('Proposal');
            ?>&nbsp;</td>
            <td><?php echo h($item['Log']['title']); ?>&nbsp;</td>
            <td class="short"><?php echo (h($item['Log']['created'])); ?>&nbsp;</td>
        </tr>
        <?php endforeach; ?>
    </table>
    <p>
    <?php
    echo $this->LightPaginator->counter(array(
    'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
    ));
    ?>
    </p>
    <div class="pagination">
        <ul>
        <?php
            echo $this->LightPaginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->LightPaginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->LightPaginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'eventLog'));