<?php if(empty($this->passedArgs['key'])) $this->passedArgs['key'] = '';?>
<div class="organisations index">
    <h2><?php echo __('Filters');?></h2>
        <?php echo $this->Form->create(); ?>
    <div class="input-append">
        <?php
        echo $this->Form->input('key', array('value' => $this->passedArgs['key'], 'div' => false, 'class' => 'input-xxlarge', 'label' => false));
        echo $this->Form->button('Go', array('class' => 'btn', 'div' => false));
        ?>
    </div>
    <?php echo $this->Form->end(); ?>

    <h2><?php echo __('Organisations'); ?></h2>
    <table cellpadding="0" cellspacing="0" class="table table-striped table-condensed">
    <tr>
            <th><?php echo $this->Paginator->sort('id'); ?></th>
            <th><?php echo $this->Paginator->sort('name'); ?></th>

            <th class="actions"><?php echo __('Actions'); ?></th>
    </tr>
    <?php foreach ($organisations as $organisation): ?>
    <tr>
        <td><?php echo h($organisation['Organisation']['id']); ?>&nbsp;</td>
        <td><?php echo h($organisation['Organisation']['name']); ?>&nbsp;</td>
        <td class="actions">
            <?php echo $this->Html->link(__('Edit'), array('action' => 'edit', $organisation['Organisation']['id'], 'admin' => true), array('class' => 'btn')); ?>
            <?php echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $organisation['Organisation']['id'], 'admin' => true), array('class' => 'btn'), __('Are you sure you want to delete # %s?', $organisation['Organisation']['id'])); ?>
        </td>
    </tr>
<?php endforeach; ?>
    </table>
    <p>
    <?php
    echo $this->Paginator->counter(array(
    'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
    ));
    ?>  </p>
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

<div class="actions">
    <h3><?php echo __('Actions'); ?></h3>
    <ul>
        <li><?php echo $this->Html->link(__('New Organisation'), array('action' => 'add', 'admin' => true)); ?></li>
    </ul>
</div>
