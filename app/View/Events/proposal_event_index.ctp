<div class="events index">
    <h2><?= __('Event with proposals');?></h2>
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
            <th class="filter">
                <?php echo $this->Paginator->sort('published');?>
            </th>
            <th><?php echo $this->Paginator->sort('id', 'ID', array('direction' => 'desc'));?></th>
            <th><?php echo $this->Paginator->sort('attribute_count', __('Proposals'));?></th>
            <th><?php echo __('Contributors');?></th>
            <?php if ($isSiteAdmin): ?>
            <th><?php echo $this->Paginator->sort('user_id', __('Email'));?></th>
            <?php endif; ?>
            <th class="filter">
                <?php echo $this->Paginator->sort('date', __('Date'), array('direction' => 'desc'));?>
            </th>
            <th class="filter">
                <?php echo $this->Paginator->sort('info');?>
            </th>
            <th title="<?php echo $eventDescriptions['distribution']['desc'];?>">
                <?php echo $this->Paginator->sort('distribution');?>
            </th>
        </tr>
        <?php foreach ($events as $event): ?>
        <tr<?php if ($event['Event']['distribution'] == 0) echo ' class="privateRed"'?>>
            <td class="short dblclickElement">
                <a href="<?= $baseurl."/events/view/".$event['Event']['id'] ?>" title="<?= __('View') ?>" aria-label="<?= __('View') ?>"><i class="<?= $event['Event']['published'] ? 'black fa fa-check' : 'black fa fa-times' ?>"></i></a>
            </td>
            <td class="short">
                <a href="<?= $baseurl."/events/view/".$event['Event']['id'] ?>" class="dblclickActionElement"><?= $event['Event']['id'] ?></a>
            </td>
            <td class="short">
                <a href="<?= $baseurl."/events/view/".$event['Event']['id'] . '/proposal:1' ?>" style="color:red;font-weight:bold;"><?= $event['Event']['proposal_count']; ?></a>
            </td>
            <td class="short">
                <?php
                    foreach ($event['orgArray'] as $k => $org) {
                        echo $this->OrgImg->getOrgImg(array('name' => $orgs[$org], 'id' => $org, 'size' => 24));
                        if ((1 + $k) < (count($event['orgArray']))) echo '<br>';
                    }
                ?>
            </td>
            <?php if ($isSiteAdmin): ?>
            <td class="short dblclickElement">
                <?php echo h($event['User']['email']); ?>
            </td>
            <?php endif; ?>
            <td class="short dblclickElement">
                <?php echo $event['Event']['date']; ?>
            </td>
            <td class="dblclickElement">
                <?php echo nl2br(h($event['Event']['info'])); ?>
            </td>
            <td class="short dblclickElement <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>">
                <?= $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : __('All');?>
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
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'viewProposalIndex'));
