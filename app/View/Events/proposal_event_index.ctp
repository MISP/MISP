<div class="events index">
    <h2><?php echo __('Event with proposals');?></h2>
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
            <th class="filter">
                <?php echo $this->Paginator->sort('published');?>
            </th>
            <th><?php echo $this->Paginator->sort('id', 'Id', array('direction' => 'desc'));?></th>
            <th><?php echo $this->Paginator->sort('attribute_count', __('Proposals'));?></th>
            <th><?php echo __('Contributors');?></th>
            <?php if ($isSiteAdmin): ?>
            <th><?php echo $this->Paginator->sort('user_id', __('Email'));?></th>
            <?php endif; ?>
            <th class="filter">
                <?php echo $this->Paginator->sort('date', 'Date', array('direction' => 'desc'));?>
            </th>
            <th class="filter">
                <?php echo $this->Paginator->sort('info');?>
            </th>
            <th title="<?php echo $eventDescriptions['distribution']['desc'];?>">
                <?php echo $this->Paginator->sort('distribution');?>
            </th>
        </tr>
        <?php foreach ($events as $event):?>
        <tr <?php if ($event['Event']['distribution'] == 0) echo 'class = "privateRed"'?>>
            <td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php
                if ($event['Event']['published'] == 1) {
                ?>
                    <a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>" class = "icon-ok" title = "<?php echo __('View');?>"></a>
                <?php
                } else {
                ?>
                    <a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>" class = "icon-remove" title = "<?php echo __('View');?>"></a>
                <?php
                }?>&nbsp;
            </td>
            <td class="short">
                <a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>"><?php echo $event['Event']['id'];?></a>
            </td>
            <td class="short" onclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" style="color:red;font-weight:bold;">
                <?php echo count($event['ShadowAttribute']); ?>&nbsp;
            </td>
            <td class="short">
                <?php
                    foreach ($event['orgArray'] as $k => $org) {
                        echo $this->OrgImg->getOrgImg(array('name' => $orgs[$org], 'id' => $org, 'size' => 24));
                        if ((1 + $k) < (count($event['orgArray']))) echo '<br />';
                    }
                ?>
                &nbsp;
            </td>
            <?php if ('true' == $isSiteAdmin): ?>
            <td class="short" onclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo h($event['User']['email']); ?>&nbsp;
            </td>
            <?php endif; ?>
            <td class="short" onclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo $event['Event']['date']; ?>&nbsp;
            </td>
            <td onclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;
            </td>
            <td class="short <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>" onclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : 'All';?>
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
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'viewProposalIndex'));
