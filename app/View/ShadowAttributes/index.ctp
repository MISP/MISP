<div class="shadowAttributes index">
    <h2><?php echo __('Proposals');?></h2>
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
    <?php
        $data = array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'text' => __('My Org\'s Events'),
                            'active' => !$all,
                            'url' => '/shadow_attributes/index'
                        ),
                        array(
                            'text' => __('All Events'),
                            'active' => $all,
                            'url' => '/shadow_attributes/index/all:1'
                        )
                    )
                )
            )
        );
        echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data));
    ?>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th><?php echo __('Event');?></th>
            <th>
                <?php echo $this->Paginator->sort('org', __('Proposal by'));?>
            </th>
            <th>
                <?php echo __('Type');?>
            </th>
            <th>
                <?php echo $this->Paginator->sort('Event.Orgc.name', __('Event creator'));?>
            </th>
            <th>
                <?php echo $this->Paginator->sort('id', __('Event Info'));?>
            </th>
            <th>
                <?php echo $this->Paginator->sort('value', __('Proposed value'));?>
            </th>
            <th>
                <?php echo $this->Paginator->sort('category', __('Category'));?>
            </th>
            <th>
                <?php echo $this->Paginator->sort('type', __('Type'));?>
            </th>
            <th>
                <?php echo $this->Paginator->sort('timestamp', __('Created'), array('direction' => 'desc'));?>
            </th>
        </tr>
        <?php foreach ($shadowAttributes as $event):?>
        <tr>
            <td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo h($event['Event']['id']);?>
            </td>
            <td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php
                    echo $this->OrgImg->getOrgImg(array('name' => $event['Org']['name'], 'id' => $event['Org']['id'], 'size' => 24));
                ?>
                &nbsp;
            </td>
            <td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php
                    if ($event['ShadowAttribute']['old_id'] != 0) {
                        echo __('Attribute edit');
                    } else {
                        echo __('New Attribute');
                    }
                ?>
            </td>
            <td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo h($event['Event']['Orgc']['name']); ?>
            </td>
            <td onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo h($event['Event']['info']); ?>
            </td>
            <td onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo h($event['ShadowAttribute']['value']);?>
            </td>
            <td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo h($event['ShadowAttribute']['category']);?>
            </td>
            <td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo h($event['ShadowAttribute']['type']);?>
            </td>
            <td class="short" onclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo date('Y-m-d H:i:s', $event['ShadowAttribute']['timestamp']);?>
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'viewProposals'));
?>
