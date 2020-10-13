<div class="eventBlocklists index">
    <h2><?php echo __('Event Blocklists');?></h2>
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
    <div>
    <?php
        $data = array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'class' => 'hidden mass-select',
                            'fa-icon' => 'trash',
                            'onClick' => "multiSelectDeleteEventBlocklist",
                            'onClickParams' => array('1', '0')
                        )
                    )
                ),
                array(
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                )
            )
        );
        echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data));
    ?>
    </div>
    <table class="table table-striped table-hover table-condensed">
    <tr>
            <th>
                <input class="select_all select" type="checkbox" title="<?php echo __('Select all');?>" role="button" tabindex="0" aria-label="<?php echo __('Select all events on current page');?>" onClick="toggleAllCheckboxes();" />&nbsp;
            </th>
            <th><?php echo $this->Paginator->sort('id');?></th>
            <th><?php echo $this->Paginator->sort('org');?></th>
            <th><?php echo $this->Paginator->sort('event_uuid', __('Event UUID'));?></th>
            <th><?php echo $this->Paginator->sort('created');?></th>
            <th><?php echo $this->Paginator->sort('event_info');?></th>
            <th><?php echo $this->Paginator->sort('comment');?></th>
            <th class="actions"><?php echo __('Actions');?></th>
    </tr><?php
foreach ($response as $item): ?>
    <tr>
        <td style="width:10px;">
            <input class="select" type="checkbox" data-id="<?php echo h($item['EventBlocklist']['id']); ?>" aria-label="select <?php echo h($item['EventBlocklist']['id'])?>" />
        </td>
        <td class="short"><?php echo h($item['EventBlocklist']['id']); ?>&nbsp;</td>
        <td class="short"><?php echo (isset($item['EventBlocklist']['event_orgc']) ? h($item['EventBlocklist']['event_orgc']) : '&nbsp;'); ?></td>
        <td class="short"><?php echo h($item['EventBlocklist']['event_uuid']); ?>&nbsp;</td>
        <td><?php echo h($item['EventBlocklist']['created']); ?>&nbsp;</td>
        <td class="short"><?php echo (isset($item['EventBlocklist']['event_info']) ? h($item['EventBlocklist']['event_info']) : '&nbsp;'); ?></td>
        <td class="short"><?php echo (isset($item['EventBlocklist']['comment']) ? h($item['EventBlocklist']['comment']) : '&nbsp;'); ?></td>
        <td class="short action-links">
            <a href="<?= $baseurl;?>/eventBlocklists/edit/<?= h($item['EventBlocklist']['id']); ?>" class="fa fa-edit" title="<?= __('Edit')?>" role="button" tabindex="0" aria-label="Edit blocklist entry">&nbsp</a>
            <?php echo $this->Form->postLink('', array('action' => 'delete', h($item['EventBlocklist']['id'])), array('class' => 'fa fa-trash', 'title' => __('Delete'), 'aria-label' => __('Delete')), __('Are you sure you want to delete the blocklist entry for the event UUID %s?', h($item['EventBlocklist']['event_uuid']))); ?>
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
<script type="text/javascript">
    $(document).ready(function(){
        popoverStartup();
        $('.select').on('change', function() {
            listCheckboxesChecked();
        });
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
<?php
    if ($isSiteAdmin) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'eventBlocklists'));
    } else {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'eventBlocklists'));
    }
