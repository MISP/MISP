<div class="events <?php if (!$ajax) echo 'index'; ?>">
    <?php $serverName = $server['Server']['name'] ? '"' . $server['Server']['name'] . '" (' . $server['Server']['url'] . ')' : '"' . $server['Server']['url'] . '"'; ?>
    <h4 class="visibleDL notPublished" ><?php echo __('You are currently viewing the event index of the remote instance %s', h($serverName));?></h4>
    <div class="pagination">
        <ul>
        <?php
            $eventViewURL = $baseurl . '/servers/previewEvent/' . h($id) . '/';
            $this->Paginator->options(array(
                'url' => $id,
                'update' => '.span12',
                'evalScripts' => true,
                'before' => '$(".progress").show()',
                'complete' => '$(".progress").hide()',
            ));
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
    <?php
        $filterParamsString = array();
        foreach ($passedArgsArray as $k => $v) {
                $filterParamsString[] = sprintf(
                    '%s: %s',
                    h(ucfirst($k)),
                    h($v)
                );
        }
        $filterParamsString = implode(' & ', $filterParamsString);
        $data = array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'id' => 'create-button',
                            'title' => __('Modify filters'),
                            'fa-icon' => 'search',
                            'onClick' => 'getPopup',
                            'onClickParams' => array($urlparams, 'servers', 'filterEventIndex/' . h($server['Server']['id']))
                        )
                    )
                ),
                array(
                    'children' => array(
                        array(
                            'requirement' => count($passedArgsArray) > 0,
                            'html' => sprintf(
                                '<span class="bold">%s</span>: %s',
                                __('Filters'),
                                $filterParamsString
                            )
                        ),
                        array(
                            'requirement' => count($passedArgsArray) > 0,
                            'url' => $baseurl . '/servers/previewIndex/' . h($server['Server']['id']),
                            'title' => __('Remove filters'),
                            'fa-icon' => 'times'
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
        if (!$ajax) {
            echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data));
        }
    ?>
    <table class="table table-striped table-hover table-condensed">
        <tr>
            <th class="filter">
                <?php echo $this->Paginator->sort('published');?>
            </th>
            <?php
                if (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg')):
            ?>
                <th class="filter"><?php echo $this->Paginator->sort('Org', 'Source org'); ?></th>
                <th class="filter"><?php echo $this->Paginator->sort('Org', 'Member org'); ?></th>
            <?php
                else:
            ?>
                <th class="filter"><?php echo $this->Paginator->sort('Org'); ?></th>
                <th class="filter"><?php echo $this->Paginator->sort('owner org');?></th>
            <?php
                endif;
            ?>
            <th><?php echo $this->Paginator->sort('id', null, array('direction' => 'desc'));?></th>
            <?php if (Configure::read('MISP.tagging')): ?>
                <th class="filter"><?php echo __('Tags');?></th>
            <?php endif; ?>
            <th><?php echo $this->Paginator->sort('attribute_count', '#Attr.');?></th>
            <th class="filter"><?php echo $this->Paginator->sort('date', null, array('direction' => 'desc'));?></th>
            <th class="filter" title="<?php echo $eventDescriptions['threat_level_id']['desc'];?>"><?php echo $this->Paginator->sort('threat_level_id');?></th>
            <th title="<?php echo $eventDescriptions['analysis']['desc'];?>">
                <?php echo $this->Paginator->sort('analysis');?>
            </th>
            <th class="filter"><?php echo $this->Paginator->sort('info');?></th>
            <th title="<?php echo $eventDescriptions['distribution']['desc'];?>">
                <?php echo $this->Paginator->sort('distribution');?>
            </th>
            <th class="actions"><?php echo __('Actions');?></th>

        </tr>
        <?php if (!empty($events)) foreach ($events as $event): ?>
        <tr <?php if ($event['Event']['distribution'] == 0) echo 'class = "privateRed"'?>>
            <td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <span class="icon-<?php echo ($event['Event']['published'] == 1) ? 'ok' : 'remove'; ?>" title="<?php echo __('Published');?>" aria-label="<?php echo __('Event ') . ($event['Event']['published'] == 1) ? '' : __('not ') . __('published'); ?>"></span>
            </td>
            <td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <?php
                    echo h($event['Event']['Orgc']['name']);
                ?>
                &nbsp;
            </td>
            <td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <?php
                    echo h($event['Event']['Org']['name']);
                ?>
                &nbsp;
            </td>
            <td style="width:30px;" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <a href='<?php echo $eventViewURL . h($event['Event']['id']);?>'><?php echo $event['Event']['id'];?></a>
            </td>
            <?php if (Configure::read('MISP.tagging')): ?>
            <td style = "max-width: 200px;width:10px;">
                <?php foreach ($event['Event']['EventTag'] as $tag):
                    if (empty($tag['Tag'])) continue;
                    $tagText = "";
                    if (Configure::read('MISP.full_tags_on_event_index') == 1) $tagText = $tag['Tag']['name'];
                    else if (Configure::read('MISP.full_tags_on_event_index') == 2) {
                        if (strpos($tag['Tag']['name'], '=')) {
                            $tagText = explode('=', $tag['Tag']['name']);
                            $tagText = h(trim(end($tagText), "\""));
                        }
                        else $tagText = $tag['Tag']['name'];
                    }
                ?>
                    <span class=tag style="margin-bottom:3px;background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>;" title="<?php echo h($tag['Tag']['name']); ?>"><?php echo h($tagText); ?>&nbsp;</span>
                <?php endforeach; ?>
            </td>
            <?php endif; ?>
            <td style="width:30px;" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <?php echo $event['Event']['attribute_count']; ?>&nbsp;
            </td>
            <td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <?php echo $event['Event']['date']; ?>&nbsp;
            </td>
            <td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <?php
                    echo h($threatLevels[$event['Event']['threat_level_id']]);
                ?>&nbsp;
            </td>
            <td class="short" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <?php echo $analysisLevels[$event['Event']['analysis']]; ?>&nbsp;
            </td>
            <td ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'">
                <?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;
            </td>
            <td class="short <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>" ondblclick="document.location.href ='<?php echo $eventViewURL . h($event['Event']['id']);?>'" title = "<?php echo $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : 'All';?>">
                <?php if ($event['Event']['distribution'] == 4):?>
                    <?php echo h($event['Event']['SharingGroup']['name']);?>
                <?php else:
                    echo h($shortDist[$event['Event']['distribution']]);
                endif;
                ?>
            </td>
            <td class="short action-links">
                <?php if ($event['Event']['published']) echo $this->Form->postLink('', $baseurl . '/servers/pull/' . $server['Server']['id'] . '/' . $event['Event']['id'], array('class' => 'fa fa-arrow-circle-down', 'title' => __('Fetch the event')), __('Are you sure you want to fetch and save this event on your instance?', $this->Form->value('Server.id'))); ?>
                <a href='<?php echo $eventViewURL . h($event['Event']['id']);?>' class = "fa fa-eye" title = "<?php echo __('View');?>"></a>
            </td>
        </tr>
        <?php endforeach; ?>
    </table>
    <p>
    <?php
    echo $this->Paginator->counter(array(
    'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}'),
    'model' => 'Server',
    ));
    ?>
    </p>
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'red', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
</div>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(document).ready(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter('<?php echo '/' . h($server['Server']['id']);?>');
        });
    });
</script>
<?php
    if (!$ajax) echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'previewIndex', 'id' => $id));
