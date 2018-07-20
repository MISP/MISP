<div class="events <?php if (!$ajax) echo 'index'; ?>">
    <h2><?php echo __('Events');?></h2>
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
        $tab = "Center";
        if (!isset($simple)) $simple = false;
        $filtered = false;
        if (!$simple && count($passedArgsArray) > 0) {
            $tab = "Left";
            $filtered = true;
        }
        if (!$ajax && !$simple):
    ?>
    <div class="tabMenuFixedContainer" style="display:inline-block;">
        <span class="tabMenuFixed tabMenuFixed<?php echo $tab; ?> tabMenuSides">
            <span role="button" tabindex="0" aria-label="<?php echo __('Modify filters');?>" id="create-button" title="<?php echo __('Modify filters');?>" class="icon-search useCursorPointer" title="Filter events" role="button" tabindex="0" aria-label="<?php echo __('Filter events');?>" onClick="getPopup('<?php echo h($urlparams);?>', 'events', 'filterEventIndex');"></span>
            <span id="multi-delete-button" title="<?php echo __('Delete selected Events');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete selected Events');?>" class="hidden icon-trash mass-select useCursorPointer" onClick="multiSelectDeleteEvents();"></span>
        </span>
        <?php
            if ($filtered):
                foreach ($passedArgsArray as $k => $v):?>
                    <span class="tabMenuFixed tabMenuFixedElement">
                        <?php echo h(ucfirst($k)) . " : " . h($v); ?>
                    </span>
                <?php endforeach; ?>
            <span class="tabMenuFixed tabMenuFixedRight tabMenuSides">
                <?php echo $this->Html->link('', array('controller' => 'events', 'action' => 'index'), array('class' => 'icon-remove', 'title' => __('Remove filters')));?>
            </span>
            <?php endif;?>
            <span role="button" tabindex="0" aria-label="<?php echo __('Quickfilter');?>" title="<?php echo __('Quickfilter');?>" id="quickFilterButton" class="tabMenuFilterFieldButton useCursorPointer" onClick="quickFilter(<?php echo h($passedArgs); ?>, '<?php echo $baseurl . '/events/index'; ?>');"><?php echo __('Filter');?></span>
            <input class="tabMenuFilterField" type="text" id="quickFilterField"></input>
            <?php
                $tempArgs = json_decode($passedArgs, true);
                $tabBackground = "";
                if (isset($tempArgs['searchemail']) && $tempArgs['searchemail'] === $me['email']) {
                    unset($tempArgs['searchemail']);
                    $tabBackground = 'background-lightblue';
                } else {
                    $tempArgs['searchemail'] = $me['email'];
                }
                $tempArgs = json_encode($tempArgs);
            ?>
            <span class="tabMenuFixed tabMenuFixedLeft tabMenuSides useCursorPointer <?php echo $tabBackground; ?>" style="margin-left:50px;">
                <span role="button" tabindex="0" aria-label="<?php echo __('My events only');?>" title="<?php echo __('My events only');?>" id="myOrgButton" title="<?php echo __('Modify filters');?>" onClick="executeFilter(<?php echo h($tempArgs);?>, '<?php echo $baseurl;?>/events/index');"><?php echo __('My Events');?></span>
            </span>
            <?php
                $tempArgs = json_decode($passedArgs, true);
                $tabBackground = "";
                if (isset($tempArgs['searchorg']) && $tempArgs['searchorg'] === $me['Organisation']['id']) {
                    unset($tempArgs['searchorg']);
                    $tabBackground = 'background-lightblue';
                } else {
                    $tempArgs['searchorg'] = $me['Organisation']['id'];
                }
                $tempArgs = json_encode($tempArgs);
            ?>
            <span class="tabMenuFixed tabMenuFixedRight tabMenuSides useCursorPointer <?php echo $tabBackground; ?>">
                <span role="button" tabindex="0" aria-label="<?php echo __('My organisation\'s events only');?>" id="myOrgButton" title="<?php echo __('My organisation\'s events only');?>" onClick="executeFilter(<?php echo h($tempArgs);?>, '<?php echo $baseurl;?>/events/index');"><?php echo __('Org Events');?></span>
            </span>
        </div>
    <?php
        endif;
        echo $this->element('Events/eventIndexTable');
    ?>
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
<input type="hidden" class="keyboardShortcutsConfig" value="/shortcuts/event_index.json" />
<?php
    if (!$ajax) echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'index'));
