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
                            'onClickParams' => array($urlparams, 'events', 'filterEventIndex')
                        )
                    )
                ),
                array(
                    'children' => array(
                        array(
                            'id' => 'multi-delete-button',
                            'title' => __('Delete selected Events'),
                            'fa-icon' => 'trash',
                            'class' => 'hidden mass-select',
                            'onClick' => 'multiSelectDeleteEvents'
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
                            'url' => $baseurl . '/events/index',
                            'title' => __('Remove filters'),
                            'fa-icon' => 'times'
                        )
                    )
                ),
                array(
                    'children' => array(
                        array(
                            'title' => __('My events only'),
                            'text' => __('My Events'),
                            'data' => array(
                                'searchemail' => h($me['email'])
                            ),
                            'class' => 'searchFilterButton',
                            'active' => isset($passedArgsArray['email']) && $passedArgsArray['email'] === $me['email']
                        ),
                        array(
                            'title' => __('My organisation\'s events only'),
                            'text' => __('Org Events'),
                            'data' => array(
                                'searchorg' => h($me['org_id'])
                            ),
                            'class' => 'searchFilterButton',
                            'active' => isset($passedArgsArray['org']) && $passedArgsArray['org'] === $me['org_id']
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
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('.searchFilterButton').click(function() {
            runIndexFilter(this);
        });
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });

</script>
<?php
    echo $this->Html->script('vis');
    echo $this->Html->css('vis');
    echo $this->Html->css('distribution-graph');
    echo $this->Html->script('network-distribution-graph');
?>

<input type="hidden" class="keyboardShortcutsConfig" value="/shortcuts/event_index.json" />
<?php
    if (!$ajax) echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'index'));
