<div class="events <?php if (!$ajax) echo 'index'; ?>">
    <h2><?php echo __('Events');?></h2>
    <div class="pagination">
        <ul>
        <?php
            $pagination = $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            $pagination .= $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            $pagination .= $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $pagination;
        ?>
        </ul>
    </div>
    <?php
        $searchScopes = [
            'searcheventinfo' => __('Event info'),
            'searchall' => __('All fields'),
            'searcheventid' => __('ID / UUID'),
            'searchtags' => __('Tag'),
        ];
        $searchKey = 'searcheventinfo';

        $filterParamsString = [];
        foreach ($passedArgsArray as $k => $v) {
            if (isset($searchScopes["search$k"])) {
                $searchKey = "search$k";
            }

            $filterParamsString[] = sprintf(
                '%s: %s',
                h(ucfirst($k)),
                h(is_array($v) ? http_build_query($v) : $v)
            );
        }
        $filterParamsString = implode(' & ', $filterParamsString);

        $columnsDescription = [
            'owner_org' => __('Owner org'),
            'is_extension' => __('Extended event'),
            'attribute_count' => __('Attribute count'),
            'creator_user' => __('Creator user'),
            'tags' => __('Tags'),
            'clusters' => __('Clusters'),
            'correlations' => __('Correlations'),
            'sightings' => __('Sightings'),
            'proposals' => __('Proposals'),
            'discussion' => __('Posts'),
            'report_count' => __('Report count'),
            'timestamp' => __('Last modified at'),
            'publish_timestamp' => __('Published at'),
            'highlights' => __('Highlights'),
        ];

        $columnsMenu = [];
        foreach ($possibleColumns as $possibleColumn) {
            $html = in_array($possibleColumn, $columns, true) ? '<i class="fa fa-check"></i> ' : '<i class="fa fa-check" style="visibility: hidden"></i> ';
            $html .= $columnsDescription[$possibleColumn];
            $columnsMenu[] = [
                'html' => $html,
                'onClick' => 'eventIndexColumnsToggle',
                'onClickParams' => [$possibleColumn],
            ];
        }

        $data = array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'id' => 'create-button',
                            'title' => __('Modify filters'),
                            'fa-icon' => 'search',
                            'onClick' => 'getPopup',
                            'onClickParams' => array(h($urlparams), 'events', 'filterEventIndex')
                        ),
                        array(
                            'id' => 'event-template-picker-button',
                            'requirement' => (
                                $this->Acl->canAccess('eventTemplates', 'index')
                                && $this->Acl->canAccess('eventTemplates', 'instantiate')
                            ),
                            'title' => __('Create event from template'),
                            'fa-icon' => 'clone',
                            'onClick' => 'openEventTemplatePicker'
                        )
                    )
                ),
                array(
                    'children' => array(
                        array(
                            'id' => 'multi-delete-button',
                            'title' => __('Delete selected events'),
                            'fa-icon' => 'trash',
                            'class' => 'hidden mass-delete',
                            'onClick' => 'multiSelectDeleteEvents'
                        ),
                        array(
                            'id' => 'multi-export-button',
                            'title' => __('Export selected events'),
                            'fa-icon' => 'file-export',
                            'class' => 'hidden mass-export',
                            'onClick' => 'multiSelectExportEvents'
                        ),
                        array(
                            'id' => 'multi-tag-button',
                            'title' => __('Tag selected events (global where permitted, local otherwise)'),
                            'html' => '<i class="fas fa-globe"></i> <i class="fas fa-tag"></i>',
                            'class' => 'hidden mass-tag',
                            'requirement' => $this->Acl->canAccess('tags', 'selectTaxonomy'),
                            'data' => [
                                'popover-popup' => $baseurl . '/tags/selectTaxonomy/selected/event',
                            ],
                        ),
                        array(
                            'id' => 'multi-local-tag-button',
                            'title' => __('Add local tag to selected events'),
                            'html' => '<i class="fas fa-user"></i> <i class="fas fa-tag"></i>',
                            'class' => 'hidden mass-tag',
                            'requirement' => $this->Acl->canAccess('tags', 'selectTaxonomy'),
                            'data' => [
                                'popover-popup' => $baseurl . '/tags/selectTaxonomy/local:1/selected/event',
                            ],
                        ),
                        array(
                            'id' => 'multi-galaxy-button',
                            'title' => __('Add cluster to selected events (global where permitted, local otherwise)'),
                            'html' => '<i class="fas fa-globe"></i> <i class="fas fa-book-open"></i>',
                            'class' => 'hidden mass-galaxy',
                            'requirement' => $this->Acl->canAccess('galaxies', 'selectGalaxyNamespace'),
                            'data' => [
                                'popover-popup' => $baseurl . '/galaxies/selectGalaxyNamespace/selected/event',
                            ],
                        ),
                        array(
                            'id' => 'multi-local-galaxy-button',
                            'title' => __('Add local cluster to selected events'),
                            'html' => '<i class="fas fa-user"></i> <i class="fas fa-book-open"></i>',
                            'class' => 'hidden mass-galaxy',
                            'requirement' => $this->Acl->canAccess('galaxies', 'selectGalaxyNamespace'),
                            'data' => [
                                'popover-popup' => $baseurl . '/galaxies/selectGalaxyNamespace/selected/event/local:1',
                            ],
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
                    'children' => array(
                        array(
                            'id' => 'simple_filter',
                            'type' => 'group',
                            'class' => 'last',
                            'title' => __('Choose columns to show'),
                            'fa-icon' => 'columns',
                            'children' => $columnsMenu,
                        ),
                    ),
                ),
                array(
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchScopes' => $searchScopes,
                    'searchKey' => $searchKey,
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
        <?= $pagination ?>
        </ul>
    </div>
</div>
<script>
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('.searchFilterButton').click(function() {
            runIndexFilter(this);
        });
        $('#quickFilterScopeSelector').change(function() {
            $('#quickFilterField').data('searchkey', this.value)
        });
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['vis', 'distribution-graph'],
    'js' => ['vis', 'jquery-ui.min', 'network-distribution-graph'],
]);
// Event-template picker modal for "Add Event → From Template" (PRD §5.2
// F2.1/F2.2). Self-contained — exposes window.openEventTemplatePicker
// which the toolbar button's onClick hands to ListTopBar. Gated on the
// eventTemplates/instantiate ACL via the toolbar's `requirement`, so
// users without access never see the button nor load the modal.
if (!$ajax
    && $this->Acl->canAccess('eventTemplates', 'index')
    && $this->Acl->canAccess('eventTemplates', 'instantiate')
) {
    echo $this->element('eventTemplates/templatePickerModal');
}
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'index'));
}
if (!$ajax) {
    echo $this->Html->script('mass-event-tagging');
}
