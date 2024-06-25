<?php
    $eventId = (int) $event['Event']['id'];
    if (!empty($this->passedArgs['correlation'])) {
        $attributeFilter = 'correlation';
    }
    $simple_filter_data = array(
        array(
            'id' => 'filter_all',
            'title' => __('Show all attributes'),
            'text' => __('All'),
            'active' => $attributeFilter === 'all',
            'onClick' => 'filterAttributes',
            'onClickParams' => array('all')
        )
    );
    foreach ($typeGroups as $group) {
        $simple_filter_data[] = array(
            'id' => 'filter_' . h($group),
            'title' => __('Only show %s related attributes', h($group)),
            'text' => Inflector::humanize($group),
            'active' => $attributeFilter === $group,
            'onClick' => 'filterAttributes',
            'onClickParams' => array($group)
        );
    }
    $simple_filter_data[] = array(
        'id' => 'filter_proposal',
        'title' => __('Only show proposals'),
        'text' => __('Proposal'),
        'active' => $attributeFilter === 'proposal',
        'onClick' => 'toggleBoolFilter',
        'onClickParams' => array('proposal')
    );
    $simple_filter_data[] = array(
        'id' => 'filter_correlation',
        'title' => __('Only show correlating attributes'),
        'text' => __('Correlation'),
        'active' => $attributeFilter === 'correlation',
        'onClick' => 'filterAttributes',
        'onClickParams' => array('correlation'),
    );
    $simple_filter_data[] = array(
        'id' => 'filter_warning',
        'title' => __('Only show potentially false positive attributes'),
        'text' => __('Warning'),
        'active' => $attributeFilter === 'warning',
        'onClick' => 'filterAttributes',
        'onClickParams' => array('warning')
    );
    $data = array(
        'children' => array(
            array(
                'children' => array(
                    array(
                        'id' => 'create-button',
                        'title' => $possibleAction === 'attribute' ? __('Add attribute') : __('Add proposal'),
                        'fa-icon' => 'plus',
                        'class' => $mayModify ? 'modal-open' : 'modal-open last',
                        'url' => $baseurl . '/' . $possibleAction . 's/add/' . $eventId,
                    ),
                    array(
                        'id' => 'object-button',
                        'title' => __('Add Object'),
                        'fa-icon' => 'list',
                        'class' => 'last',
                        'onClick' => 'popoverPopupNew',
                        'onClickParams' => ['this', "$baseurl/objectTemplates/objectMetaChoice/$eventId"],
                        'requirement' => $mayModify,
                    ),
                    array(
                        'id' => 'multi-edit-button',
                        'title' => __('Edit selected Attributes'),
                        'class' => 'mass-select hidden',
                        'fa-icon' => 'edit',
                        'onClick' => 'editSelectedAttributes',
                        'onClickParams' => array($eventId)
                    ),
                    array(
                        'id' => 'multi-tag-button',
                        'title' => __('Tag selected Attributes'),
                        'class' => 'mass-select hidden',
                        'fa-icon' => 'tag',
                        'data' => [
                            'popover-popup' => $baseurl . '/tags/selectTaxonomy/selected/attribute',
                        ],
                    ),
                    array(
                        'id' => 'multi-local-tag-button',
                        'title' => __('Add Local tag on selected Attributes'),
                        'class' => 'mass-select hidden',
                        'fa-icon' => 'user',
                        'data' => [
                            'popover-popup' => $baseurl . '/tags/selectTaxonomy/local:1/selected/attribute',
                        ],
                    ),
                    array(
                        'id' => 'multi-galaxy-button',
                        'title' => __('Add new cluster to selected Attributes'),
                        'class' => 'mass-select hidden',
                        'fa-icon' => 'rebel',
                        'fa-source' => 'fab',
                        'data' => [
                            'popover-popup' => $baseurl . '/galaxies/selectGalaxyNamespace/selected/attribute/eventid:' . $eventId,
                        ],
                    ),
                    array(
                        'id' => 'multi-galaxy-button',
                        'title' => __('Add new local cluster to selected Attributes'),
                        'class' => 'mass-select hidden',
                        'fa-icon' => 'empire',
                        'fa-source' => 'fab',
                        'data' => [
                            'popover-popup' => $baseurl . '/galaxies/selectGalaxyNamespace/selected/attribute/local:1/eventid:' . $eventId,
                        ],
                    ),
                    array(
                        'id' => 'group-into-object-button',
                        'title' => __('Group selected Attributes into an Object'),
                        'class' => 'mass-select hidden',
                        'fa-icon' => 'object-group',
                        'fa-source' => 'fa',
                        'onClick' => 'proposeObjectsFromSelectedAttributes',
                        'onClickParams' => array('this', $eventId)
                    ),
                    array(
                        'id' => 'multi-relationship-button',
                        'title' => __('Create new relationship for selected entities'),
                        'class' => 'mass-select hidden',
                        'fa-icon' => 'project-diagram',
                        'fa-source' => 'fas',
                        'onClick' => 'bulkAddRelationshipToSelectedAttributes',
                        'onClickParams' => array('this', $eventId)
                    ),
                    array(
                        'id' => 'multi-delete-button',
                        'title' => __('Delete selected Attributes'),
                        'class' => 'mass-select hidden',
                        'fa-icon' => 'trash',
                        'onClick' => 'multiSelectAction',
                        'onClickParams' => array($eventId, 'deleteAttributes')
                    ),
                    array(
                        'id' => 'multi-accept-button',
                        'title' => __('Accept selected Proposals'),
                        'class' => 'mass-proposal-select hidden',
                        'fa-icon' => 'check-circle',
                        'onClick' => 'multiSelectAction',
                        'onClickParams' => array($eventId, 'acceptProposals')
                    ),
                    array(
                        'id' => 'multi-discard-button',
                        'title' => __('Discard selected Proposals'),
                        'class' => 'mass-proposal-select hidden',
                        'fa-icon' => 'times',
                        'onClick' => 'multiSelectAction',
                        'onClickParams' => array($eventId, 'discardProposals')
                    ),
                    array(
                        'id' => 'multi-sighting-button',
                        'title' => __('Sightings display for selected attributes'),
                        'class' => 'mass-select hidden sightings_advanced_add',
                        'data' => array('object-id' => 'selected', 'object-context' => 'attribute'),
                        'fa-icon' => 'wrench'
                    )
                )
            ),
            array(
                'children' => array(
                    array(
                        'id' => 'freetext-button',
                        'title' => __('Populate using the freetext import tool'),
                        'fa-icon' => 'align-left',
                        'onClick' => 'getPopup',
                        'onClickParams' => array($eventId, 'events', 'freeTextImport')
                    ),
                    array(
                        'id' => 'attribute-replace-button',
                        'title' => __('Replace all attributes of a category/type combination within the event'),
                        'fa-icon' => 'random',
                        'onClick' => 'getPopup',
                        'onClickParams' => array($eventId, 'attributes', 'attributeReplace'),
                        'requirement' => $mayModify
                    )
                )
            ),
            array(
                'children' => array(
                    array(
                        'id' => 'simple_filter',
                        'type' => 'group',
                        'active' => $attributeFilter !== 'all',
                        'title' => __('Use a list of simple scopes to filter the data'),
                        'text' => __('Scope toggle'),
                        'children' => $simple_filter_data
                    ),
                    array(
                        'id' => 'filter_deleted',
                        'title' => __('Include deleted attributes'),
                        'fa-icon' => 'trash',
                        'text' => __('Deleted'),
                        'active' => $deleted,
                        'onClick' => 'toggleBoolFilter',
                        'onClickParams' => array('deleted'),
                        'requirement' => $me['Role']['perm_sync'] || $event['Orgc']['id'] == $me['org_id']
                    ),
                    array(
                        'id' => 'show_attribute_decaying_score',
                        'title' => __('Show attribute decaying score'),
                        'fa-icon' => 'chart-line',
                        'text' => __('Decay score'),
                        'active' => $includeDecayScore,
                        'onClick' => 'toggleBoolFilter',
                        'onClickParams' => array('includeDecayScore')
                    ),
                    array(
                        'id' => 'show_attribute_sightingdb',
                        'title' => __('Show SightingDB lookup results'),
                        'fa-icon' => 'binoculars',
                        'text' => __('SightingDB'),
                        'active' => !empty($includeSightingdb),
                        'onClick' => 'toggleBoolFilter',
                        'onClickParams' => array('includeSightingdb'),
                        'requirement' => $sightingsDbEnabled,
                    ),
                    array(
                        'id' => 'show_attribute_context',
                        'title' => __('Show attribute context fields'),
                        'fa-icon' => 'info-circle',
                        'text' => __('Context'),
                        'onClick' => 'toggleContextFields'
                    ),
                    array(
                        'id' => 'show_related_tags',
                        'title' => __('Show related tags'),
                        'fa-icon' => 'project-diagram',
                        'text' => __('Related Tags'),
                        'active' => $includeRelatedTags,
                        'onClick' => 'toggleBoolFilter',
                        'onClickParams' => array('includeRelatedTags')
                    ),
                    array(
                        'id' => 'advanced_filtering',
                        'title' => __('Advanced filtering tool'),
                        'fa-icon' => 'filter',
                        'html' => sprintf(
                            '%s%s',
                            __('Filtering tool'),
                            $advancedFilteringActive ? sprintf(
                                ' (<span class="bold" title="%s">%s</span>)',
                                sprintf(
                                    __('%s active rule(s)'),
                                    h(count($advancedFilteringActiveRules))
                                ),
                                h(count($advancedFilteringActiveRules))
                            ) : ''
                        ),
                        'active' => $advancedFilteringActive,
                        'onClick' => 'triggerEventFilteringTool',
                    )
                )
            ),
            [
                'children' => [
                    [
                        'id' => 'expand-all-objects',
                        'text' => __('Expand all Objects'),
                        'title' => __('Show all Attribute contained in Objects'),
                        'fa-icon' => 'angle-double-down',
                        'onClick' => 'showAllAttributeInObjects',
                        'onClickParams' => [],
                    ],
                    [
                        'id' => 'collapse-all-objects',
                        'text' => __('Collapse all Attributes'),
                        'title' => __('Hide all Attribute contained in Objects'),
                        'fa-icon' => 'angle-double-up',
                        'onClick' => 'hideAllAttributeInObjects',
                        'onClickParams' => [],
                    ],
                ],
            ],
            array(
                'type' => 'search',
                'fa-icon' => 'search',
                'placeholder' => __('Enter value to search'),
                'value' => isset($filters['searchFor']) ? $filters['searchFor'] : null,
                'cancel' => array(
                    'fa-icon' => 'times',
                    'title' => __('Remove filters'),
                    'onClick' => 'filterAttributes',
                    'onClickParams' => array('all')
                )
            )
        )
    );
    echo $this->element('/genericElements/ListTopBar/scaffold', array('data' => $data));
    echo $this->element('/Events/View/eventFilteringQueryBuilder');
