<?php

echo '<div class="index">';

echo $this->element('/genericElements/IndexTable/index_table', [
    'data' => [
        'title' => __('Attributes'),
        'data' => $attributes,
        'fields' => [
            [
                'name' => __('Date'),
                'sort' => 'Attribute.timestamp',
                'element' => 'timestamp',
                'time_format' => 'Y-m-d',
                'data_path' => 'Attribute.timestamp'
            ],
            [
                'name' => __('Event'),
                'sort' => 'Attribute.event_id',
                'data_path' => 'Attribute.event_id'
            ],
            [
                'name' => __('Org'),
                'sort' => 'Event.Orgc.name',
                'data_path' => 'Event.Orgc',
                'element' => 'org'
            ],
            [
                'name' => __('Category'),
                'sort' => 'Attribute.category',
                'data_path' => 'Attribute.category'
            ],
            [
                'name' => __('Type'),
                'sort' => 'Attribute.type',
                'data_path' => 'Attribute.type'
            ],
            [
                'name' => __('Value'),
                'sort' => 'Attribute.value',
                'data_path' => 'Attribute.value'
            ],
            [
                'name' => __('Tags'),
                'element' => 'attributeTags',
                'data_path' => 'Attribute.AttributeTag',
                'class' => 'short'
            ],
            [
                'name' => __('Galaxies'),
                'element' => 'attributeGalaxies',
                'data_path' => 'Attribute.Galaxy',
                'class' => 'short'
            ],
            [
                'name' => __('Comment'),
                'data_path' => 'Attribute.comment'
            ],
            [
                'name' => __('Correlate'),
                'element' => 'correlate',
                'data' => [
                    'object' => [
                        'value_path' => 'Attribute'
                    ]
                ]
            ],
            [
                'name' => __('Related Events'),
                'element' => 'relatedEvents',
                'data' => [
                    'object' => [
                        'value_path' => 'Attribute'
                    ],
                    'scope' => 'Attribute'
                ]
            ],
            [
                'name' => __('Feed hits'),
                'element' => 'feedHits',
                'data' => [
                    'object' => [
                        'value_path' => 'Attribute'
                    ]
                ]
            ],
            [
                'name' => __('IDS'),
                'element' => 'toIds',
                'data' => [
                    'object' => [
                        'value_path' => 'Attribute'
                    ]
                ],
            ],
            [
                'name' => __('Distribution'),
                'element' => 'distribution_levels',
                'data_path' => 'Attribute.distribution',
                'distributionLevels' => $distributionLevels,
                'data' => [
                    'object' => [
                        'value_path' => 'Attribute'
                    ],
                    'scope' => 'Attribute'
                ],
                'quickedit' => true
            ],
            [
                'name' => __('Sightings'),
                'element' => 'sightings',
                'data' => [
                    'object' => [
                        'value_path' => 'Attribute'
                    ],
                ],
                'sightings' => $sightingsData
            ],
            [
                'name' => __('Activity'),
                'element' => 'sightingsActivity',
                'data' => [
                    'object' => [
                        'value_path' => 'Attribute'
                    ],
                ],
                'sightings' => $sightingsData
            ],
        ],
        'actions' => array(
            [
                'url' => $baseurl . '/shadow_attributes/edit',
                'url_params_data_paths' => array(
                    'Attribute.id'
                ),
                'icon' => 'comment'
            ],
            [
                'onclick' => "deleteObject('shadow_attributes', 'delete', '[onclick_params_data_path]');",
                'onclick_params_data_path' => 'Attribute.id',
                'icon' => 'trash',
                'title' => __('Propose deletion'),
                'requirement' => $isSiteAdmin,
            ],
            [
                'url' => $baseurl . '/attributes',
                'icon' => 'grip-lines-vertical'
            ],
            [
                'url' => $baseurl . '/attributes/edit',
                'url_params_data_paths' => array(
                    'Attribute.id'
                ),
                'icon' => 'edit'
            ],
            [
                'onclick' => "deleteObject('attributes', 'delete', '[onclick_params_data_path]/true');",
                'onclick_params_data_path' => 'Attribute.id',
                'icon' => 'trash',
                'title' => __('Permanently delete attribute'),
                'requirement' => $isSiteAdmin,
            ]
        )
    ]
]);

echo '</div>';

// Generate form for adding sighting just once, generation for every attribute is surprisingly too slow
echo $this->Form->create('Sighting', ['id' => 'SightingForm', 'url' => $baseurl . '/sightings/add/', 'style' => 'display:none;']);
echo $this->Form->input('id', ['label' => false, 'type' => 'number']);
echo $this->Form->input('type', ['label' => false]);
echo $this->Form->end();

$class = $isSearch == 1 ? 'searchAttributes2' : 'listAttributes';
echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => $class));

?>

<script type="text/javascript">
    // tooltips
    $(function() {
        $("td, div").tooltip({
            'placement': 'top',
            'container': 'body',
            delay: {
                show: 500,
                hide: 100
            }
        });
        $('.screenshot').click(function() {
            screenshotPopup($(this).attr('src'), $(this).attr('title'));
        });
        $('.addGalaxy').click(function() {
            addGalaxyListener(this);
        });
        $('.sightings_advanced_add').click(function() {
            var selected = [];
            var object_context = $(this).data('object-context');
            var object_id = $(this).data('object-id');
            if (object_id == 'selected') {
                $(".select_attribute").each(function() {
                    if ($(this).is(":checked")) {
                        selected.push($(this).data("id"));
                    }
                });
                object_id = selected.join('|');
            }
            url = "<?php echo $baseurl; ?>" + "/sightings/advanced/" + object_id + "/" + object_context;
            genericPopup(url, '#popover_box');
        });
        $('.correlation-toggle').click(function() {
            var attribute_id = $(this).data('attribute-id');
            getPopup(attribute_id, 'attributes', 'toggleCorrelation', '', '#confirmation_box');
            return false;
        });
        $('.toids-toggle').click(function() {
            var attribute_id = $(this).data('attribute-id');
            getPopup(attribute_id, 'attributes', 'toggleToIDS', '', '#confirmation_box');
            return false;
        });
        popoverStartup();
        $(document).on('click', function(e) {
            //did not click a popover toggle or popover
            if ($(e.target).data('toggle') !== 'popover' &&
                $(e.target).parents('.popover.in').length === 0) {
                // filter for only defined popover
                var definedPopovers = $('[data-toggle="popover"]').filter(function(i, e) {
                    return $(e).data('popover') !== undefined;
                });
                definedPopovers.popover('hide');
            }
        });
    });
</script>