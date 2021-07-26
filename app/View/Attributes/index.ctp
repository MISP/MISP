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
                'class' => 'short',
                'element' => 'timestamp',
                'time_format' => 'Y-m-d',
                'data_path' => 'Attribute.timestamp',
            ],
            [
                'name' => __('Event'),
                'sort' => 'Attribute.event_id',
                'class' => 'short',
                'data_path' => 'Attribute.event_id',
            ],
            [
                'name' => __('Org'),
                'sort' => 'Event.Orgc.name',
                'class' => 'short',
                'data_path' => 'Event.Orgc',
                'element' => 'org'
            ],
            [
                'name' => __('Category'),
                'sort' => 'Attribute.category',
                'class' => 'short',
                'data_path' => 'Attribute.category',
            ],
            [
                'name' => __('Type'),
                'sort' => 'Attribute.type',
                'class' => 'short',
                'data_path' => 'Attribute.type',
            ],
            [
                'name' => __('Value'),
                'sort' => 'Attribute.value',
                'class' => 'short',
                'data_path' => 'Attribute.value',
            ],
            [
                'name' => __('Tags'),
                'class' => 'short',
                'data_path' => 'Attribute.AttributeTag',
            ],
            [
                'name' => __('Galaxies'),
                'class' => 'short',
                'data_path' => 'Attribute.Galaxy',
            ],
            [
                'name' => __('Comment'),
                'class' => 'shortish',
                'data_path' => 'Attribute.comment',
            ],
            [
                'name' => __('Correlate'),
                'class' => 'shortish',
                'data_path' => 'Attribute.disable_correlation',
                'data' => [
                    'object' => [
                        'value_path' => 'Attribute'
                    ],
                ],
                'element' => 'correlate',
                'scope' => 'Attribute',
            ],
        ],
    ]
]);
echo '</div>';

$class = $isSearch == 1 ? 'searchAttributes2' : 'listAttributes';
echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => $class));

?>

<script type="text/javascript">
    // tooltips
    $(function() {
        $('.correlation-toggle').click(function() {
            var attribute_id = $(this).data('attribute-id');
            getPopup(attribute_id, 'attributes', 'toggleCorrelation', '', '#confirmation_box');
            return false;
        });
    });
</script>