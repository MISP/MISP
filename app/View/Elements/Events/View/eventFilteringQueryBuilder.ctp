<div id="eventFilteringQBWrapper" style="padding: 5px; display: none; border: 1px solid #dddddd; border-bottom: 0px;">
    <div id="eventFilteringQB"></div>
    <button id="eventFilteringQBSubmit" type="button" class="btn btn-inverse" style="display:block; margin-left:auto; margin-right: 0"> <i class="fa fa-filter"></i> Filter </button>
</div>
<?php
?>

<script>
function triggerEventFilteringTool(clicked) {
    var qbOptions = {
        plugins: {
            'filter-description' : {
                mode: 'inline'
            },
            'unique-filter': null,
            'bt-tooltip-errors': null,
        },
        allow_empty: true,
        display_empty_filter: false,
        conditions: ['OR', 'AND'],
        lang: {
            operators: {
                equal: 'show',
                in: 'show'
            }
        },
        filters: [
            {
                "input": "select",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "attributeFilter",
                "label": "Category",
                "values": {
                    "file": "File",
                    "network": "Network",
                    "financial": "Financial",
                    "all": "All"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "proposal",
                "label": "Proposal",
                "values": {
                    0: "Both",
                    1: "Proposal only",
                    2: "Exclude proposal"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "correlation",
                "label": "Correlation",
                "values": {
                    0: "Both",
                    1: "Correlation only",
                    2: "Exclude correlation"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "warning",
                "label": "Warning",
                "values": {
                    0: "Both",
                    1: "Warning only",
                    2: "Exclude warning"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "deleted",
                "label": "Deleted",
                "values": {
                    0: "Both",
                    1: "Deleted only",
                    2: "Exclude deleted"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "includeRelatedTags",
                "label": "Related Tags",
                "values": {
                    0: "None",
                    1: "Yes"
                }
            },
            {
                "input": "checkbox",
                "type": "integer",
                "operators": [
                    "in"
                ],
                "unique": true,
                "id": "distribution",
                "label": "Distribution",
                "values": {
                    0: "Your orginisation only",
                    1: "This community only",
                    2: "Connected community",
                    3: "All communities",
                    4: "Sharing group",
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "taggedAttributes",
                "label": "Tags",
                "values": {
                    0: "Both",
                    1: "Untagged Attribute",
                    2: "Tagged Attribute"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "galaxyAttachedAttributes",
                "label": "Galaxies",
                "values": {
                    0: "Both",
                    1: "Attributes without galaxy",
                    2: "Attributes with galaxy"
                }
            },
            {
                "input": "select",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": false,
                "id": "objectType",
                "label": "Object Types",
                <?php
                    $object_types = array();
                    foreach ($event['objects'] as $k => $object) {
                        if ($object['objectType'] == 'object') {
                            $object_types[$object['name']] = $object['name'];
                        }
                    }
                    ksort($object_types);
                ?>
                "values": <?php echo json_encode($object_types); ?>
            },
            {
                "input": "select",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": false,
                "id": "attributeType",
                "label": "Attribute Types",
                <?php
                    $attribute_types = array();
                    foreach ($event['objects'] as $k => $attribute) {
                        if ($attribute['objectType'] == 'attribute') {
                            $attribute_types[$attribute['type']] = $attribute['type'];
                        }
                    }
                    ksort($attribute_types);
                ?>
                "values": <?php echo json_encode($attribute_types); ?>
            },
            {
                "input": "text",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": false,
                "id": "searchFor",
                "label": "Search in Attribute",
                <?php
                $searchableFields = array('id', 'uuid', 'value', 'comment', 'type', 'category', 'Tag.name');
                $searchableFields = implode(', ', $searchableFields);
                ?>
                "description": "Searchable Attribute fields: <b><?php echo $searchableFields; ?></b>",
                "validation": {
                    "allow_empty_value": true
                }
            },
        ],
        rules: rules = {
            condition: 'AND',
            not: false,
            rules: [
                {
                    field: 'attributeFilter',
                    id: 'attributeFilter',
                    value: '<?php echo !isset($filteringData['category']) ?  'all' : h($filteringData['category']) ?>'
                },
                {
                    field: 'proposal',
                    id: 'proposal',
                    value: 0,
                },
                {
                    field: 'correlation',
                    id: 'correlation',
                    value: 0,
                },
                {
                    field: 'warning',
                    id: 'warning',
                    value: 0,
                },
                {
                    field: 'deleted',
                    id: 'deleted',
                    value: 0,
                },
                {
                    field: 'includeRelatedTags',
                    id: 'includeRelatedTags',
                    value: 0,
                },
                {
                    field: 'distribution',
                    id: 'distribution',
                    operator: 'in',
                    value: [0, 1, 2, 3, 4],
                },
                {
                    field: 'taggedAttributes',
                    id: 'taggedAttributes',
                    value: 0,
                },
                {
                    field: 'galaxyAttachedAttributes',
                    id: 'galaxyAttachedAttributes',
                    value: 0,
                },
                {
                    condition: 'OR',
                    not: false,
                    flags: {
                        no_add_group: true
                    },
                    rules: [{
                        field: 'objectType',
                        id: 'objectType',
                        value: '<?php reset($object_types); echo key($object_types); ?>',
                    }]
                },
                {
                    condition: 'OR',
                    not: false,
                    flags: {
                        no_add_group: true
                    },
                    rules: [{
                        field: 'attributeType',
                        id: 'attributeType',
                        value: '<?php reset($attribute_types); echo key($attribute_types); ?>',
                    }]
                },
                {
                    field: 'searchFor',
                    id: 'searchFor'
                }
            ],
            flags: {
                no_add_group: true
            }
        },
        icons: {
            add_group: 'fa fa-plus-square',
            add_rule: 'fa fa-plus-circle',
            remove_group: 'fa fa-minus-square',
            remove_rule: 'fa fa-minus-circle',
            error: 'fa fa-exclamation-triangle'
        },
    };


    var $wrapper = $('#eventFilteringQBWrapper');
    var $ev = $('#eventFilteringQB');
    var querybuilderTool = $ev.queryBuilder(qbOptions);
    querybuilderTool = querybuilderTool[0].queryBuilder;
    $wrapper.toggle('blind', 100, { direction: 'up' });
    // remove outer OR condition
    $ev.find('#eventFilteringQB_group_0 > .rules-group-header input[value="OR"]').parent().remove();
    $ev.find('#eventFilteringQB_group_0 > .rules-group-body input[value="AND"]').parent().remove();

    $('#eventFilteringQBSubmit').off('click').on('click', function() {
        $button = $(this);
        var rules = querybuilderTool.getRules();
        performQuery(rules);
    });


    function recursiveInject(result, rules) {
        if (rules.rules === undefined) { // add to result
            var field = rules.field;
            var value = rules.value;
            if (result.hasOwnProperty(field)) {
                if (Array.isArray(result[field])) {
                    result[field].push(value);
                } else {
                    result[field] = [result[field], value];
                }
            } else {
                result[field] = value;
            }
        }
        else if (Array.isArray(rules.rules)) {
            rules.rules.forEach(function(subrules) {
               recursiveInject(result, subrules) ;
            });
        }
    }

    function buildURL(res) {
        var url = "/events/viewEventAttributes/<?php echo h($event['Event']['id']); ?>";
        Object.keys(res).forEach(function(k) {
            var v = res[k];
            url += "/" + k + ":" + v;
        });
        return url;
    }

    function performQuery(rules) {
        var res = {};
        recursiveInject(res, rules);
        // clean up invalid and unset
        Object.keys(res).forEach(function(k) {
            var v = res[k];
            if (v === undefined || v === '') {
                delete res[k];
            }
        });

        url = buildURL(res);
        $.ajax({
    		type:"get",
    		url: url,
    		beforeSend: function (XMLHttpRequest) {
    			$(".loading").show();
    		},
    		success:function (data) {
    			$("#attributes_div").html(data);
    			$(".loading").hide();
    		},
    		error:function() {
    			showMessage('fail', 'Something went wrong - could not fetch attributes.');
    		}
    	});
    }

}
</script>
