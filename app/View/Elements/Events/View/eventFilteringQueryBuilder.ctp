<div id="eventFilteringQBWrapper" style="padding: 5px; display: none; border: 1px solid #dddddd; border-bottom: 0px;">
    <div id="eventFilteringQB" style="overflow-y: auto; padding-right: 5px; resize: vertical; max-height: 750px; height: 400px;"></div>
    <div style="display: flex; justify-content: flex-end; margin-top: 5px;">
            <input id="eventFilteringQBLinkInput" class="form-control" style="width: 66%;"></input>
            <button id="eventFilteringQBLinkCopy" type="button" class="btn btn-inverse" style="margin-right: 5px; margin-left: 5px;" onclick="clickMessage(this);"> <i class="fa fa-clipboard"></i> <?php echo h('Copy to clipboard'); ?> </button>
            <button id="eventFilteringQBSubmit" type="button" class="btn btn-success" style="margin-right: 5px;"> <i class="fa fa-filter"></i> <?php echo h('Filter'); ?> </button>
            <button id="eventFilteringQBClear" type="button" class="btn btn-xs btn-danger" style="" title="<?php echo h('Clear filtering rules'); ?>"> <i class="fa fa-times"></i> <?php echo h('Clear'); ?> </button>
    </div>
</div>
<?php
?>

<script>
var defaultFilteringRules = <?php echo json_encode($defaultFilteringRules); ?>;
var querybuilderTool;
function triggerEventFilteringTool(hide) {
    var qbOptions = {
        plugins: {
            'filter-description' : {
                mode: 'inline'
            },
            'unique-filter': null,
            'bt-tooltip-errors': null,
        },
        allow_empty: true,
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
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "includeDecayScore",
                "label": "Decay Score",
                "values": {
                    0: "No",
                    1: "Yes"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "toIDS",
                "label": "IDS Flag",
                "values": {
                    0: "Both",
                    1: "Set only",
                    2: "Exclude Unset"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "feed",
                "label": "Feeds",
                "values": {
                    0: "Both",
                    1: "Feed hits only",
                    2: "Exclude feed hits"
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "server",
                "label": "Servers",
                "values": {
                    0: "Both",
                    1: "Server hits only",
                    2: "Exclude server hits"
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
                    5: "Inherit",
                }
            },
            {
                "input": "radio",
                "type": "integer",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "sighting",
                "label": "Sightings",
                "values": {
                    0: "Both",
                    1: "Have sighting(s) only",
                    2: "Doesn\'t have sighting(s)"
                }
            },
            <?php
            if (empty($attributeTags) && isset($filters['taggedAttributes'])) {
                $attributeTags = array($filters['taggedAttributes']);
            }
            if (!empty($attributeTags)):
            ?>
            {
                "input": "select",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "taggedAttributes",
                "label": "Tags",
                "values": <?php echo json_encode(array_map("h", $attributeTags)); // additional `h` because values are directly insterted into the DOM by QB.?>
            },
            <?php endif; ?>
            <?php
            if (empty($attributeClusters) && isset($filters['galaxyAttachedAttributes'])) {
                $attributeClusters = array($filters['galaxyAttachedAttributes']);
            }
            if (!empty($attributeClusters)):
            ?>
            {
                "input": "select",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "galaxyAttachedAttributes",
                "label": "Galaxies",
                "values": <?php echo json_encode(array_map("h", $attributeClusters)); // additional `h` because values are directly insterted into the DOM by QB.?>
            },
            <?php endif; ?>
            {
                "input": "text",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "searchFor",
                "label": "Search in Attribute",
                <?php
                $searchableFields = array('id', 'uuid', 'value', 'comment', 'type', 'category', 'Tag.name');
                $searchableFields = implode(', ', $searchableFields);
                ?>
                "description": "Searchable Attribute fields: <b><?php echo h($searchableFields); ?></b>",
                "validation": {
                    "allow_empty_value": true
                }
            },
        ],
        rules: {
            condition: 'AND',
            not: false,
            rules: [
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['searchFor'])): ?>
                {
                    field: 'searchFor',
                    id: 'searchFor',
                    value: $('<div />').html("<?php echo isset($filters['searchFor']) ? h($filters['searchFor']) : ''; ?>").text()
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['attributeFilter'])): ?>
                {
                    field: 'attributeFilter',
                    id: 'attributeFilter',
                    <?php if (isset($filters['attributeFilter'])): ?>
                        value: "<?php echo in_array($filters['attributeFilter'], array('all', 'network', 'financial', 'file')) ? h($filters['attributeFilter']) : 'all'; ?>"
                    <?php else: ?>
                        value: "<?php echo 'all'; ?>"
                    <?php endif; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['proposal'])): ?>
                {
                    field: 'proposal',
                    id: 'proposal',
                    value: <?php echo isset($filters['proposal']) ? h($filters['proposal']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['correlation'])): ?>
                {
                    field: 'correlation',
                    id: 'correlation',
                    value: <?php echo isset($filters['correlation']) ? h($filters['correlation']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['warning'])): ?>
                {
                    field: 'warning',
                    id: 'warning',
                    value: <?php echo isset($filters['warning']) ? h($filters['warning']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['deleted'])): ?>
                {
                    field: 'deleted',
                    id: 'deleted',
                    value: <?php echo isset($filters['deleted']) ? h($filters['deleted']) : 2; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['includeRelatedTags'])): ?>
                {
                    field: 'includeRelatedTags',
                    id: 'includeRelatedTags',
                    value: <?php echo isset($filters['includeRelatedTags']) ? h($filters['includeRelatedTags']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['includeDecayScore'])): ?>
                {
                    field: 'includeDecayScore',
                    id: 'includeDecayScore',
                    value: <?php echo isset($filters['includeDecayScore']) ? h($filters['includeDecayScore']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['toIDS'])): ?>
                {
                    field: 'toIDS',
                    id: 'toIDS',
                    value: <?php echo isset($filters['toIDS']) ? h($filters['toIDS']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['feed'])): ?>
                {
                    field: 'feed',
                    id: 'feed',
                    value: <?php echo isset($filters['feed']) ? h($filters['feed']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['server'])): ?>
                {
                    field: 'server',
                    id: 'server',
                    value: <?php echo isset($filters['server']) ? h($filters['server']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['sighting'])): ?>
                {
                    field: 'sighting',
                    id: 'sighting',
                    value: <?php echo isset($filters['sighting']) ? h($filters['sighting']) : 0; ?>
                },
                <?php endif; ?>
                <?php if (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['distribution'])): ?>
                {
                    field: 'distribution',
                    id: 'distribution',
                    operator: 'in',
                    value: <?php echo isset($filters['distribution']) ? json_encode($filters['distribution']) : json_encode(array(0, 1, 2, 3, 4, 5)); ?>
                },
                <?php endif; ?>
                <?php
                if (!empty($filters['taggedAttributes']) && (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['taggedAttributes']))):
                    $tmp = array(
                        'field' => 'taggedAttributes',
                        'id' => 'taggedAttributes',
                        'value' => $filters['taggedAttributes']
                    );
                    echo json_encode($tmp) . ','; // sanitize data
                endif;
                if (!empty($filters['galaxyAttachedAttributes']) && (count($advancedFilteringActiveRules) == 0 || isset($advancedFilteringActiveRules['galaxyAttachedAttributes']))):
                    $tmp = array(
                        'field' => 'galaxyAttachedAttributes',
                        'id' => 'galaxyAttachedAttributes',
                        'value' => $filters['galaxyAttachedAttributes']
                    );
                    echo json_encode($tmp); // sanitize data
                endif;
                ?>
            ],
            flags: {
                no_add_group: true,
                condition_readonly: true,
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

    var filters = <?php echo json_encode($filters); ?>;
    var $wrapper = $('#eventFilteringQBWrapper');
    var $ev = $('#eventFilteringQB');
    querybuilderTool = $ev.queryBuilder(qbOptions);
    querybuilderTool = querybuilderTool[0].queryBuilder;

    querybuilderTool.on('rulesChanged', function() {
        updateURL();
    });
    if (hide === undefined || !hide) {
        $('#eventFilteringQB').height(qbOptions.rules.rules.length < 7 ? 'unset' : $('#eventFilteringQB').height());
        $wrapper.toggle('blind', 100, { direction: 'up' });
    }

    $('#eventFilteringQBSubmit').off('click').on('click', function() {
        $button = $(this);
        var rules = querybuilderTool.getRules({ skip_empty: true, allow_invalid: true });
        performQuery(rules);
    });

    $('#eventFilteringQBLinkCopy').off('click').on('click', function() {
        copyToClipboard($('#eventFilteringQBLinkInput'));
    });

    $('#eventFilteringQBClear').off('click').on('click', function() {
        // querybuilderTool.setRules({condition: "AND", rules: []});
        querybuilderTool.reset();
        $('#eventFilteringQB').queryBuilder('reset');
    });

    $ev.off('keyup').on('keyup', function(e){
        if(e.keyCode == 13) {
            $('#eventFilteringQBSubmit').trigger("click");
        }
    });

    updateURL();

    function updateURL() {
        var rules = querybuilderTool.getRules({ skip_empty: true, allow_invalid: true });
        var res = cleanRules(rules);
        var url = "<?php echo $baseurl; ?>/events/view/<?php echo h($event['Event']['id']); ?>" + buildFilterURL(res);
        $('#eventFilteringQBLinkInput').val(url);
    }
}


function buildFilterURL(res) {
    var url = "";
    Object.keys(res).forEach(function(k) {
        var v = res[k];
        if (Array.isArray(v)) {
            // v = JSON.stringify(v);
            v = v.join('||');
        }
        if (!Array.isArray(defaultFilteringRules[k]) && defaultFilteringRules[k] != v) {
            url += "/" + k + ":" + encodeURIComponent(v);
        } else {
            if (Array.isArray(defaultFilteringRules[k]) && defaultFilteringRules[k].join('||') != v) {
                url += "/" + k + ":" + encodeURIComponent(v);
            }
        }
    });
    return url;
}

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

function cleanRules(rules) {
    var res = {};
    recursiveInject(res, rules);
    // clean up invalid and unset
    Object.keys(res).forEach(function(k) {
        var v = res[k];
        if (v === undefined || v === '') {
            delete res[k];
        }
    });
    return res;
}

function performQuery(rules) {
    var res = cleanRules(rules);

    var url = "/events/viewEventAttributes/<?php echo h($event['Event']['id']); ?>";
    $.ajax({
        type:"post",
        url: url,
        data: res,
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

function copyToClipboard(element) {
    var $temp = $("<input id='xxx'>");
    $("body").append($temp);
    $temp.val($(element).val()).select();
    document.execCommand("copy");
    $temp.remove();
}

function clickMessage(clicked) {
    $clicked = $(clicked);
    $clicked.tooltip({
        title: 'Copied!',
        trigger: 'manual',
        container: 'body'
    })
    .tooltip('show');
    setTimeout(function () {
        $clicked.tooltip('destroy');
    }, 2000);
}
</script>
