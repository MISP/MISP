<?php
$warninglistsValues = [];
foreach ($event['warnings'] as $id => $name) {
    $warninglistsValues[] = [(int)$id => h($name)];
}
$warninglistsValues = json_encode($warninglistsValues, JSON_UNESCAPED_UNICODE);

$relatedEventsValues = [];
foreach ($event['RelatedEvent'] as $relatedEvent) {
    $relatedEventsValues[] = [(int)$relatedEvent["Event"]["id"] => "#{$relatedEvent["Event"]["id"]} " . h($relatedEvent["Event"]["info"])];
}
$relatedEventsValues = json_encode($relatedEventsValues, JSON_UNESCAPED_UNICODE);

// Rules for query builder
$rules = [];
if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules['searchFor'])) {
    $rules['searchFor'] = isset($filters['searchFor']) ? h($filters['searchFor']) : '';
}
if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules['attributeFilter'])) {
    $rules['attributeFilter'] = isset($filters['attributeFilter']) && in_array($filters['attributeFilter'], ['all', 'network', 'financial', 'file'], true) ? $filters['attributeFilter'] : 'all';
}
if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules['proposal'])) {
    $rules['proposal'] = isset($filters['proposal']) ? intval($filters['proposal']) : 0;
}
if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules['correlation'])) {
    $rules['correlation'] = isset($filters['correlation']) ? intval($filters['correlation']) : 0;
}
if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules['correlationId'])) {
    if (isset($filters['correlationId'])) {
        $value = is_array($filters['correlationId']) ? array_map("intval", $filters['correlationId']) : intval($filters['correlationId']);
    } else {
        $value = "";
    }
    $rules['correlationId'] = $value;
}
if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules['warning'])) {
    $rules['warning'] = isset($filters['warning']) ? intval($filters['warning']) : 0;
}
if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules['warninglistId'])) {
    if (isset($filters['warninglistId'])) {
        $value = is_array($filters['warninglistId']) ? array_map("intval", $filters['warninglistId']) : intval($filters['warninglistId']);
    } else {
        $value = "";
    }
    $rules['warninglistId'] = $value;
}
foreach (['deleted', 'includeRelatedTags', 'includeDecayScore', 'toIDS', 'feed', 'server', 'sighting'] as $field) {
    if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules[$field])) {
        $rules[$field] = isset($filters[$field]) ? intval($filters[$field]) : 0;
    }
}
if (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules['distribution'])) {
    if (isset($filters['distribution'])) {
        $value = is_array($filters['distribution']) ? array_map("intval", $filters['distribution']) : intval($filters['distribution']);
    } else {
        $value = [0, 1, 2, 3, 4, 5];
    }
    $rules['distribution'] = $value;
}
foreach (['taggedAttributes', 'galaxyAttachedAttributes'] as $field) {
    if (!empty($filters[$field]) && (empty($advancedFilteringActiveRules) || isset($advancedFilteringActiveRules[$field]))) {
        $rules[$field] = $filters[$field];
    }
}
$jsonRules = [];
foreach ($rules as $field => $value) {
    if ($field === 'distribution') {
        $jsonRules[] = [
            'field' => $field,
            'id' => $field,
            'operator' => 'in',
            'value' => $value,
        ];
    } else {
        $jsonRules[] = [
            'field' => $field,
            'id' => $field,
            'value' => $value,
        ];
    }
}
$jsonRules = json_encode($jsonRules, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
?>
<div id="eventFilteringQBWrapper">
    <div id="eventFilteringQB"></div>
    <div style="display: flex; justify-content: flex-end; margin-top: 5px;">
        <input id="eventFilteringQBLinkInput" class="form-control" style="width: 66%;">
        <button id="eventFilteringQBLinkCopy" type="button" class="btn btn-inverse" style="margin-right: 5px; margin-left: 5px;"> <i class="fa fa-clipboard"></i> Copy to clipboard</button>
        <button id="eventFilteringQBSubmit" type="button" class="btn btn-success" style="margin-right: 5px;"> <i class="fa fa-filter"></i> Filter</button>
        <button id="eventFilteringQBClear" type="button" class="btn btn-xs btn-danger" title="Clear filtering rules"> <i class="fa fa-times"></i> Clear</button>
    </div>
</div>
<script>
var defaultFilteringRules = <?= json_encode($defaultFilteringRules); ?>;
var querybuilderTool = undefined;
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
                "input": "select",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "correlationId",
                "label": "Correlations with event",
                "values": <?= $relatedEventsValues ?>
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
                "input": "select",
                "type": "string",
                "operators": [
                    "equal",
                ],
                "unique": true,
                "id": "warninglistId",
                "label": "Warninglist",
                "values": <?= $warninglistsValues ?>
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
                    0: "Exclude deleted",
                    1: "Both",
                    2: "Deleted only",
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
                    0: "Your organisation only",
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
                "values": <?php echo json_encode(array_map("h", $attributeTags)); // additional `h` because values are directly inserted into the DOM by QB.?>
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
                "values": <?php echo json_encode(array_map("h", $attributeClusters)); // additional `h` because values are directly inserted into the DOM by QB.?>
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
            rules: <?= $jsonRules ?>,
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

    var $wrapper = $('#eventFilteringQBWrapper');
    var $ev = $('#eventFilteringQB');
    querybuilderTool = $ev.queryBuilder(qbOptions);
    querybuilderTool = querybuilderTool[0].queryBuilder;

    querybuilderTool.on('rulesChanged', function() {
        updateURL();
    });
    if (hide === undefined || !hide) {
        $ev.height(qbOptions.rules.rules.length < 7 ? 'unset' : $ev.height());
        $wrapper.toggle('blind', 100, { direction: 'up' });
    }

    $('#eventFilteringQBSubmit').off('click').on('click', function() {
        var rules = querybuilderTool.getRules({ skip_empty: true, allow_invalid: true });
        performQuery(rules);
    });

    $('#eventFilteringQBLinkCopy').off('click').on('click', function() {
        copyToClipboard($('#eventFilteringQBLinkInput'));
        clickMessage(this);
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
        var url = "<?php echo $baseurl; ?>/events/view/<?= intval($event['Event']['id']) ?>" + buildFilterURL(res);
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

function clickMessage(clicked) {
    var $clicked = $(clicked);
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
