// tooltips
var thread = null;
function setApiInfoBox(isTyping) {
    clearTimeout(thread);
    if (isTyping) {
        var delay = 200;
    } else {
        var delay = 0;
    }
    var $this = $(this);
    var payload = {
        "url": $('#ServerUrl').val()
    };
    if (payload) {
        thread = setTimeout(
            function() {
                $.ajax({
                    type: "POST",
                    url: '/servers/getApiInfo',
                    data: payload,
                    success:function (data, textStatus) {
                        $('#apiInfo').html(data);
                            addHoverInfo($('#ServerUrl').data('urlWithoutParam'));
                    }
                });
            },
            delay
        );
    } else {
        $('#apiInfo').empty();
    }
}

    var allValidApis;
    var fieldsConstraint;
    var querybuilderTool;

    $('form').submit(function(e) {
        $('#querybuilder').remove();
        return true;
    });

    $(document).ready(function () {
        insertRawRestResponse();
        $('.format-toggle-button').bind('click', function() {
            $('#rest-response-container').empty();
            if ($(this).data('toggle-type') == 'Raw') {
                insertRawRestResponse();
            } else if ($(this).data('toggle-type') == 'HTML') {
                insertHTMLRestResponse();
            } else if ($(this).data('toggle-type') == 'JSON') {
                insertJSONRestResponse();
            }
        });
        $('#ServerUrl').keyup(function() {
            $('#TemplateSelect').val($(this).val()).trigger("chosen:updated").trigger("change");
        });
        $('#TemplateSelect').change(function() {
            var selected_template = $('#TemplateSelect').val();
            if (selected_template !== '' && allValidApis[selected_template] !== undefined) {
                $('#template_description').show();
                $('#ServerMethod').val('POST');
                $('#ServerUrl').val(allValidApis[selected_template].url);
                $('#ServerUrl').data('urlWithoutParam', selected_template);
                $('#ServerBody').val(allValidApis[selected_template].body);
                setApiInfoBox(false);
                updateQueryTool(selected_template);
            }
        });

        /* Query builder */

        // Fix for Bootstrap Datepicker
        $('#builder-widgets').on('afterUpdateRuleValue.queryBuilder', function(e, rule) {
            if (rule.filter.plugin === 'datepicker') {
                rule.$el.find('.rule-value-container input').datepicker('update');
            }
        });

        querybuilderTool = $('#querybuilder').queryBuilder({
            plugins: {
                'filter-description' : {
                    mode: 'inline'
                },
                'unique-filter': null,
                'bt-tooltip-errors': null,
                'chosen-selectpicker': null,
                'not-group': null
            },
            allow_empty: true,

            filters: [{
                id: 'noValidFilters',
                label: 'No valid filters, Pick an endpoint first',
                type: 'string'
            }],
            icons: {
              add_group: 'fa fa-plus-square',
              add_rule: 'fa fa-plus-circle',
              remove_group: 'fa fa-minus-square',
              remove_rule: 'fa fa-minus-circle',
              error: 'fa fa-exclamation-triangle'
            }
        });
        querybuilderTool = querybuilderTool[0].queryBuilder;
        
        $('#btn-apply').on('click', function() {
            var result = querybuilderTool.getRules();
            
            if (!$.isEmptyObject(result)) {
                alert(JSON.stringify(result, null, 2));
            }
        });
        $('#btn-inject').on('click', function() {
            injectQuerybuilterRulesToBody();
        });

        /* Apply jquery chosen where applicable */
        $("#TemplateSelect").chosen();
    });


function updateQueryTool(url) {
    var apiJson = allValidApis[url];
    var filtersJson = fieldsConstraint[url];
    var filters = [];
    for (var k in filtersJson) {
        if (filtersJson.hasOwnProperty(k)) {
            var filter = filtersJson[k];
            var helptext = filter.help;
            if (helptext !== undefined) {
                filter.description = helptext;
            }
            if (filter.input === 'select') {
                filter.plugin = 'chosen';
            }
            filter.unique = filter.unique !== undefined ? filter.unique : true;
            filters.push(filter);
        }
    }
    if (filters.length > 0) {
        querybuilderTool.setFilters(true, filters);
    }

    // add and lock mandatory fields
    var mandatoryFields = apiJson.mandatory;
    if (mandatoryFields !== undefined && mandatoryFields.length > 0) {
        var rules = {
            "condition": "AND",
            "rules": [
                {
                    "condition": "AND",
                    "rules": [],
                    "not": false,
                    "valid": true,
                    "flags": {
                        "condition_readonly": true,
                        "no_add_rule": true,
                        "no_add_group": true,
                        "no_delete": true
                    }
                }
            ],
            "not": false,
            "valid": true
        };
        mandatoryFields.forEach(function(mandatory) {
            var r = filtersJson[mandatory];
            r.flags = {
                no_delete: true,
                filter_readonly: true
            };
            rules.rules[0].rules.push(r);
        })
    } else {
        var rules = {
            "condition": "AND",
            "rules": [],
            "not": false,
            "valid": true
        };
    }

    // add Params input field
    var paramFields = apiJson.params;
    $('#divAdditionalParamInput').remove();
    if (paramFields !== undefined && paramFields.length > 0) {
        var div = $('.selected-path-container');
        var additionalInput = $('<div class="query-builder">'
                + '<div class="rules-list">'
                    + '<div id="divAdditionalParamInput" class="rule-container">'
                        + '<input id="paramInput" class="form-control" type="text" style="margin-bottom: 0px;" placeholder="' + paramFields[0] + '">'
                    + '</div>'
                + '</div>'
            + '</div>');
        div.append(additionalInput);
    }

    querybuilderTool.setRules(rules, false);
}

function injectQuerybuilterRulesToBody() {
    var rules_root = querybuilderTool.getRules();
    var result = {};
    recursiveInject(result, rules_root, false);
    var jres = JSON.stringify(result, null, '    ');
    $('#ServerBody').val(jres);

    // inject param to url
    var param = $('#paramInput').val();
    if (param !== undefined) {
        var origVal = $('#ServerUrl').val();
        var newVal = origVal.replace(/(\[\w+\]){1}/, param);
        $('#ServerUrl').val(newVal);
    }
}

function recursiveInject(result, rules, isNot) {
    if (rules.rules === undefined) { // add to result
        var field = rules.field.split(".")[1];
        var value = rules.value;
        var operator_notequal = rules.operator === 'not_equal' ? true : false;
        var negate = isNot ^ operator_notequal;
        value = negate ? '!' + value : value;
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
           recursiveInject(result, subrules, isNot ^ rules.not) ;
        });
    }
}

function addHoverInfo(url) {
    if (allValidApis[url] === undefined) {
        return;
    }

    var authorizedParamTypes = ['mandatory', 'optional'];

    var todisplay = allValidApis[url].controller + '/' + allValidApis[url].action + '/';
    $('#selected-path').text(todisplay);

    authorizedParamTypes.forEach(function(paramtype) {
        if (allValidApis[url][paramtype] !== undefined) {
            allValidApis[url][paramtype].forEach(function(field) {
                if (fieldsConstraint[url][field] !== undefined) { // add icon
                    var apiInfo = fieldsConstraint[url][field].help;
                    if(apiInfo !== undefined && apiInfo !== '') {
                        $('#infofield-'+field).popover({
                            trigger: 'hover',
                            //placement: 'right',
                            content: apiInfo,
                        });
                    } else { // no help, delete icon
                        $('#infofield-'+field).remove();
                    }
                }
            });
        }
    });
}
