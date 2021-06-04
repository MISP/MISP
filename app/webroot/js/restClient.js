/* Codacy comment to notify that baseurl is a read-only global variable. */
/* global baseurl */

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
        "url": extractPathFromUrl($('#ServerUrl').val())
    };
    if (payload) {
        thread = setTimeout(
            function() {
                $.ajax({
                    type: "POST",
                    url: baseurl + '/servers/getApiInfo',
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

function loadRestClientHistory(k, data_container) {
    $('#ServerMethod').val(data_container[k]['RestClientHistory']['http_method']);
    $('#ServerUseFullPath').prop("checked", data_container[k]['RestClientHistory']['use_full_path']);
    $('#ServerShowResult').prop("checked", data_container[k]['RestClientHistory']['show_result']);
    $('#ServerSkipSslValidation').prop("checked", data_container[k]['RestClientHistory']['skip_ssl_validation']);
    $('#ServerUrl').val(data_container[k]['RestClientHistory']['url']);
    $('#ServerHeader').val(data_container[k]['RestClientHistory']['headers']);
    toggleRestClientBookmark();
    cm.setValue(data_container[k]['RestClientHistory']['body'])

    var url = extractPathFromUrl(data_container[k]['RestClientHistory']['url'])
    $('#TemplateSelect').val(url).trigger("chosen:updated");
    updateQueryTool(url, false);
    $('#querybuilder').find('select').trigger('chosen:updated');
    setApiInfoBox(false);
}

function extractPathFromUrl(url) {
    var el = document.createElement('a')
    el.href = url
    return el.pathname
}

function populate_rest_history(scope) {
    if (scope === 'history') {
        scope = '';
        var container_class = 'history_queries';
    } else {
        scope = '1';
        var container_class = 'bookmarked_queries';
    }
    $.get(baseurl + "/rest_client_history/index/" + scope, function(data) {
        $('.' + container_class).html(data);
    });
}

function toggleRestClientBookmark() {
    if ($('#ServerBookmark').prop("checked") == true) {
        $('#bookmark-name').css('display', 'block');
    } else {
        $('#bookmark-name').css('display', 'none');
    }
}

function removeRestClientHistoryItem(id) {
    $.ajax({
        data: '[]',
        success:function (data, textStatus) {
            populate_rest_history('bookmark');
            populate_rest_history('history');
        },
        error:function() {
            handleGenericAjaxResponse({'saved':false, 'errors':['Request failed due to an unexpected error.']});
        },
        type:"post",
        cache: false,
        url: baseurl + '/rest_client_history/delete/' + id,
    });
}




    var allValidApis;
    var fieldsConstraint;
    var querybuilderTool;
    var debounceTimerUpdate;

    $('form').submit(function(e) {
        $('#querybuilder').remove();
        return true;
    });

    $(document).ready(function () {
        insertRawRestResponse();
        $('.format-toggle-button').bind('click', function() {
            if ($(this).data('toggle-type') == 'Raw') {
                $('#rest-response-container').empty();
                insertRawRestResponse();
            } else if ($(this).data('toggle-type') == 'HTML') {
                $('#rest-response-container').empty();
                insertHTMLRestResponse();
            } else if ($(this).data('toggle-type') == 'JSON') {
                $('#rest-response-container').empty();
                insertJSONRestResponse();
            } else if ($(this).data('toggle-type') == 'Download') {
                var download_content = $('#rest-response-hidden-container').text();
                var extension = 'json';
                var export_type = 'json';
                var mime = 'application/json';
                if ($('#header-X-Response-Format').length != 0) {
                    extension = $('#header-X-Response-Format').text();
                }
                if ($('#header-Content-Type').length != 0) {
                    mime = $('#header-Content-Type').text();
                }
                if ($('#header-X-Export-Module-Used').length != 0) {
                    export_type = $('#header-X-Export-Module-Used').text();
                }
                var filename = export_type + '.result.' + extension;
                var blob = new Blob([download_content], {
                    type: mime
                });
                saveAs(blob, filename);
            }
        });

        $('#TemplateSelect').val($('#ServerUrl').val()).trigger("chosen:updated").trigger("change");
        $('#ServerUrl').keyup(function(e) {
            var that = this
            clearTimeout(debounceTimerUpdate);
            var c = String.fromCharCode(e.keyCode);
            var isWordCharacter = c.match(/\w/);
            if (e.keyCode === undefined || isWordCharacter) {
                debounceTimerUpdate = setTimeout(function() {
                    $('#TemplateSelect').val($(that).val()).trigger("chosen:updated").trigger("change");
                }, 200);
            }
        });

        $('#TemplateSelect').change(function(e) {
            var selected_template = $('#TemplateSelect').val();
            var previously_selected_template = $('#ServerUrl').data('urlWithoutParam')
            if (selected_template !== '' && allValidApis[selected_template] !== undefined) {
                $('#template_description').show();
                $('#ServerMethod').val('POST');
                var server_url_changed = $('#ServerUrl').val() != allValidApis[selected_template].url;
                $('#ServerUrl').val(allValidApis[selected_template].url);
                $('#ServerUrl').data('urlWithoutParam', selected_template);
                var body_value = cm.getValue();
                var body_changed = allValidApis[previously_selected_template] !== undefined ? allValidApis[previously_selected_template].body != body_value : true;
                var refreshBody = (body_value === '' || (server_url_changed && !body_changed))
                if (refreshBody) {
                    $('#ServerBody').val(allValidApis[selected_template].body);
                    cm.setValue(allValidApis[selected_template].body)
                }
                setApiInfoBox(false);
                updateQueryTool(selected_template, refreshBody);
            }
        });

        $('#showQB').click(function() {
            $('#qb-div').toggle();
            if ($('#TemplateSelect').val() !== '') {
                $('#ServerUrl').val('')
                $('#TemplateSelect').trigger("change");
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


function updateQueryTool(url, isEmpty) {
    if ($('#qb-div').css('display') == 'none') {
        return
    }
    var apiJson = allValidApis[url];
    var filtersJson = fieldsConstraint[url];

    isEmpty = isEmpty === undefined ? false : isEmpty;
    var body = cm.getValue();
    if (!isEmpty && body !== undefined && body.length > 0) {
        try {
            body = JSON.parse(body);
        } catch(e) {
            body = {};
        }
    } else {
        body = {};
    }

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
            var action = r.id.split('.')[1];
            if (body[action] !== undefined) {
                r.value = body[action];
                delete body[action];
            }
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

    Object.keys(body).forEach(function(k) {
        var values = body[k];
        if (Array.isArray(values)) {
            values.forEach(function(value) {
                var r = $.extend({}, filtersJson[k], true);
                r.value = value;
                if (mandatoryFields !== undefined && mandatoryFields.length > 0) {
                    rules.rules[0].rules.push(r);
                } else {
                    rules.rules.push(r);
                }
            });
        } else {
            var r = filtersJson[k];
            if (r !== undefined) { // rule is not defined in the description
                r.value = values;
                if (mandatoryFields !== undefined && mandatoryFields.length > 0) {
                    rules.rules[0].rules.push(r);
                } else {
                    rules.rules.push(r);
                }
            }
        }
    });

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
    cm.setValue(jres)

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
            var validApi = allValidApis[url][paramtype];
            if (!Array.isArray(validApi)) {
                var k = Object.keys(validApi)[0];
                if (k === 'AND' || k === 'OR') {
                    validApi = validApi[k];
                } else { // not an array, need to generate a new one (some api contain nested arrays: i.e. Org=>Array())
                    validApi = [];
                    for (var k in allValidApis[url][paramtype]){
                        if (allValidApis[url][paramtype].hasOwnProperty(k)) {
                            var v = allValidApis[url][paramtype][k];
                            if (typeof v === 'string') {
                                validApi.push(v);
                            } else {
                                v.forEach(function(v2) {
                                    validApi.push(v2);
                                });
                            }
                        }
                    }
                }
            }
            validApi.forEach(function(field) {
                if (fieldsConstraint[url][field] !== undefined) { // add icon
                    var apiInfo = fieldsConstraint[url][field].help;
                    if(apiInfo !== undefined && apiInfo !== '') {
                        $('#infofield-'+field).popover({
                            trigger: 'hover',
                            content: field + ': ' + apiInfo,
                        });
                    } else { // no help, delete icon
                        $('#infofield-'+field).remove();
                    }
                }
            });
        }
    });
}

function findPropertyFromValue(token) {
    var absoluteIndex = cm.indexFromPos(CodeMirror.Pos(token.line, token.start))
    var rawText = cm.getValue()
    for (var index = absoluteIndex; index > 0; index--) {
        var ch = rawText[index];
        if (ch == ':') {
            var token = cm.getTokenAt(cm.posFromIndex(index-2))
            if (token.type == 'string property') {
                return token.string.slice(1, token.string.length-1);
            }
        }
    }
    return false
}

function findMatchingHints(str, allHints) {
    allHints = allHints.map(function(str) {
        var strArray = typeof str === "object" ? String(str.value).split('&quot;') : str.split('&quot;')
        return {
            text: strArray.join('\\\"'), // transforms quoted elements into escaped quote
            renderText: typeof str === "object" ? str.label : strArray.join('\"'),
            render: function(elem, self, data) {
                $(elem).append(data.renderText);
            }
        }
    })
    if (str.length > 0) {
        var hints = []
        var maxHints = 100
        var hint
        for (var i = 0; hints.length < maxHints && i < allHints.length; i++) {
            hint = allHints[i];
            if (hint.text.startsWith(str)) {
                hints.push(hint)
            }
        }
        return hints
    } else {
        return allHints
    }
}

function getCompletions(token, isJSONKey) {
    var hints = []
    var url = $('#TemplateSelect').val()
    if (allValidApis[url] === undefined) {
        return hints
    }
    if (isJSONKey) {
        var apiJson = allValidApis[url];
        var filtersJson = fieldsConstraint[url];
        allHints = (apiJson.mandatory !== undefined ? apiJson.mandatory : []).concat((apiJson.optional !== undefined ? apiJson.optional : []))
        hints = findMatchingHints(token.string, allHints)
    } else {
        jsonKey = findPropertyFromValue(token)
        var filtersJson = fieldsConstraint[url];
        if (filtersJson[jsonKey] !== undefined) {
            var values = filtersJson[jsonKey].values
            if (values !== undefined) {
                allHints = Array.isArray(values) ? values : Object.keys(values)
                hints = findMatchingHints(token.string, allHints)
            }
        }
    }
    return hints
}

function jsonHints() {
    var cur = cm.getCursor()
    var token = cm.getTokenAt(cur)
    if (token.type != 'string property' && token.type != 'string') {
        return
    }
    if (cm.getMode().helperType !== "json") return;
    token.state = cm.state;
    token.line = cur.line

    if (/\"([^\"]*)\"/.test(token.string)) {
      token.end = cur.ch;
      token.string = token.string.slice(1, cur.ch - token.start);
    }

    return {
        list: getCompletions(token, token.type == 'string property'),
        from: CodeMirror.Pos(cur.line, token.start+1),
        to: CodeMirror.Pos(cur.line, token.end)
    }
}

var cm;
function setupCodeMirror() {
    var cmOptions = {
        mode: "application/json",
        theme:'default',
        gutters: ["CodeMirror-lint-markers"],
        lint: true,
        lineNumbers: true,
        indentUnit: 4,
        showCursorWhenSelecting: true,
        lineWrapping: true,
        autoCloseBrackets: true,
        extraKeys: {
            "Esc": function(cm) {
            },
            "Ctrl-Space": "autocomplete",
        },
        hintOptions: {
            completeSingle: false,
            hint: jsonHints
        },
    }
    cm = CodeMirror.fromTextArea(document.getElementById('ServerBody'), cmOptions);
    cm.on("keyup", function (cm, event) {
        if (!cm.state.completionActive && /*Enables keyboard navigation in autocomplete list*/
            event.keyCode != 13) {     /*Enter - do not open autocomplete list just after item has been selected in it*/ 
            cm.showHint()
        }
    });
}
