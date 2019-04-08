(function(factory) {
        "use strict";
        if (typeof define === 'function' && define.amd) {
            define(['jquery'], factory);
        } else if (window.jQuery && !window.jQuery.fn.DecayingTool) {
            factory(window.jQuery);
        }
    }

    (function($) {
        'use strict';

        var DecayingTool = function(container, options) {
            this.container = container;
            this._validateOptions(options);
            var default_options = {
                TICK_NUM: 300,
                margin: {top: 10, right: 10, bottom: 20, left: 30},
            };
            this.options = $.extend(true, {}, default_options, options);
            this._backup = {
                selection_history1: [],
                selection_history2: []
            };
            this._init();
        };

        DecayingTool.prototype = {
            constructor: DecayingTool,

            _validateOptions: function(options) {

            },

            getMultiplier: function() {
                return $('#input_Tau').data('multiplier');
            },
            resetMultiplier: function() {
                $('#input_Tau').data('multiplier', $('#input_Tau').val()/this.options.TICK_NUM);
            },

            /* Model */
            getScore: function(x, base_score) { // returns the score (x in days)
                if (base_score === undefined) {
                    base_score = 100;
                }
                var delta = parseFloat($('#input_Delta').val());
                var tau = parseInt($('#input_Tau').val());
                return parseFloat((base_score * (1 - Math.pow(x / tau, 1/delta))).toFixed(2));
            },
            getBaseLog: function(x, y) { // compute logarithm of any base
                return parseFloat(Math.log(y) / Math.log(x));
            },
            getDeltaFromPoint: function(x, y, base_score) {
                if (base_score === undefined) {
                    base_score = 100.0;
                }
                x = parseFloat(x);
                y = parseFloat(y);
                var tau = parseFloat($('#input_Tau').val());
                var delta = 1 / this.getBaseLog(x / tau, 1 - (y / base_score));
                return parseFloat(delta);
            },
            getReverseScore: function(y, base_score) {
                if (base_score === undefined) {
                    base_score = 100;
                }
                var delta = parseFloat($('#input_Delta').val());
                var tau = parseInt($('#input_Tau').val());
                return (tau * Math.pow(1 - (y / base_score), delta)).toFixed(2);
            },
            genDecay: function() { // generate scoring values over time
                var that = this;
                var threshold = parseInt($('#input_Threshold').val());
                return this.genAxis().map(function(e, x) {
                    var y = that.getScore(x * that.getMultiplier());
                    return y >= threshold ? y : 0;
                });
            },
            genLine: function() { // generate threshold values over time
                return this.genAxis().map(function(e) {
                    return parseInt($('#input_Threshold').val());
                });
            },
            genAxis: function(textLabel) { // generate all ticks based on lifetime value
                var tau = parseInt($('#input_Tau').val());
                return d3.range(0, tau + tau / this.options.TICK_NUM, tau / this.options.TICK_NUM);
            },
            genAll: function() {
                var decay = this.genDecay();
                var axe = this.genAxis();
                var thres = this.genLine();
                var data = [];
                for (var i=0; i<decay.length; i++) {
                    data.push({x: axe[i], y: decay[i], yThres: thres[i]});
                }
                return data;
            },

            /* BASE SCORE */
            toggleBasescoreForm: function() {

            },

            /* CANVAS */
            _init: function() {
                var that = this;
                this.resetMultiplier();
                this.width = $(this.container).width() - this.options.margin.left - this.options.margin.right;
                this.height = 380 - this.options.margin.top - this.options.margin.bottom;
                this.x = d3.scale.linear().range([0, this.width]);
                this.y = d3.scale.linear().range([this.height, 0]);
                this.xAxis = d3.svg.axis().scale(this.x).orient('bottom');
                this.yAxis = d3.svg.axis().scale(this.y).orient("left");
                this.yGrid = d3.svg.axis().scale(this.x).orient("bottom")
                    .ticks(5)
                    .tickSize(-this.height)
                    .tickFormat("");
                this.xGrid = d3.svg.axis().scale(this.y).orient("left")
                    .ticks(3)
                    .tickSize(-this.width)
                    .tickFormat("");

                this.drag = d3.behavior.drag().on("drag", this.dragmove);

                // define the area
                this.area = d3.svg.area()
                    .interpolate("monotone")
                    .x(function(d) { return that.x(d.x); })
                    .y0(this.height)
                    .y1(function(d) { return that.y(d.y); });
                this.areaThres = d3.svg.area()
                    .interpolate("monotone")
                    .x(function(d) { return that.x(d.x); })
                    .y0(this.height)
                    .y1(function(d) { return that.y(d.yThres); });

                // define the line
                this.valueline = d3.svg.line()
                    .interpolate("monotone")
                    .x(function(d) { return that.x(d.x); })
                    .y(function(d) { return that.y(d.y); });
                this.valuelineThres = d3.svg.line()
                    .interpolate("monotone")
                    .x(function(d) { return that.x(d.x); })
                    .y(function(d) { return that.y(d.yThres); });

                this.svg = d3.select(this.container)
                    .append("svg")
                        .attr("width", this.width + this.options.margin.left + this.options.margin.right)
                        .attr("height", this.height + this.options.margin.top + this.options.margin.bottom)
                    .append("g")
                        .attr("transform", "translate(" + this.options.margin.left + "," + this.options.margin.top + ")");

                var data = this.genAll();

                // scale the range of the data
                this.x.domain(d3.extent(data, function(d) { return d.x; }));
                this.y.domain([0, d3.max(data, function(d) { return d.y; })]);


                // add the Y gridlines
                this.svg.append("g")
                    .attr("class", "decayingGraphAxis grid grid-x")
                    .call(this.xGrid);

                // add the X gridlines
                this.svg.append("g")
                    .attr("class", "decayingGraphAxis grid grid-y")
                    .attr("transform", "translate(0," + this.height + ")")
                    .call(this.yGrid);

                // add the valueline path.
                this.svg.append("path")
                    .data([data])
                    .attr("class", "decayingGraphLine")
                    .attr("d", this.valueline);
                this.svg.append("path")
                    .data([data])
                    .attr("class", "decayingGraphLineThres")
                    .attr("d", this.valuelineThres);

                this.svg.append("path")
                .data([data])
                .attr("class", "decayingGraphAreaThres")
                .attr("d", this.areaThres);

                this.svg.selectAll('.decayingGraphDot')
                    .data([data])
                    .enter()
                    .append('g')
                    .append('circle')
                    .attr('id', 'decayingGraphDot')
                    .attr('class', 'decayingGraphDot useCursorPointer')
                    .attr("cx", function(d) { return that.x(that.getReverseScore(parseInt($('#input_Threshold').val()))); })
                    .attr("cy", function(d, i) { return that.y(parseInt($('#input_Threshold').val())); })
                    .attr("r", 5)
                    .call(this.drag);

                this.svg.selectAll('.decayingGraphHandleDot')
                    .data([data])
                    .enter()
                    .append('g')
                    .append('circle')
                    .attr('id', 'decayingGraphHandleDot')
                    .attr('class', 'decayingGraphHandleDot useCursorPointer')
                    .attr("cx", function(d) { return that.x(parseFloat($('#input_Tau').val()/2)); })
                    .attr("cy", function(d) { return that.y(that.getScore(parseInt($('#input_Tau').val()/2))); })
                    .attr("r", 5)
                    .call(this.drag);

                // add the X Axis
                this.svg.append("g")
                    .attr("class", "decayingGraphAxis axis-x")
                    .attr("transform", "translate(0," + this.height + ")")
                    .call(this.xAxis);

                // add the Y Axis
                this.svg.append("g")
                    .attr("class", "decayingGraphAxis axis-y")
                    .call(this.yAxis);

                this.refreshInfoCells();
            },
            redrawGraph: function(computeFromHandle) {
                var that = this;
                this.resetMultiplier();
                // update parameters based on the handle
                if (computeFromHandle !== undefined && computeFromHandle == 'decayingGraphHandleDot') {
                    var handle = this.svg.select('.decayingGraphHandleDot');
                    var hx = this.x.invert(handle.attr('cx'));
                    var hy = this.getValueYFromCanvas(this.height, parseInt(handle.attr('cy')));
                    var delta = this.getDeltaFromPoint(hx, hy);
                    $('#input_Delta').val(delta);
                } else if (computeFromHandle !== undefined && computeFromHandle == 'decayingGraphDot') {
                    var handle = this.svg.select('.decayingGraphDot');
                    var hx = parseInt(handle.attr('cx'));
                    var hy = parseInt(this.getValueYFromCanvas(this.height, parseInt(handle.attr('cy'))));
                    $('#input_Threshold').val(hy);
                }

                var data = this.genAll();

                if (data.length == 0) {
                    $(this.container).hide();
                    return;
                } else {
                    $(this.container).show();
                }

                // scale the range of the data
                this.x.domain(d3.extent(data, function(d) { return d.x; }));
                this.y.domain([0, d3.max(data, function(d) { return d.y; })]);

                this.svg.select(".decayingGraphAxis.grid-x")
                    .call(this.xGrid);
                this.svg.select(".decayingGraphAxis.grid-y")
                    .call(this.yGrid);

                this.svg.select(".decayingGraphLine")
                    .data([data])
                    .attr("d", this.valueline);
                this.svg.select(".decayingGraphLineThres")
                    .data([data])
                    .attr("d", this.valuelineThres);

                this.svg.select(".decayingGraphAreaThres")
                    .data([data])
                    .attr("d", this.areaThres);

                this.svg.select('.decayingGraphDot')
                    .data([data])
                    .attr("cx", function(d) { return that.x(that.getReverseScore(parseFloat($('#input_Threshold').val()))); })
                    .attr("cy", function(d, i) { return that.y(parseFloat($('#input_Threshold').val())); });

                if (computeFromHandle === undefined) {
                    this.svg.select('.decayingGraphHandleDot')
                        .attr("cx", function(d) { return that.x(parseFloat($('#input_Tau').val()/2)); })
                        .attr("cy", function(d) { return that.y(that.getScore(parseFloat($('#input_Tau').val()/2))); });
                }

                this.svg.select(".axis-x")
                    .call(this.xAxis);

                this.refreshInfoCells();
            },
            dragmove: function(d) {
                var point = d3.select(this);
                var id = point.attr('id');
                point.attr("cx", function() { return Math.max(Math.min(d3.event.x, decayingTool.width-1), 1); })
                    .attr("cy", function() { return Math.min(Math.max(d3.event.y, 0), decayingTool.height-1); });
                decayingTool.redrawGraph(id);
            },
            getValueYFromCanvas: function(canvas_height, curr_y) {
                return 100 * (canvas_height - curr_y) / canvas_height;
            },

            /* MODEL TABLE */
            loadModel: function(clicked) {
                var that = this;
                var $clicked = $(clicked);
                var tr = $clicked.closest('tr');
                var parameters = {
                    tau: parseFloat(tr.find('td.DMParameterTau').text()),
                    delta: parseFloat(tr.find('td.DMParameterDelta').text()),
                    threshold: parseInt(tr.find('td.DMParameterThreshold').text())
                };
                var name = tr.find('td.DMName').text();
                var desc = tr.find('td.DMDescription').text();
                var model_id = tr.find('td.DMId').text();

                $('#input_Tau').val(parameters.tau);
                $('#input_Tau').data('multiplier', $('#input_Tau').val()/this.options.TICK_NUM);
                $('#input_Delta').val(parameters.delta);
                $('#input_Threshold').val(parameters.threshold);
                var $form = $('#saveForm');
                $form.find('[name="name"]').val(name);
                $form.find('[name="description"]').val(desc);
                this.refreshInfoCells(parameters.threshold);
                this.redrawGraph();
                // highlight attribute types
                $.getJSON('/decayingModelMapping/viewAssociatedTypes/' + model_id, function(j) {
                    that.highlightAttributeType(j);
                });
            },
            retreiveData: function() {
                var $form = $('#saveForm')
                var data = {};
                data.name = $form.find('[name="name"]').val();
                data.description = $form.find('[name="description"]').val();
                var params = {};
                params.tau = parseInt($('#input_Tau').val());
                params.delta = parseFloat($('#input_Delta').val());
                params.threshold = parseInt($('#input_Threshold').val());
                data.parameters = params;
                return data;
            },
            saveModel: function(clicked) {
                var $clicked = $(clicked);
                var type = $clicked.data('save-type');
                var model_id = false;
                var data = this.retreiveData();
                data.parameters = JSON.stringify(data.parameters);
                if (type == 'edit') {
                    model_id = $clicked.data('model-id');
                    if (!confirm('Confirm overwrite?')) {
                        return;
                    }
                }
                this.fetchFormAndSubmit($clicked, type, model_id, data);
            },
            fetchFormAndSubmit: function($clicked, type, model_id, formData, baseurl) {
                var that = this;
                var url = baseurl === undefined ? "/decayingModel/" : baseurl;
                if (type == "add") {
                    url += type;
                } else {
                    url += type + "/" + model_id;
                }
                var loadingSpan = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';

                $.get(url, function(data) {
                    var $confbox = $("#confirmation_box");
                    $confbox.html(data);
                    var $form = $confbox.find('form');
                    that.injectData($form, formData);
                    $.ajax({
                        data: $form.serialize(),
                        cache: false,
                        beforeSend: function(XMLHttpRequest) {
                            $clicked.append(loadingSpan);
                        },
                        success: function(data, textStatus) {
                            showMessage('success', 'Network has been saved');
                            if (baseurl == "/decayingModel/") {
                                that.refreshRow(data);
                            } else if (baseurl == "/decayingModelMapping/") {
                                that.refreshTypeMappingTable(model_id);
                            }
                        },
                        error: function( jqXhr, textStatus, errorThrown ){
                            showMessage('fail', 'Could not save network');
                            console.log( errorThrown );
                        },
                        complete: function() {
                            $clicked.find('#loadingSpan').remove();
                            $form.remove();
                        },
                        type: 'post',
                        url: url
                    });
                });
            },
            applyModel: function(clicked) {
                var $row = $(clicked).parent().parent();
                var rowData = this.getDataFromRow($row);
                var selected_types = this.getSelected();
                var model_id = rowData.id;
                var data = { 'attributetypes': selected_types };
                this.fetchFormAndSubmit($(clicked), 'linkAttributeTypeToModel', model_id, data, "/decayingModelMapping/");
                // TODO: Implement
            },
            getDataFromRow: function($row) {
                var data = {};
                data.id = $row.find('td.DMId').text();
                data.name = $row.find('td.DMName').text();
                data.description = $row.find('td.DMDescription').text();
                data.parameters = {};
                data.parameters.tau = parseInt($row.find('td.DMParameterTau').text());
                data.parameters.delta = parseFloat($row.find('td.DMParameterDelta').text());
                data.parameters.threshold = parseInt($row.find('td.DMParameterThreshold').text());
                return data;
            },
            highlightMatchingRow: function() {
                var that = this;
                var data = this.retreiveData();
                delete data['name'];
                delete data['description'];
                var $rows = $('#modelTableBody').find('tr');
                $rows.removeClass('success');
                $('div.input-prepend > span.param-name').removeClass('success');
                $rows.each(function(i) {
                    var rowData = that.getDataFromRow($(this));
                    delete rowData['name'];
                    delete rowData['description'];
                    if (that.simpleCompareObject(data, rowData)) {
                        $(this).addClass('success');
                        $('div.input-prepend > span.param-name').addClass('success');
                    }
                });
            },
            refreshRow: function(data) {
                var decayingModel = data.data.DecayingModel;
                var row = '<tr id="modelId_' + decayingModel.id + '">'
                    + '<td class="DMName">' + decayingModel.name + '</td>'
                    + '<td class="DMName">' + decayingModel.org_id + '</td>'
                    + '<td class="DMDescription">' + decayingModel.description + '</td>'
                    + '<td class="DMParameterTau">' + decayingModel.parameters.tau + '</td>'
                    + '<td class="DMParameterDelta">' + decayingModel.parameters.delta + '</td>'
                    + '<td class="DMParameterThreshold">' + decayingModel.parameters.threshold + '</td>'
                    + '<td data->'
                    + '<button class="btn btn-success btn-small" onclick="decayingTool.loadModel(this);"><span class="fa fa-arrow-up"> Load model</span></button>'
                    + '<button class="btn btn-danger btn-small" style="margin-left: 3px;" data-save-type="edit" data-model-id="' + decayingModel.id + '" onclick="decayingTool.saveModel(this);"><span class="fa fa-paste"> Overwrite model</span></button>'
                    + '<button class="btn btn-info btn-small" style="margin-left: 3px;" onclick="decayingTool.applyModel(this);"><span class="fa fa-upload"> Apply model</span></button>'
                    + '</td>'
                    + '</tr>';

                if (data.action == 'add') {
                    var $row = $(row);
                    $('#modelTableBody').append($row);
                } else {
                    var $row = $('#modelId_'+decayingModel.id);
                    $row[0].outerHTML = row;
                }
                this.highlightMatchingRow();
            },

            /* TYPE TABLE */
            toggleCB: function(clicked, force) {
                var $clicked = $(clicked);
                var $cb = $clicked.first().find('input');
                if (force === undefined) {
                    $cb.prop('checked', !$cb.is(':checked'));
                } else {
                    $cb.prop('checked', force);
                }
            },
            getSelected: function() {
                var $selected_td = $('#table_attribute_type > tbody > tr.info > td:nth-child(2)');
                var selected_types = [];
                $selected_td.each(function() {
                    selected_types.push($(this).text().trim());
                });
                return selected_types;
            },
            filterTableType: function(table, searchString) {
                var $table = $(table);
                var $body = $table.find('tbody');
                if (searchString === '') {
                    $body.find('tr.isNotToIDS').forceClass('hidden', !$('#table_toggle_all_type').is(':checked'));
                    $body.find('tr.isObject').forceClass('hidden', !$('#table_toggle_objects').is(':checked'));
                    $body.find('tr:not(".isObject, .isNotToIDS")').forceClass('hidden', false);
                } else {
                    // hide everything
                    $body.find('tr').each(function() {
                        $(this).forceClass('hidden', true);
                    });
                    // show only matching elements
                    var $cells = $table.find('tbody > tr > td.isFilteringField');
                    $cells.each(function() {
                        if ($(this).text().trim().indexOf(searchString) != -1) {
                            $(this).parent().filter('.isNotToIDS').forceClass('hidden', !$('#table_toggle_all_type').is(':checked'));
                            $(this).parent().filter('.isObject').forceClass('hidden', !$('#table_toggle_objects').is(':checked'));
                            $(this).parent().filter(':not(".isObject, .isNotToIDS")').forceClass('hidden', false);
                        }
                    });
                }
            },
            highlightAttributeType: function(obj) {
                var that = this;
                if (obj instanceof jQuery) {
                    var $tr = obj;
                } else { // obj is list of type
                    var $tr = this.findMatchingAttributeType(obj);
                }
                decayingTool.backupSelection();
                var $all_tr = $('#attributeTypeTableBody').find('tr');
                var $all_checkboxes = $all_tr.find('input[type="checkbox"]');
                $all_checkboxes.prop('checked', false);
                $all_tr.removeClass('info');
                $tr.forceClass('info ui-selectee ui-selected', true)
                    .find('input[type="checkbox"]').prop('checked', true);
            },
            refreshModelId: function(model_id, obj) {
                if (obj instanceof jQuery) {
                    var $tr = obj;
                } else { // obj is list of type
                    var $tr = this.findMatchingAttributeType(obj);
                }
                var $all_tr = $('#attributeTypeTableBody').find('tr');
                $all_tr.find("td.isModelIdField > a:contains('" + model_id + "')").remove();
                var $a = $('<a href="#" onclick="$(\'#modelId_' + model_id + '\').find(\'.decayingLoadBtn\').click();">' + model_id + '</a>')
                $tr.find('td.isModelIdField').append($a);

            },
            findMatchingAttributeType: function(types) {
                var $cells = $('#table_attribute_type').find('tbody > tr > td.isAttributeTypeField');
                var matching = $cells.filter(function() {
                    var value = $(this).text().trim();
                    if (types.includes(value)) {
                        return true;
                    } else {
                        return false;
                    }
                });
                return matching.parent();
            },
            refreshTypeMappingTable: function(model_id) {
                var that = this;
                $.getJSON('/decayingModelMapping/viewAssociatedTypes/' + model_id, function(j) {
                    // ensure that the row contains the model ID
                    var $tr = that.findMatchingAttributeType(j);
                    that.highlightAttributeType($tr);
                    that.refreshModelId(model_id, $tr);
                });
            },
            backupSelection: function() {
                this._backup.selection_history2 = this._backup.selection_history1;
                this._backup.selection_history1 = $('#table_attribute_type').find('tbody > tr.info');
            },
            restoreSelection: function() {
                if (this._backup.selection_history2.length > 0) {
                    selectSelectableElement(this._backup.selection_history2);
                }
            },

            /* UTIL */
            refreshInfoCells: function() {
                var threshold = parseInt($('#input_Threshold').val());
                $('#infoCellHalved').text(this.daysToText(this.getReverseScore((100-threshold)/2 + threshold)));
                $('#infoCellExpired').text(this.daysToText(this.getReverseScore(threshold)));
                this.highlightMatchingRow();
            },
            daysToText: function(days) {
                days = parseFloat(days);
                var hours = parseInt((days - parseInt(days)) * 24);
                var text = ""
                    + parseInt(days)
                    + (days>1 ? " days" : " day");
                if (hours > 0) {
                    text += " and " + hours + (hours>1 ? " hours" : " hour");
                }
                return text;
            },
            injectData: function($form, data) {
                var prefixkey = $form.attr('action').split('/')[1].ucfirst();
                Object.keys(data).forEach(function(k) {
                    var v = data[k];
                    v = Array.isArray(v) ? JSON.stringify(v) : v;
                    var field = k.ucfirst();
                    $('#'+prefixkey+field).val(v);
                });
            },
            simpleCompareObject: function(obj1, obj2) { // recursively compare object equality on their value
                var flag_same = true;
                var objectKeys = Object.keys(obj1);
                for (var i = 0; i < objectKeys.length; i++) {
                    var k = objectKeys[i];
                    var v1 = obj1[k];
                    var v2 = obj2[k];

                    if (v1 instanceof Object && v2 instanceof Object) {
                        flag_same = this.simpleCompareObject(v1, v2);
                    } else if ( (v1 instanceof Object) && !(v2 instanceof Object) || (!(v1 instanceof Object) && (v2 instanceof Object))) {
                        return false;
                    } else if (v1 !== v2) {
                        return false;
                    }

                    if (!flag_same) {
                        return false;
                    }
                }
                return flag_same;
            },
        };

        $.DecayingTool = DecayingTool;
        $.fn.decayingTool = function(options) {
            var pickedArgs = arguments;

            return this.each(function() {
                var $this = $(this),
                    inst = $this.data('decayingTool'),
                    options = ((typeof options === 'object') ? options : {});
                if ((!inst) && (typeof options !== 'string')) {
                    $this.data('decayingTool', new DecayingTool(this, options));
                } else {
                    if (typeof options === 'string') {
                        inst[options].apply(inst, Array.prototype.slice.call(pickerArgs, 1));
                    }
                }
            });
        };

        $.fn.decayingTool.constructor = DecayingTool;
    })
);

jQuery.fn.forceClass = function(className, state) {
    var o = this // It's your element
    if (state) {
        o.addClass(className);
    } else {
        o.removeClass(className);
    }
    return this; // This is needed so others can keep chaining off of this
};

function refreshGraph(updated) {
    decayingTool.redrawGraph();
}

function selectSelectableElement(elementToSelect) {
    // add unselecting class to all elements in the styleboard canvas except current one
    $('#table_attribute_type').find('tbody > tr.info').removeClass("ui-selected").addClass("ui-unselecting");

    // add ui-selecting class to the element to select
    elementToSelect.addClass("ui-selecting");

    decayingTool.selectable_widget.selectable('refresh');
    // trigger the mouse stop event (this will select all .ui-selecting elements, and deselect all .ui-unselecting elements)
    decayingTool.selectable_widget.selectable( "instance" )._mouseStop(null);
}

var decayingTool;
$(document).ready(function() {
    $('[data-toggle="tooltip"]').tooltip();
    var container = '#decayGraph';
    $(container).decayingTool();
    decayingTool = $(container).data('decayingTool');

    decayingTool.selectable_widget = $("#attributeTypeTableBody").selectable({
        filter: "tr:not(.hidden)",
        cancel: "a, input",
        selected: function( event, ui ) {
            if (event.ctrlKey) {
                $(ui.selected).toggleClass("info");
                decayingTool.toggleCB($(ui.selected));
            } else {
                $(ui.selected).addClass("info");
                decayingTool.toggleCB($(ui.selected), true);
            }
        },
        unselected: function( event, ui ) {
            $(ui.unselected).removeClass("info");
            decayingTool.toggleCB($(ui.unselected), false);
        },
        stop: function( event, ui) {
            decayingTool.backupSelection();
        }
    });

    $('#attributeTypeTableBody').find('input[type="checkbox"]').change(function() {
        $row = $(this).closest('tr');
        $row.toggleClass('info ui-selectee ui-selected', this.checked);
        decayingTool.backupSelection();
    });

    $('#checkAll').change(function() {
        var $checkboxes = $('#attributeTypeTableBody').find('input[type="checkbox"]');
        $checkboxes.prop('checked', this.checked);
        var $row = $($checkboxes).closest('tr');
        $row.toggleClass('info ui-selectee ui-selected', this.checked);
    });

    $('#table_toggle_all_type').change(function() {
        decayingTool.filterTableType('#table_attribute_type', $('#table_type_search').val());
    });

    $('#table_toggle_objects').change(function() {
        decayingTool.filterTableType('#table_attribute_type', $('#table_type_search').val());
    });

    $('#table_type_search').on('input', function() {
        decayingTool.filterTableType('#table_attribute_type', this.value);
    });
});
