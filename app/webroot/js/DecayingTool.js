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
                    .attr('class', 'decayingGraphDot')
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
                    .attr('class', 'decayingGraphHandleDot')
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

                // scale the range of the data
                this.x.domain(d3.extent(data, function(d) { return d.x; }));
                this.y.domain([0, d3.max(data, function(d) { return d.y; })]);

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
                var $clicked = $(clicked);
                var tr = $clicked.closest('tr');
                var parameters = {
                    tau: parseFloat(tr.find('td.DMParameterTau')[0].innerHTML),
                    delta: parseFloat(tr.find('td.DMParameterDelta')[0].innerHTML),
                    threshold: parseInt(tr.find('td.DMParameterThreshold')[0].innerHTML)
                };
                var name = tr.find('td.DMName')[0].innerHTML;
                var desc = tr.find('td.DMDescription')[0].innerHTML;

                $('#input_Tau').val(parameters.tau);
                $('#input_Tau').data('multiplier', $('#input_Tau').val()/this.options.TICK_NUM);
                $('#input_Delta').val(parameters.delta);
                $('#input_Threshold').val(parameters.threshold);
                var $form = $('#saveForm');
                $form.find('[name="name"]').val(name);
                $form.find('[name="description"]').val(desc);
                this.refreshInfoCells(parameters.threshold);
                this.redrawGraph();
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
            fetchFormAndSubmit: function($clicked, type, model_id, formData) {
                var that = this;
                var url = "/decayingModel/";
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
                            that.refreshRow(data);
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
                // TODO: Implement
            },
            getDataFromRow: function($row) {
                var data = {};
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
                $rows.each(function(i) {
                    var rowData = that.getDataFromRow($(this));
                    delete rowData['name'];
                    delete rowData['description'];
                    if (that.simpleCompareObject(data, rowData)) {
                        $(this).addClass('success');
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
                var cb = $clicked.first().find('input');
                if (force === undefined) {
                    cb.prop('checked', !cb.is(':checked'));
                } else {
                    cb.prop('checked', force);
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
                Object.keys(data).forEach(function(k) {
                    var v = data[k];
                    var field = k.charAt(0).toUpperCase() + k.slice(1);
                    $('#DecayingModel'+field).val(v);
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
            }

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

function refreshGraph(updated) {
    decayingTool.redrawGraph();
}

var decayingTool;
$(document).ready(function() {
    $('[data-toggle="tooltip"]').tooltip();
    var container = '#decayGraph';
    $(container).decayingTool();
    decayingTool = $(container).data('decayingTool');

    $("#attributeTypeTableBody").selectable({
        filter: "tr:not(.hidden)",
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
        }
    });

    $('#attributeTypeTableBody').find('input[type="checkbox"]').change(function() {
        $row = $(this).closest('tr');
        $row.toggleClass('info', this.checked);
    });

    $('#checkAll').change(function() {
        var $checkboxes = $('#attributeTypeTableBody').find('input[type="checkbox"]');
        $checkboxes.prop('checked', this.checked);
        $row = $($checkboxes).closest('tr');
        $row.toggleClass('info', this.checked);
    });

    $('#table_toggle_all_type').change(function() {
        $('#attributeTypeTableBody').find('tr.isNotToIDS').toggleClass('hidden', !this.checked);
    });

    $('#table_toggle_objects').change(function() {
        $('#attributeTypeTableBody').find('tr.isObject').toggleClass('hidden', !this.checked);
    });
});
