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
            var that = this;
            this.container = container;
            this._validateOptions(options);
            var default_options = {
                TICK_NUM: 300,
                margin: {top: 10, right: 10, bottom: 35, left: 45},
            };
            this.options = $.extend(true, {}, default_options, options);
            this._backup = {
                selection_history1: [],
                selection_history2: []
            };
            this.model_table = new ModelTable();
            this.model_table.refreshTable();
            this._init();
        };

        DecayingTool.prototype = {
            constructor: DecayingTool,

            _validateOptions: function(options) {

            },

            getMultiplier: function() {
                return $('#input_lifetime').data('multiplier');
            },
            resetMultiplier: function() {
                $('#input_lifetime').data('multiplier', $('#input_lifetime').val()/this.options.TICK_NUM);
            },

            /* Model */
            getScore: function(x, base_score) { // returns the score (x in days)
                if (base_score === undefined) {
                    base_score = 100;
                }
                var decay_speed = parseFloat($('#input_decay_speed').val());
                var lifetime = parseInt($('#input_lifetime').val());
                return parseFloat((base_score * (1 - Math.pow(x / lifetime, 1/decay_speed))).toFixed(2));
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
                var lifetime = parseFloat($('#input_lifetime').val());
                var decay_speed = 1 / this.getBaseLog(x / lifetime, 1 - (y / base_score));
                return parseFloat(decay_speed);
            },
            getReverseScore: function(y, base_score) {
                if (base_score === undefined) {
                    base_score = 100;
                }
                var decay_speed = parseFloat($('#input_decay_speed').val());
                var lifetime = parseInt($('#input_lifetime').val());
                return (lifetime * Math.pow(1 - (y / base_score), decay_speed)).toFixed(2);
            },
            genDecay: function() { // generate scoring values over time
                var that = this;
                var threshold = parseInt($('#input_threshold').val());
                return this.genAxis().map(function(e, x) {
                    var y = that.getScore(x * that.getMultiplier());
                    return y >= threshold ? y : 0;
                });
            },
            genLine: function() { // generate threshold values over time
                return this.genAxis().map(function(e) {
                    return parseInt($('#input_threshold').val());
                });
            },
            genAxis: function(textLabel) { // generate all ticks based on lifetime value
                var lifetime = parseInt($('#input_lifetime').val());
                return d3.range(0, lifetime + lifetime / this.options.TICK_NUM, lifetime / this.options.TICK_NUM);
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
                var that = this;
                $.get(baseurl + '/decayingModel/decayingToolBasescore', function(html) {
                    $('#popover_form_large').html('<div class="close-icon useCursorPointer" onClick="$(\'#popover_form_large\').fadeOut();$(\'#gray_out\').fadeOut();"></div>' + html);
                    openPopup('#popover_form_large');
                    that.syncBasescoreSliders();
                });
            },
            syncBasescoreSliders: function() {
                var default_base_score = $('#input_default_base_score').val();
                $('#basescore_configurator #base_score_default_value').val(default_base_score);
                var base_score_config = JSON.parse($('#input_base_score_config').val());
                Object.keys(base_score_config).forEach(function(taxonomy_name) {
                    var taxonomy_val = base_score_config[taxonomy_name]*100;
                    $('#body_taxonomies').find('[data-taxonomyname="' + taxonomy_name + '"]').val(taxonomy_val)
                        .first().trigger('change');
                });
            },

            /* CANVAS */
            _init: function() {
                var that = this;
                this.user_org_id = logged_user_org_id;
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
                    .attr("cx", function(d) { return that.x(that.getReverseScore(parseInt($('#input_threshold').val()))); })
                    .attr("cy", function(d, i) { return that.y(parseInt($('#input_threshold').val())); })
                    .attr("r", 5)
                    .call(this.drag);

                this.svg.selectAll('.decayingGraphHandleDot')
                    .data([data])
                    .enter()
                    .append('g')
                    .append('circle')
                    .attr('id', 'decayingGraphHandleDot')
                    .attr('class', 'decayingGraphHandleDot useCursorPointer')
                    .attr("cx", function(d) { return that.x(parseFloat($('#input_lifetime').val()/4)); })
                    .attr("cy", function(d) { return that.y(that.getScore(parseInt($('#input_lifetime').val()/4))); })
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

                this.svg.append("text")
                    .classed('axis-label', true)
                    .attr("text-anchor", "end")
                    .attr("x", this.width / 2)
                    .attr("y", this.height)
                    .attr("dy", '30px')
                    .text("Days");

                this.svg.append("text")
                    .classed('axis-label', true)
                    .attr("text-anchor", "middle")
                    .attr("transform", "rotate(-90 0 " + this.height / 2 + ")")
                    .attr("x", 0)
                    .attr("dy", '-30px')
                    .attr("y", this.height / 2)
                    .text("Score");

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
                    var decay_speed = this.getDeltaFromPoint(hx, hy);
                    $('#input_decay_speed').val(decay_speed);
                } else if (computeFromHandle !== undefined && computeFromHandle == 'decayingGraphDot') {
                    var handle = this.svg.select('.decayingGraphDot');
                    var hx = parseInt(handle.attr('cx'));
                    var hy = parseInt(this.getValueYFromCanvas(this.height, parseInt(handle.attr('cy'))));
                    $('#input_threshold').val(hy);
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
                    .attr("cx", function(d) { return that.x(that.getReverseScore(parseFloat($('#input_threshold').val()))); })
                    .attr("cy", function(d, i) { return that.y(parseFloat($('#input_threshold').val())); });

                if (computeFromHandle === undefined) {
                    this.svg.select('.decayingGraphHandleDot')
                        .attr("cx", function(d) { return that.x(parseFloat($('#input_lifetime').val()/4)); })
                        .attr("cy", function(d) { return that.y(that.getScore(parseFloat($('#input_lifetime').val()/4))); });
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
                var $tr = $clicked.closest('tr');
                var model = d3.select($tr[0]).data()[0].DecayingModel;
                $('#table-model td > span.DMCheckbox > input').prop('checked', false).prop('disabled', true).trigger('change');
                if (!model.default) {
                    $tr.find('td > span.DMCheckbox > input').prop('checked', true).prop('disabled', false).trigger('change');
                }

                $('#input_lifetime, #input_lifetime').val(model.parameters.lifetime);
                $('#input_lifetime').data('multiplier', $('#input_lifetime').val()/this.options.TICK_NUM);
                $('#input_decay_speed, #input_decay_speed_range').val(model.parameters.decay_speed);
                $('#input_threshold, #input_threshold_range').val(model.parameters.threshold);
                var base_score_config = model.parameters.base_score_config === undefined ? {} : model.parameters.base_score_config;
                $('#input_base_score_config').val(JSON.stringify(base_score_config));
                var model_settings = model.parameters.settings === undefined ? {} : model.parameters.settings;
                $('#textarea_other_settings_formulas').val(JSON.stringify(model_settings));
                $('#input_default_base_score').val(model.parameters.default_base_score);
                $('#formulaSelectPicker').val(model.formula);
                var $form = $('#saveForm');
                $form.find('[name="name"]').val(model.name);
                $form.find('[name="description"]').val(model.description);
                toggleContainer();
                this.refreshInfoCells();
                this.redrawGraph();
                // highlight attribute types
                $.getJSON(baseurl + '/decayingModelMapping/viewAssociatedTypes/' + model.id, function(j) {
                    that.highlightAttributeType(j);
                });
            },
            retreiveData: function() {
                var $form = $('#saveForm')
                var data = {};
                data.name = $form.find('[name="name"]').val();
                data.description = $form.find('[name="description"]').val();
                data.formula = $('#formulaSelectPicker').val();
                var params = {};
                params.lifetime = parseInt($('#input_lifetime').val());
                params.decay_speed = parseFloat($('#input_decay_speed').val());
                params.threshold = parseInt($('#input_threshold').val());
                params.default_base_score = parseInt($('#input_default_base_score').val());
                var base_score_config = $('#input_base_score_config').val();
                base_score_config = base_score_config === '' ? '{}' : base_score_config;
                params.base_score_config = JSON.parse(base_score_config)
                var model_settings = $('#textarea_other_settings_formulas').val();
                model_settings = model_settings === '' ? '{}' : model_settings;
                params.settings = JSON.parse(model_settings)
                data.parameters = params;
                return data;
            },
            saveModel: function(clicked) {
                var that = this;
                var $clicked = $(clicked);
                var type = 'add';
                var model_id = false;
                var data = this.retreiveData();
                if ($clicked.data('isedit') == 1) {
                    type = 'edit';
                    model_id = $clicked.data('modelid');
                }
                this.fetchFormAndSubmit($clicked, type, model_id, data, undefined, function(data) {
                    that.registerMapping(data.data.DecayingModel.id);
                });
            },
            enableModel: function(clicked, model_id) {
                this.fetchFormAndSubmit($(clicked), 'enable', model_id, {});
            },
            disableModel: function(clicked, model_id) {
                this.fetchFormAndSubmit($(clicked), 'disable', model_id, {});
            },
            fetchFormAndSubmit: function($clicked, action, model_id, formData, baseurl, callback) {
                var that = this;
                baseurl = baseurl === undefined || '' ? "/decayingModel/" : baseurl;
                var url = baseurl;
                if (action == "add") {
                    url += action;
                } else {
                    url += action + "/" + model_id;
                }
                var loadingSpan = '<span id="loadingSpan" class="fa fa-spin fa-spinner" style="margin-left: 5px;"></span>';

                $.get(url, function(data) {
                    var $confbox = $("#confirmation_box");
                    $confbox.html(data);
                    var $form = $confbox.find('form');
                    var post_url = $form.attr('action');
                    if (baseurl.includes('decayingModelMapping')) {
                        that.injectDataAttributeTypes($form, formData);
                    } else if (action.includes('able')) { // if enable/disable model
                        // do nothing, form filled already
                    } else {
                        that.injectDataModel($form, formData);
                    }
                    $.ajax({
                        data: $form.serialize(),
                        cache: false,
                        beforeSend: function(XMLHttpRequest) {
                            if ($clicked !== undefined) {
                                $clicked.append(loadingSpan);
                            }
                        },
                        success: function(data, textStatus) {
                            if (baseurl.includes('decayingModelMapping')) {
                                showMessage('success', 'Mapping has been saved');
                                that.refreshTypeMappingTable(model_id);
                                var updated_data = that.quickModelDataUpdate(model_id, {'attribute_types': data});
                                that.refreshRow({ data: updated_data, action: 'edit'});
                                if (callback !== undefined) {
                                    callback();
                                }
                            } else {
                                showMessage('success', 'Model has been saved');
                                that.refreshRow(data);
                                if (callback !== undefined) {
                                    callback(data);
                                }
                            }
                        },
                        error: function( jqXhr, textStatus, errorThrown ){
                            showMessage('fail', 'Error while saving');
                            console.log( errorThrown );
                        },
                        complete: function() {
                            if ($clicked !== undefined) {
                                $clicked.find('#loadingSpan').remove();
                            }
                            $form.remove();
                        },
                        type: 'post',
                        url: post_url
                    });
                });
            },
            registerMapping: function(model_id) {
                var selected_types = this.getSelected();
                var data = { 'attributetypes': selected_types };
                this.fetchFormAndSubmit(undefined, 'linkAttributeTypeToModel', model_id, data, "/decayingModelMapping/");
            },
            highlightMatchingRow: function() {
                var that = this;
                var data = $.extend({}, this.retreiveData());;
                delete data['name'];
                delete data['description'];
                var $rows = $('#table-model-body > tr');
                $rows.removeClass('success');
                $('div.input-prepend > span.param-name, #summary_base_score_config').removeClass('success');
                $('#button-toggle-simulation').addClass('disabled').attr('href', '/decayingModel/decayingToolSimulation/');
                var match_detected = false;
                $rows.each(function(i) {
                    var model = $.extend({}, d3.select(this).data()[0].DecayingModel);
                    var model_id = model['id'];
                    delete model['id'];
                    delete model['name'];
                    delete model['description'];
                    var current_match = that.simpleCompareObject(data, model);
                    match_detected =  match_detected || current_match;
                    if (current_match) {
                        $('#button-toggle-simulation').removeClass('disabled').attr('href', '/decayingModel/decayingToolSimulation/' + model_id);
                        $('#saveForm #save-model-button').data('modelid', model_id);
                        $(this).addClass('success');
                        $('div.input-prepend > span.param-name, #summary_base_score_config').addClass('success');
                    }
                });
                return match_detected;
            },
            refreshRow: function(data) {
                // search and replace matching row if any
                var models = this.model_table.savedDecayingModels.slice(0);
                if (data.action == 'edit' || data.action == 'enable' || data.action == 'disable') {
                    models.forEach(function(model, i) {
                        if (model.DecayingModel.id == data.data.DecayingModel.id) {
                            models[i].DecayingModel = data.data.DecayingModel;
                        }
                    });
                } else {
                    models.push({DecayingModel: data.data.DecayingModel});
                }
                this.model_table.update(models);
                this.highlightMatchingRow();
            },
            quickModelDataUpdate: function(model_id, dico_override) {
                var $row = $('#table-model-body > #modelId_' + model_id);
                var model = $.extend({}, d3.select($row[0]).data()[0]);
                Object.keys(dico_override).forEach(function(k) {
                    model.DecayingModel[k] = dico_override[k];
                });
                return model;
            },

            applyBaseScore: function(taxonomy_config, base_score_default_value) {
                $('#input_base_score_config').val(JSON.stringify(taxonomy_config));
                $('#input_default_base_score').val(base_score_default_value);
                if (Object.keys(taxonomy_config).length > 0 || $('#input_default_base_score').val() > 0) {
                    $('#summary_base_score_config > span').removeClass('fa-square').addClass('fa-check-square');
                } else {
                    $('#summary_base_score_config > span').removeClass('fa-check-square').addClass('fa-square');
                }
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
                    $body.find('tr').forceClass('hidden', true);
                    // show only matching elements
                    var $cells = $table.find('tbody > tr > td.isFilteringField');
                    $cells.each(function() {
                        if ($(this).text().trim().toUpperCase().indexOf(searchString.toUpperCase()) != -1) {
                            $(this).parent().filter('tr.isNotToIDS').forceClass('hidden', !$('#table_toggle_all_type').is(':checked'));
                            $(this).parent().filter('tr.isObject').forceClass('hidden', !$('#table_toggle_objects').is(':checked'));
                            $(this).parent().filter('tr:not(".isObject, .isNotToIDS")').forceClass('hidden', false);
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
                if (isNaN(model_id)) { // ensure model_id to be a number
                    return;
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
                $.getJSON(baseurl + '/decayingModelMapping/viewAssociatedTypes/' + model_id, function(j) {
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
                var threshold = parseInt($('#input_threshold').val());
                $('#infoCellHalved').text(this.daysToText(this.getReverseScore((100-threshold)/2 + threshold)));
                $('#infoCellExpired').text(this.daysToText(this.getReverseScore(threshold)));
                var base_score_config = JSON.parse($('#input_base_score_config').val());
                if (Object.keys(base_score_config).length > 0 || $('#input_default_base_score').val() > 0) {
                    $('#summary_base_score_config > span').removeClass('fa-square').addClass('fa-check-square');
                } else {
                    $('#summary_base_score_config > span').removeClass('fa-check-square').addClass('fa-square');
                }
                this.highlightMatchingRow()
            },
            refreshSaveButton: function() {
                var $checkbox = $('#table-model td > span.DMCheckbox > input:checked');
                var save_button = $('#saveForm #save-model-button');
                var btn_content_html;
                var selected_model = d3.select($checkbox.closest('tr')[0]).data()[0];
                if ($checkbox.length > 0) {
                    if (!selected_model.DecayingModel.isEditable) {
                        save_button.data('isedit', 0).data('modelid', 0).removeClass('btn-warning').addClass('btn-success');
                        btn_content_html = '<i class="fa fa-plus"> ' + save_button.data('savetext');
                    } else {
                        save_button.data('isedit', 1).removeClass('btn-success').addClass('btn-warning');
                        btn_content_html = '<i class="fa fa-edit"> ' + save_button.data('edittext');
                    }
                } else {
                    save_button.data('isedit', 0).data('modelid', 0).removeClass('btn-warning').addClass('btn-success');
                    btn_content_html = '<i class="fa fa-plus"> ' + save_button.data('savetext');
                }
                save_button.html(btn_content_html);
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
            injectDataModel: function($form, data) {
                $form.find('#DecayingModelName').val(data.name);
                $form.find('#DecayingModelDescription').val(data.description);
                $form.find('#DecayingModelFormula').val(data.formula);
                $form.find('#DecayingModelParametersLifetime').val(data.parameters.lifetime);
                $form.find('#DecayingModelParametersDecaySpeed').val(data.parameters.decay_speed);
                $form.find('#DecayingModelParametersThreshold').val(data.parameters.threshold);
                $form.find('#DecayingModelParametersDefaultBaseScore').val(data.parameters.default_base_score);
                $form.find('#DecayingModelParametersBaseScoreConfig').val(JSON.stringify(data.parameters.base_score_config));
                $form.find('#DecayingModelParametersSettings').val(JSON.stringify(data.parameters.settings));
            },
            injectDataAttributeTypes: function($form, data) {
                $form.find('#DecayingModelMappingAttributetypes').val(JSON.stringify(data.attributetypes));
            },
            simpleCompareObject: function(obj1, obj2) { // recursively compare object equality on their value
                var flag_same = true;
                var objectKeys = Object.keys(obj1);
                for (var i = 0; i < objectKeys.length; i++) {
                    var k = objectKeys[i];
                    var v1 = obj1[k];
                    var v2 = obj2[k];

                    if (
                        (v1 instanceof Object && v2 instanceof Object) &&
                        (!Array.isArray(v1) && !Array.isArray(v2))
                    ) {
                        flag_same = this.simpleCompareObject(v1, v2);
                    } else if ( (v1 instanceof Object) && !(v2 instanceof Object) || (!(v1 instanceof Object) && (v2 instanceof Object))) {
                        return false;
                    } else if (Array.isArray(v1) && Array.isArray(v2)) {
                        flag_same = this.simpleCompareObject(v1, v2);
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
                    inst = $this.data('decayingTool');
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

    $('#summary_base_score_config').tooltip({
        html: true,
        placement: 'right',
        title: function() {
            var bs_config = $('#input_base_score_config').val();
            var bs_default = $('#input_default_base_score').val();
            if ((bs_config === '' || bs_config === '[]') && bs_default == 0) {
                return 'No tuning done yet';
            } else {
                bs_config = JSON.parse(bs_config);
            }
            var html_table = '<table style="text-align: left;"><thead><tr><th>Taxonomy</th><th>%</th></tr></thead><tbody></tbody></table>';
            if (bs_default > 0 && bs_config.length == 0) {
                return 'Default base score = ' + bs_default;
            } else if (bs_default > 0) {
                html_table = $('<div></div>').text('Default base score = ' + bs_default)[0].outerHTML + html_table;
            }
            var $title = $(html_table).find('tbody');
            Object.keys(bs_config).forEach(function(k, i) {
                var value = bs_config[k];
                var $td1 = $('<td></td>').css({'padding-right': '5px'}).text(k);
                var $td2 = $('<td></td>').text((value * 100).toFixed(1));
                $title.append(
                    $('<tr></tr>').append($td1).append($td2)
                );
            })
            var to_return = $title.parent()[0].outerHTML;
            if (bs_default) {
                to_return = $('<b></b>').text('Default base score = ' + bs_default)[0].outerHTML + '</br>' + to_return;
            }
            return to_return;
        }
    });
});


var ModelTable = function(container, options) {
    var default_options = {
        animation_short_duration: 400
    };
    this.options = $.extend(true, {}, default_options, options);
    this._init();
};

ModelTable.prototype = {
    constructor: ModelTable,

    _init: function() {
        this.$table = $('#table-model');
        this.thead = d3.select('#table-model > #table-model-head');
        this.tbody = d3.select('#table-model > #table-model-body');
        this.table_header = [
            {name: ''},
            {name: 'ID'},
            {name: 'Model Name'},
            {name: 'Org ID'},
            {name: 'Description'},
            {name: 'Formula'},
            {name: 'Parameters',
                children: [
                    {name: 'Lifetime'},
                    {name: 'Decay speed'},
                    {name: 'Threshold'},
                    {name: 'Default basescore'},
                    {name: 'Basescore config'},
                    {name: 'Settings'}
                ]
            },
            {name: '# Types'},
            {name: 'Enabled'},
            {name: 'Action'}
        ];
        this.data = [];
        this.thead.html(this._get_html_header(this.table_header));

        // bind listener on radio filters
        var that = this;
        $('.tableRadioFilterOptionsContainer input[type=\'radio\']').change(function() {
            that.refreshTable();
        });
    },

    update: function(data) {
        this.savedDecayingModels = this.massage_data(data);
        this._draw();
    },

    refreshTable: function(data) {
        var that = this;
        var $filter_radio = $('.tableRadioFilterOptionsContainer input[type=\'radio\']:checked');
        var filters = {};
        if ($filter_radio) {
            filters[$filter_radio.val()] = 1;
        }
        $.getJSON(baseurl + '/decayingModel/getAllDecayingModels/', filters, function(json) {
            that.update(json);
        });
    },

    massage_data: function(data) {
        var massaged_data = $.extend([], data);
        
        data.forEach(function(model, i) {
            if (model.DecayingModel.parameters.settings === undefined) {
                massaged_data[i].DecayingModel.parameters.settings = {};
            }
        });
        return massaged_data;
    },

    get_depth: function(header, current_depth, max_depth) {
        var that = this;
        if (header !== null && typeof header == "object" ) {
            Object.keys(header).forEach(function(key, i) {
                var current_entry = header[key];
                if (current_entry.children !== undefined) {
                    var children_depth = that.get_depth(current_entry.children, current_depth+1, max_depth);
                    max_depth = max_depth > children_depth ? max_depth : children_depth;
                } else {
                    max_depth = max_depth > current_depth ? max_depth : current_depth;
                }
            });
        }
        return max_depth;
    },

    // max depth = 2, max children block = 1
    _get_html_header: function(header, no_tr_embedding) {
        var that = this;
        var header_max_depth = this.get_depth(header, 0, 0);
        var tr_html = no_tr_embedding ? '' : '<tr>';
        var sub_tr_html = '<tr>';
        Object.keys(header).forEach(function(key, i) {
            var col = header[key];
            var th_html;
            if (col.children !== undefined) {
                th_html = $('<th colspan="' + (col.children.length) + '"></th>').text(col.name)[0].outerHTML;
                sub_tr_html += that._get_html_header(col.children, true);
            } else {
                th_html = $('<th rowspan="' + (header_max_depth+1) + '"></th>').text(col.name)[0].outerHTML;
            }
            tr_html += th_html;
        });
        sub_tr_html += '</tr>';
        tr_html += no_tr_embedding ? '' : '</tr>';
        return tr_html + (sub_tr_html.length > 9 ? sub_tr_html : '');
    },

    _gen_td: function(html, td_class, html_attributes) {
        var $span = $('<span></span>');
        td_class = td_class !== undefined ? td_class : '';
        $span.addClass(td_class);
        if (html_attributes !== undefined) {
            Object.keys(html_attributes).forEach(function(k) {
                $span.data(k, html_attributes[k]);
            });
        }
        $span.html(html !== undefined ? html : '');
        return $span[0].outerHTML;
    },
    _gen_td_link: function(url, html, td_class) {
        var $span = $('<span></span>');
        td_class = td_class !== undefined ? td_class : '';
        $span.addClass(td_class);
        $span.append(
            $('<a></a>').attr('href', url).html(html !== undefined ? html : '')
        )
        return $span[0].outerHTML;
    },
    _gen_td_buttons: function(model) {
        var html_button = '<div style="width: max-content">';
        html_button += '<button class="btn btn-info btn-small decayingLoadBtn" onclick="decayingTool.loadModel(this);"><span class="fa fa-line-chart"> Load model</span></button>';
        if (model.DecayingModel.isEditable) {
            if (isNaN(model.DecayingModel.id)) { // enforce id to be a number
                return;
            }
            if (model.DecayingModel.enabled) {
                html_button += '<button class="btn btn-danger btn-small" style="margin-left: 3px;" onclick="decayingTool.disableModel(this, ' + model.DecayingModel.id + ');" title="Disable model"><span class="fa fa-pause"></span></button>'
            } else {
                html_button += '<button class="btn btn-success btn-small" style="margin-left: 3px;" onclick="decayingTool.enableModel(this, ' + model.DecayingModel.id + ');" title="Enable model"><span class="fa fa-play"></span></button>'
            }
        }
        html_button += '</div>';
        return html_button;
    },

    _get_html_cells: function(model) {
        var bs_config_html = '';
        if (!Array.isArray(model.DecayingModel.parameters.base_score_config) && typeof model.DecayingModel.parameters.base_score_config === 'object') {
            bs_config_html = jsonToNestedTable(model.DecayingModel.parameters.base_score_config, [], ['table', 'table-condensed', 'table-bordered']);
        }
        var settings_html = '';
        if (!Array.isArray(model.DecayingModel.parameters.settings) && typeof model.DecayingModel.parameters.settings === 'object') {
            settings_html = jsonToNestedTable(model.DecayingModel.parameters.settings, [], ['table', 'table-condensed', 'table-bordered']);
        }
        var is_row_selected = $('#saveForm #save-model-button').data('modelid') == model.DecayingModel.id;
        return cells_html = [
            this._gen_td('<input type="checkbox" onchange="decayingTool.refreshSaveButton()" style="margin:0" ' + (is_row_selected ? 'checked' : 'disabled') + '>', 'DMCheckbox'),
            this._gen_td_link('/decayingModel/view/'+model.DecayingModel.id, this._h(model.DecayingModel.id), 'DMId'),
            this._gen_td(
                this._h(model.DecayingModel.name) + (model.DecayingModel.default ? '<img src="/img/orgs/MISP.png" width="24" height="24" style="padding-bottom:3px;" title="Default Model from MISP Project" />' : '') ,
                'DMName'
            ),
            this._gen_td_link('/organisations/view/'+model.DecayingModel.org_id, this._h(model.DecayingModel.org_id), 'DMOrg'),
            this._gen_td(this._h(model.DecayingModel.description), 'DMNDescription'),
            this._gen_td(this._h(model.DecayingModel.formula), 'DMFormula'),
            this._gen_td(this._h(model.DecayingModel.parameters.lifetime), 'DMParameterLifetime'),
            this._gen_td(this._h(model.DecayingModel.parameters.decay_speed), 'DMParameterDecay_speed'),
            this._gen_td(this._h(model.DecayingModel.parameters.threshold), 'DMParameterThreshold'),
            this._gen_td(this._h(model.DecayingModel.parameters.default_base_score), 'DMParameterDefaultBasescore'),
            this._gen_td(
                bs_config_html,
                'DMParameterBasescoreConfig',
                {'basescoreconfig': btoa(JSON.stringify(model.DecayingModel.parameters.base_score_config))}
            ),
            this._gen_td(
                settings_html,
                'DMSettings',
                {'basescoreconfig': btoa(JSON.stringify(model.DecayingModel.parameters.settings))}
            ),
            this._gen_td(model.DecayingModel.attribute_types.length, 'DMNumType'),
            this._gen_td(model.DecayingModel.enabled ? '<i class="fa fa-check"></i>' : '<i class="fa fa-times"></i>', 'DMEnabled'),
            this._gen_td_buttons(model)
        ];
    },

    _draw: function() {
        var that = this;

        // create a row for each object in the data
        var rows = this.tbody.selectAll('#table-model-body > tr')
            .data(this.savedDecayingModels);
        rows.enter()
            .append('tr')
            .attr('id', function(d, row_i) {
                return 'modelId_' + d.DecayingModel.id;
            });
        rows.exit().remove();

        // create a cell in each row for each column
        var cells = rows.selectAll('#table-model-body > tr > td')
            .data(function (model, row_i) {
                var html_cell = that._get_html_cells(model);
                return html_cell;
            });
        cells.enter()
            .append('td');
        cells.html(function (e) { return e; })
            .style('opacity', 0.0)
            .transition()
            .duration(this.options.animation_short_duration)
            .style('opacity', 1.0);
    },

    _h: function(text) {
        return $('<div>').text(text).html();
    }
}
