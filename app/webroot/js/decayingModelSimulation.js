(function(factory) {
        "use strict";
        if (typeof define === 'function' && define.amd) {
            define(['jquery'], factory);
        } else if (window.jQuery && !window.jQuery.fn.DecayingSimulation) {
            factory(window.jQuery);
        }
    }

    (function($) {
        'use strict';

        var DecayingSimulation = function(container, options, data) {
            this.container_id = '#' + container.id;
            this.$container = $(container);
            this._validateOptions(options);
            var default_options = {
                tick_num: 300,
                margin: {top: 10, right: 10, bottom: 35, left: 35},
                animation_duration: 250,
                animation_short_duration: 100,
                redraw_timeout: 200,
                time_format: '%Y-%m-%d %H:%M:%S'
            };
            this.options = $.extend(true, {}, default_options, options);
            this.chart_data = [];
            this.sightings = [];
            this._init();
            this._init_canvas();
            if (data !== undefined) {
                this.update(data)
            }
        };

        DecayingSimulation.prototype = {
            constructor: DecayingSimulation,

            _validateOptions: function(options) {

            },
            _init: function() {
                var that = this;
                this.$loadingContainer = $('<div id="loadingSimulationContainer" style="background: #ffffff9f"><span class="fa fa-spinner fa-spin" style="font-size: xx-large;"></span></div>').css({
                    position: 'absolute',
                    left: '0',
                    right: '0',
                    top: '0',
                    bottom: '0',
                    display: 'flex',
                    'align-items': 'center',
                    'justify-content': 'center'
                }).hide();
                this.tooltip_container = d3.select('body').append('div')
                    .classed('tooltip', true)
                    .style('opacity', 0)
                    .style('padding', '3px')
                    .style('background-color', '#000')
                    .style('color', 'white')
                    .style('border-radius', '5px')
                    .style('display', 'none');
                this.$container.append(this.$loadingContainer);
                this.timeFormatter = d3.time.format(this.options.time_format).parse;
            },

            _init_canvas: function() {
                var that = this;
                this.$container.empty();
                this.svg_width = this.$container.width();
                this.svg_height = this.$container.height();
                this.width = this.svg_width - this.options.margin.left - this.options.margin.right;
                this.height = this.svg_height - this.options.margin.top - this.options.margin.bottom;

                this.x = d3.time.scale()
                    .domain(d3.extent(this.chart_data, function(d) { return d.date; }))
                    .range([ 0, this.width ]);
                this.y = d3.scale.linear()
                    .domain([0, 100])
                    .range([ this.height, 0 ]);

                this.yGrid = d3.svg.axis().scale(this.x).orient("bottom")
                    .tickSize(-this.height)
                    .tickFormat("");
                this.xGrid = d3.svg.axis().scale(this.y).orient("left")
                    .ticks(3)
                    .tickSize(-this.width)
                    .tickFormat("");

                this.value_line = d3.svg.line()
                    .x(function(d) { return that.x(d.date); })
                    .y(function(d) { return that.y(d.value); });

                this.svg = d3.select(this.container_id)
                    .append("svg")
                    .classed('svg-content-responsive', true)
                    .attr("width", this.svg_width)
                    .attr("height", this.svg_height)
                    .append("g")
                    .attr("transform", "translate(" + this.options.margin.left + "," + this.options.margin.top + ")");

                this.svg.append("g")
                    .attr('class', 'decayingGraphAxis axis-x')
                    .attr("transform", "translate(0," + this.height + ")")
                this.svg.append("g")
                    .attr('class', 'decayingGraphAxis axis-y')

                this.svg.append("g")
                    .attr("class", "decayingGraphAxis grid grid-x");
                this.svg.append("g")
                    .attr("class", "decayingGraphAxis grid grid-y")
                    .attr("transform", "translate(0," + this.height + ")");

                this.svg.append("text")
                    .classed('axis-label', true)
                    .attr("text-anchor", "end")
                    .attr("x", this.width / 2)
                    .attr("y", this.height)
                    .attr("dy", '30px')
                    .text("Date");

                this.svg.append("text")
                    .classed('axis-label', true)
                    .attr("text-anchor", "middle")
                    .attr("transform", "rotate(-90 0 " + this.height / 2 + ")")
                    .attr("x", 0)
                    .attr("dy", '-25px')
                    .attr("y", this.height / 2)
                    .text("Score");

                this.svg.append('g')
                    .classed('line-group', true);

                this.svg
                    .append("g")
                    .classed("d3-line-guides-group", true);

                this.svg.insert('g')
                    .classed('circles', true);

                window.addEventListener("resize", function() {
                    if (that.resize_timeout !== undefined) {
                        clearTimeout(that.resize_timeout);
                    }
                    that.resize_timeout = setTimeout(function() { that.redraw_timeout_handler(that) }, that.options.redraw_timeout);
                });
            },

            redraw_timeout_handler: function(inst) {
                clearTimeout(inst.resize_timeout);
                inst._init_canvas();
                inst._draw();
            },

            update: function(data, model) {
                this.raw_data = data;
                this.chart_data = data.csv;
                this.sightings = data.sightings;
                this.current_score = data.current_score;
                this.model = model;
                this._parseDataset();
                this._draw();
            },

            _draw: function() {
                var that = this;
                this.x.domain(d3.extent(this.chart_data, function(d) { return d.date; }))

                this.xAxis = this.svg.select('.axis-x')
                    .call(d3.svg.axis().scale(this.x).orient('bottom'));
                this.yAxis = this.svg.select('.axis-y')
                    .call(d3.svg.axis().scale(this.y).orient("left"));

                this.svg.select('.grid-x')
                    .call(this.xGrid);
                this.svg.select('.grid-y')
                    .call(this.yGrid);

                this.line = this.svg.select('.line-group')
                    .selectAll('.line')
                    .data([this.chart_data]);
                this.line
                    .enter()
                    .append('path')
                    .attr("class","line")
                    .attr("fill", "none")
                    .attr("stroke", "steelblue")
                    .attr("stroke-width", 2.5)
                this.line
                    .transition()
                    .duration(this.options.animation_duration)
                    .attr("d", this.value_line);
                this.line.exit().remove();

                this.line_guides = this.svg
                    .select('.d3-line-guides-group')
                    .selectAll('.d3-line-guides')
                    .data(this.sightings_data);
                this.line_guides
                    .enter()
                    .append('line')
                    .attr('class', 'd3-line-guides')
                this.line_guides // Update
                    .attr('x1', function(d) { return that.x(d.date); })
                    .attr('y1', function(d) { return that.height; })
                    .attr('x2', function(d) { return that.x(d.date); })
                    .attr('y2', function(d) { return that.height; })
                    .style("stroke", "rgba(70, 130, 180, 0.5)")
                    .style("stroke-dasharray", "4,2")
                    .style("shape-rendering", "crispEdges")
                    .transition()
                    .duration(this.options.animation_duration)
                    .attr('y2', function(d) { return that.y(d.value); });
                this.line_guides.exit().remove();

                // current time
                this.line_guide_now = this.svg
                    .selectAll('.d3-line-now')
                    .data([new Date()]);
                this.line_guide_now
                    .enter()
                    .append('line')
                    .attr('class', 'd3-line-now')
                this.line_guide_now
                    .attr('x1', function(d) { return that.x(d); })
                    .attr('y1', function(d) { return that.y(0); })
                    .attr('x2', function(d) { return that.x(d); })
                    .attr('y2', function(d) { return that.y(101); })
                    .style("stroke", "#000")
                    .attr("stroke-width", 2)
                    .on('mouseover', function(d) {
                        that.tooltipText(true, this, d3.time.format("%e %B @ %H:%M")(new Date()));
                    })
                    .on('mouseout', function() {
                        that.tooltipText(false);
                    });
                this.line_guide_now.exit().remove();
                this.carret_line_guide_now = this.svg
                    .selectAll('.carret-time-now')
                    .data([new Date()]);
                this.carret_line_guide_now
                    .enter()
                    .append('text')
                    .attr('class', 'carret-time-now')
                this.carret_line_guide_now
                    .attr('x', that.x(new Date())-5.5)
                    .attr('y', that.y(99))
                    .attr('font-family', 'FontAwesome')
                    .attr('font-size', '20px')
                    .text(function(d) { return '\uf0d7' });
                this.carret_line_guide_now.exit().remove();

                this.svg.append('rect')
                    .attr('class', 'decayingGraphAreaThres')
                    .style('opacity', 0.6)
                    .attr('x', 0)
                    .attr('y', this.height)
                    .attr('width', this.width)
                    .attr('height', 0)
                    .on('mouseover', function(d) {
                        d3.select(this).transition()
                            .duration(that.options.animation_duration)
                            .style('opacity', 0.9)
                        that.tooltipText(true, this, 'Cutoff threshold: <b>' + that.model.parameters.threshold + '</b>');
                    })
                    .on('mouseout', function() {
                        d3.select(this).transition()
                            .duration(that.options.animation_duration)
                            .style('opacity', 0.6)
                        that.tooltipText(false);
                    });
                this.svg.select('.decayingGraphAreaThres')
                    .transition()
                    .duration(this.options.animation_duration)
                    .attr('height', this.height-this.y(this.model.parameters.threshold))
                    .attr('y', this.y(this.model.parameters.threshold));

                this.points = this.svg
                    .selectAll('.d3-line-circle')
                    .data(this.sightings_data);
                this.points
                    .enter()
                    .append('circle')
                    .attr('class', 'decayingGraphHandleDot useCursorPointer d3-line-circle');
                this.points // Update
                    .attr('cx', function (d) { return that.x(d.date); })
                    .attr('cy', function (d) { return that.y(d.value); })
                    .attr('r', 5)
                    .on('mouseover', function(d) {
                        d3.select(this).transition()
                            .duration(that.options.animation_duration)
                            .attr('r', 7);
                        that.tooltipDate(true, this, d);
                    })
                    .on('mouseout', function() {
                        d3.select(this).transition()
                            .duration(that.options.animation_duration)
                            .attr('r', 5);
                        that.tooltipDate(false);
                    })
                    .style('opacity', 0)
                    .transition()
                    .duration(this.options.animation_duration)
                    .delay(this.options.animation_duration)
                    .ease('linear')
                    .style('opacity', 1);
                this.points.exit().remove();

                // current score
                this.current_score_target = this.svg
                    .selectAll('.current-score-target')
                    .data([new Date()]);
                this.current_score_target
                    .enter()
                    .append('circle')
                    .classed('useCursorPointer current-score-target', true);
                this.current_score_target
                    .attr('cx', that.x(new Date()))
                    .attr('cy', that.y(this.current_score))
                    .attr('fill', 'white')
                    .attr('stroke', 'black')
                    .attr('stroke-width', 2)
                    .attr('r', 6);
                this.current_score_target = this.svg
                    .selectAll('.current-score-target-center')
                    .data([new Date()]);
                this.current_score_target
                    .enter()
                    .append('circle')
                    .classed('useCursorPointer current-score-target-center', true);
                this.current_score_target
                    .attr('cx', that.x(new Date()))
                    .attr('cy', that.y(this.current_score))
                    .attr('stroke', 'black')
                    .attr('r', 2);
                d3.selectAll('.current-score-target, .current-score-target-center')
                    .on('click', function(d) {
                        $('#simulation-current-score').parent().children().effect('highlight');
                    });

            },

            toggleLoading: function(state) {
                if (state === undefined) {
                    this.$loadingContainer.toggle();
                } else if(state) {
                    this.$loadingContainer.show();
                } else {
                    this.$loadingContainer.hide();
                }
                this.$container;
            },

            tooltipDate: function(show, d3Element, datum) {
                var that = this;
                var tooltip = this._toggleTooltip(show, d3Element);
                if (show) {
                    tooltip.html(this._generate_tooltip(datum));
                }
            },

            tooltipText: function(show, d3Element, html) {
                var that = this;
                var tooltip = this._toggleTooltip(show, d3Element);
                if (show) {
                    tooltip.html(html);
                }
            },

            _toggleTooltip: function(show, d3Element) {
                var that = this;
                if (show) {
                    var bb_rect = d3.select(d3Element)[0][0].getBoundingClientRect();
                    var cx = bb_rect.left;
                    var cy = bb_rect.top;
                    this.tooltip_container
                        .style('display', 'block')
                        .style('left', (cx + 17) + 'px')
                        .style('top', (cy - 6) + 'px')
                        .transition()
                        .duration(that.options.animation_short_duration)
                        .delay(that.options.animation_short_duration/2)
                        .style('opacity', '0.7');
                } else {
                    this.tooltip_container.transition()
                        .duration(this.options.animation_short_duration)
                        .style('opacity', 0)
                        .delay(this.options.animation_short_duration)
                        .style('display', 'none');
                }
                return this.tooltip_container;
            },

            _generate_tooltip: function(datum) {
                var formated_date = d3.time.format("%e %B @ %H:%M")(datum.date);
                var html = 'Sighting on ' + formated_date + ' by ' + datum.org;
                return html;
            },

            _parseDataset: function() {
                var that = this;
                if (typeof this.chart_data === 'string') {
                    this.chart_data = d3.csv.parse(this.chart_data, function(d){
                        var parsed_date = that.timeFormatter(d.date);
                        return { timestamp: Math.floor(parsed_date.getTime() / 1000), date: parsed_date, value : parseFloat(d.value) }
                    });
                } else if (Array.isArray(this.chart_data)){
                    this.chart_data.forEach(function(entry, i) {
                        that.chart_data[i].date = that.timeFormatter(entry.date);
                    })
                }
                this.sightings_data = this.sightings.map(function(d) {
                    var sighting = d.Sighting;
                    var res = { timestamp: sighting.rounded_timestamp, date: new Date(sighting.rounded_timestamp*1000), value : that.raw_data.base_score_config.base_score };
                    res['org'] = d.Organisation !== undefined ? d.Organisation.name : '?';
                    return res;
                });
            }
        }

        $.DecayingSimulation = DecayingSimulation;
        $.fn.decayingSimulation = function(options) {
            var pickedArgs = arguments;

            var $elements = this.each(function() {
                var $this = $(this),
                    inst = $this.data('DecayingSimulation');
                options = ((typeof options === 'object') ? options : {});
                if ((!inst) && (typeof options !== 'string')) {
                    $this.data('DecayingSimulation', new DecayingSimulation(this, options));
                } else {
                    if (typeof options === 'string') {
                        inst[options].apply(inst, Array.prototype.slice.call(pickerArgs, 1));
                    }
                }
            });
            return $elements.length == 1 ? $elements.data('DecayingSimulation') : $elements;
        };

        $.fn.decayingSimulation.constructor = DecayingSimulation;
    })
);


(function(factory) {
        "use strict";
        if (typeof define === 'function' && define.amd) {
            define(['jquery'], factory);
        } else if (window.jQuery && !window.jQuery.fn.BasescoreComputationTable) {
            factory(window.jQuery);
        }
    }

    (function($) {
        'use strict';

        var BasescoreComputationTable = function(container, options, data) {
            this.container_id = '#' + container.id;
            this.$container = $(container);
            this._validateOptions(options);
            var default_options = {
                animation_duration: 250,
            };
            this.options = $.extend(true, {}, default_options, options);
            this._init();
            if (data !== undefined) {
                this.update(data)
            }
        };

        BasescoreComputationTable.prototype = {
            constructor: BasescoreComputationTable,

            _validateOptions: function(options) {

            },
            _init: function() {
                var that = this;
                this.$loadingContainer = $('<div id="loadingSimulationContainer" style="background: #ffffff9f"><span class="fa fa-spinner fa-spin" style="font-size: xx-large;"></span></div>').css({
                    position: 'absolute',
                    left: '0',
                    right: '0',
                    top: '0',
                    bottom: '0',
                    display: 'flex',
                    'align-items': 'center',
                    'justify-content': 'center'
                }).hide();
                this.tooltip_container = d3.select('body').append('div')
                    .classed('tooltip', true)
                    .style('opacity', 0)
                    .style('padding', '3px')
                    .style('background-color', '#000')
                    .style('color', 'white')
                    .style('border-radius', '5px')
                    .style('display', 'none');
                this.$container.append(this.$loadingContainer);
                $('#basescore-simulation-container #pick_notice').remove();
            },

            update: function(data, model) {
                this.base_score_config = data.base_score_config;
                this.base_score = data.base_score_config.base_score;
                this.tags = data.base_score_config.tags;
                this.overriddenTags = data.base_score_config.overridden;
                this._draw();
            },

            _create_all_tag_html: function(tag) {
                var that = this;
                if (tag !== false) {
                    var html_tag = this._create_tag_html(tag);
                    var overridden_html = '';
                    var namespace_predicate = tag.Tag.name.split('=')[0];
                    this.overriddenTags.forEach(function(entry) {
                        var cur_namespace_predicate = entry.AttributeTag.Tag.name.split('=')[0];
                        if (namespace_predicate == cur_namespace_predicate) {
                            overridden_html += '<div class="overriden_tag_wrapper" style="filter: grayscale(80%);">' + that._create_tag_html(entry.EventTag) + '</div>';
                        }
                    });
                    if (overridden_html !== '') {
                        return '<div style="position:relative;" class="useCursorPointer overridden_tags_container">'
                            + overridden_html
                            + '<div class="attribute_tag_wrapper" style="top:-12px;margin-bottom:-12px; left:4px;margin-right:-4px; float: left;  position: relative;">' + html_tag + '</div>'
                        + '</div>';
                    } else {
                        return html_tag;
                    }
                } else { // last row
                    return '<span style="border-radius: 4px; border: 1px solid #ccc; background-color: #eeeeee; padding: 4px 5px;">base_score</span>';
                }
            },
            _create_tag_html: function(tag) {
                if (tag !== false) {
                    var $span = $('<span></span>');
                    $span.addClass('tag')
                        .css({
                            'white-space': 'nowrap',
                            'background-color': tag.Tag.colour,
                            'color': getTextColour(tag.Tag.colour)
                        })
                        .text(tag.Tag.name);
                    return $span[0].outerHTML;
                } else { // last row
                    return '<span style="border-radius: 4px; border: 1px solid #ccc; background-color: #eeeeee; padding: 4px 5px;">base_score</span>';
                }
            },

            _get_computation_step: function(tag) {
                if (tag === false) {
                    return ['', '', '', this.base_score.toFixed(2)];
                }
                var namespace = tag.Tag.name.split('=')[0];

                if (this.base_score_config.taxonomy_effective_ratios[namespace] !== undefined) {
                    var html1 = this.base_score_config.taxonomy_effective_ratios[namespace].toFixed(2);
                    var html4 = (parseFloat(tag.Tag.numerical_value) * this.base_score_config.taxonomy_effective_ratios[namespace]).toFixed(2);
                } else {
                    var html1 = '0';
                    var html4 = '0';
                }
                var html2 = '<it class="fa fa-times" style=""></it>';
                var html3 = parseFloat(tag.Tag.numerical_value).toFixed(2);
                return [html1, html2, html3, html4];
            },

            _draw: function() {
                var that = this;
                $('#basescore-simulation-container #computation_help_container_body').empty();
                var	tbody = d3.select('#basescore-simulation-container #computation_help_container_body');

                // create a row for each object in the data
                var rows = tbody.selectAll('tr')
                    .data(this.tags.concat(false))
                    .enter()
                    .append('tr')
                    .attr('class', function(e, row_i) {
                        if (that.tags.length == row_i) {
                            return 'cellHeavyTopBorder bold';
                        }
                    });

                // create a cell in each row for each column
                var cells = rows.selectAll('td')
                    .data(function (tag, row_i) {
                        var html_computation = that._get_computation_step(tag);
                        return [
                            that._create_all_tag_html(tag),
                            html_computation[0], html_computation[1], html_computation[2], html_computation[3]
                        ]
                    });
                cells.enter()
                    .append('td')
                    .html(function (e) { return e; })
                    .style('opacity', 0.0)
                    .style('padding', function(e, col_i) {
                        if (col_i == 2) {
                            return '8px 2px 8px 8px';
                        }
                        return '';
                    })
                    .transition()
                    .duration(this.options.animation_duration)
                    .style('opacity', 1.0)
                    .each("end", function(td_content, col_i){
                        var $div = $(td_content);
                        if (col_i == 0 && $div.hasClass('overridden_tags_container')) {
                            $('.overridden_tags_container').popover({
                                title: 'Event tag overridden by Attribute tag',
                                content: that._generateOverridenExplanationPopoverHTML($div),
                                html: true,
                                trigger: 'hover',
                                placement: 'left',
                                container: 'body'
                            });
                        }
                    });
            },

            _generateOverridenExplanationPopoverHTML: function($div) {
                var $tags_event = $div.find('.overriden_tag_wrapper .tag');
                var $tag_attribute = $div.find('.attribute_tag_wrapper .tag');
                var html = '<div style="text-align: center;">';
                    $tags_event.each(function() {
                        html += '<div>' + $(this)[0].outerHTML + '</div>'
                    });
                    html += '<div><i class="fa fa-arrow-down"></i></div>'
                    html += '<div>' + $tag_attribute[0].outerHTML + '</div>'
                html += '</div>';
                return html;
            },

            toggleLoading: function(state) {
                if (state === undefined) {
                    this.$loadingContainer.toggle();
                } else if(state) {
                    this.$loadingContainer.show();
                } else {
                    this.$loadingContainer.hide();
                }
                this.$container;
            },
        }

        $.BasescoreComputationTable = BasescoreComputationTable;
        $.fn.basescoreComputationTable = function(options) {
            var pickedArgs = arguments;

            var $elements = this.each(function() {
                var $this = $(this),
                    inst = $this.data('BasescoreComputationTable');
                options = ((typeof options === 'object') ? options : {});
                if ((!inst) && (typeof options !== 'string')) {
                    $this.data('BasescoreComputationTable', new BasescoreComputationTable(this, options));
                } else {
                    if (typeof options === 'string') {
                        inst[options].apply(inst, Array.prototype.slice.call(pickerArgs, 1));
                    }
                }
            });
            return $elements.length == 1 ? $elements.data('BasescoreComputationTable') : $elements;
        };

        $.fn.basescoreComputationTable.constructor = BasescoreComputationTable;
    })
);
