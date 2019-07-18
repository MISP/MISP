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
                margin: {top: 10, right: 10, bottom: 20, left: 30},
                animation_duration: 1000,
                animation_short_duration: 250,
                time_format: '%Y-%m-%d %H:%M:%S'
            };
            this.options = $.extend(true, {}, default_options, options);
            this._init();
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
                this.width = this.$container.width() - this.options.margin.left - this.options.margin.right;
                this.height = this.$container.height() - this.options.margin.top - this.options.margin.bottom;
                this.chart_data = [];
                this.sightings = [];
                this._parseDataset();

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
                    .attr("width", this.width + this.options.margin.left + this.options.margin.right)
                    .attr("height", this.height + this.options.margin.top + this.options.margin.bottom)
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

                this.svg.append('g')
                    .classed('line-group', true);

                this.svg
                    .append("g")
                    .classed("d3-line-guides-group", true);

                this.svg.insert('g')
                    .classed('circles', true);
            },

            update: function(data, model) {
                this.raw_data = data;
                this.chart_data = data.csv;
                this.sightings = data.sightings;
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
                    .duration(this.options.animation_short_duration)
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
                    .style("stroke", "rgba(70, 130, 180, 0.3)")
                    .style("stroke-dasharray", "4,2")
                    .style("shape-rendering", "crispEdges")
                    .transition()
                    .duration(this.options.animation_short_duration)
                    .attr('y2', function(d) { return that.y(d.value); });
                this.line_guides.exit().remove();

                this.svg.append('rect')
                    .attr('class', 'decayingGraphAreaThres')
                    .style('opacity', 0.6)
                    .attr('x', 0)
                    .attr('y', this.height)
                    .attr('width', this.width)
                    .attr('height', 0)
                    .on('mouseover', function(d) {
                        d3.select(this).transition()
                            .duration(that.options.animation_short_duration)
                            .style('opacity', 0.9)
                        that.tooltipText(true, this, 'Cutoff threshold: <b>' + that.model.parameters.threshold + '</b>');
                    })
                    .on('mouseout', function() {
                        d3.select(this).transition()
                            .duration(that.options.animation_short_duration)
                            .style('opacity', 0.6)
                        that.tooltipText(false);
                    });
                this.svg.select('.decayingGraphAreaThres')
                    .transition()
                    .duration(this.options.animation_short_duration)
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
                            .duration(that.options.animation_short_duration)
                            .attr('r', 7);
                        that.tooltipDate(true, this, d);
                    })
                    .on('mouseout', function() {
                        d3.select(this).transition()
                            .duration(that.options.animation_short_duration)
                            .attr('r', 5);
                        that.tooltipDate(false);
                    })
                    .style('opacity', 0)
                    .transition()
                    .duration(this.options.animation_short_duration)
                    .delay(this.options.animation_short_duration)
                    .ease('linear')
                    .style('opacity', 1);
                this.points.exit().remove();

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
                    return { timestamp: sighting.rounded_timestamp, date: new Date(sighting.rounded_timestamp*1000), value : that.raw_data.base_score_config.base_score, org: d.Organisation.name };
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
                animation_short_duration: 250,
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

                this._draw();
            },

            _create_tag_html: function(tag) {
                if (tag !== false) {
                    return '<span class="tag" style="background-color:' + tag.Tag.colour + '; color: ' + getTextColour(tag.Tag.colour) + '">' + tag.Tag.name + '</span>';
                } else {
                    return '';
                }
            },

            _get_computation_step: function(tag) {
                if (tag === false) {
                    return ['', '', '', this.base_score.toFixed(2)];
                }
                var namespace = tag.Tag.name.split(':')[0];

                var html1 = this.base_score_config.taxonomy_effective_ratios[namespace].toFixed(2);
                var html2 = '*';
                var html3 = parseFloat(tag.Tag.numerical_value).toFixed(2);
                var html4 = (parseFloat(tag.Tag.numerical_value) * this.base_score_config.taxonomy_effective_ratios[namespace]).toFixed(2);
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
                            that._create_tag_html(tag),
                            html_computation[0], html_computation[1], html_computation[2], html_computation[3]
                        ]
                    });
                cells.enter()
                    .append('td')
                    .html(function (e) { return e; })
                    .style('opacity', 0.0)
                    .transition()
                    .duration(this.options.animation_short_duration)
                    .style('opacity', 1.0);
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

            _parseDataset: function() {

            }
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
