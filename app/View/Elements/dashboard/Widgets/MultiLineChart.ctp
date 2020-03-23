<?php
    /**
     * 
     * Data expected format: Array({
     *      date: "time_format",
     *      line1: value1,
     *      line2: value2,
     *      ...
     * })
     * For abscissa linear scale, replace the date key by index
     */
    echo $this->Html->script('d3');
    $seed = rand();
    if (!empty($data['formula'])) {
        echo sprintf(
            '<div style="width:100%%;text-align:center;" class="blue bold">%s</div>',
            h($data['formula'])
        );
    }
    echo $this->element('genericElements/assetLoader', array(
        'css' => array('treemap', 'decayingTool'),
    ));
?>
<!-- <svg id="svg-<?= $seed ?>" width="960" height="500"></svg> -->
<div id="chartContainer-<?= $seed ?>" style="flex-grow: 1;"></div>
<script>
(function() { // variables and functions have their own scope (no override)
    'use strict';
    var container_id = "#chartContainer-<?= $seed ?>";
    var $container = $(container_id);
    var $loadingContainer, tooltip_container;
    var resize_timeout;
    var timeFormatter;
    var svg;
    var width, height, svg_width, svg_height;
    var xAxis, yAxis;
    var x, y, xGrid, yGrid, value_line
    var series, line_guides, points, pointsGroup, labels
    var colors = d3.scale.category10();

    var options = <?= json_encode(isset($data['options']) ? $data['options'] : array()) ?>;
    _validateOptions(options);
    var data_nodes = [];
    var data_nodes_active = [];
    var chart_data = [];
    var legend_labels = [];
    var raw_data;
    var data = <?= json_encode($data['data']) ?>;
    var default_options = {
        tick_num: 300,
        margin: {top: 10, right: 20, bottom: 35, left: 35},
        animation_duration: 250,
        animation_short_duration: 100,
        redraw_timeout: 300,
        time_format: '%Y-%m-%d',
        abscissa_linear: false,
        style: {
            x: {
                label: "Date"
            },
            y: {
                label: "Count"
            }
        }
    };
    var options = $.extend(true, {}, default_options, options);
    _init();
    _init_canvas();
    if (data !== undefined) {
        update(data)
    }

    function _validateOptions() {
        return true;
    }

    function _init() {
        $loadingContainer = $('<div id="loadingChartContainer" style="background: #ffffff9f"><span class="fa fa-spinner fa-spin" style="font-size: xx-large;"></span></div>').css({
            position: 'absolute',
            left: '0',
            right: '0',
            top: '0',
            bottom: '0',
            display: 'flex',
            'align-items': 'center',
            'justify-content': 'center'
        }).hide();
        tooltip_container = d3.select('body').append('div')
            .classed('tooltip', true)
            .style('opacity', 0)
            .style('padding', '3px')
            .style('background-color', '#000')
            .style('color', 'white')
            .style('border-radius', '5px')
            .style('display', 'none');
        $container.append($loadingContainer);
        timeFormatter = d3.time.format(options.time_format).parse;
    }

    function _init_canvas() {
        $container.empty();
        svg_width = $container.width();
        svg_height = $container.height();
        width = svg_width - options.margin.left - options.margin.right;
        height = svg_height - options.margin.top - options.margin.bottom;

        if (options.abscissa_linear) {
            x = d3.scale.linear()
            .domain(d3.extent(data, function(d) { return d.index; }))
            .range([ 0, width ]);
        } else {
            x = d3.time.scale()
                .domain(d3.extent(data, function(d) { return d.date; }))
                .range([ 0, width ]);
        }
        y = d3.scale.linear()
            .domain(d3.extent(data, function(d) { return d.value; }))
            .range([ height, 0 ]);

        yGrid = d3.svg.axis().scale(x).orient("bottom")
            .tickSize(-height)
            .tickFormat("");
        xGrid = d3.svg.axis().scale(y).orient("left")
            .ticks(3)
            .tickSize(-width)
            .tickFormat("");

        value_line = d3.svg.line()
            .x(function(d) { return x(d.date); })
            .y(function(d) { return y(d.count); });

        svg = d3.select(container_id)
            .append("svg")
            .classed('svg-content-responsive', true)
            .attr("width", svg_width)
            .attr("height", svg_height)
            .append("g")
            .attr("transform", "translate(" + options.margin.left + "," + options.margin.top + ")");

        svg.append("g")
                .attr('class', 'decayingGraphAxis axis-x')
                .attr("transform", "translate(0," + height + ")")
        svg.append("g")
            .attr('class', 'decayingGraphAxis axis-y')

        svg.append("g")
            .attr("class", "decayingGraphAxis grid grid-x");
        svg.append("g")
            .attr("class", "decayingGraphAxis grid grid-y")
            .attr("transform", "translate(0," + height + ")");

        svg.append("text")
            .classed('axis-label', true)
            .attr("text-anchor", "end")
            .attr("x", width / 2)
            .attr("y", height)
            .attr("dy", '30px')
            .text(options.style.x.label);
        svg.append("text")
            .classed('axis-label', true)
            .attr("text-anchor", "middle")
            .attr("transform", "rotate(-90 0 " + height / 2 + ")")
            .attr("x", 0)
            .attr("dy", '-25px')
            .attr("y", height / 2)
            .text(options.style.y.label);

        svg.append('g')
            .classed('line-group', true);

        svg.append('g')
            .classed('point-group', true);

        svg.append('g')
            .classed('legend', true);

        window.addEventListener("resize", function() {
            if (resize_timeout !== undefined) {
                clearTimeout(resize_timeout);
            }
            resize_timeout = setTimeout(function() { redraw_timeout_handler() }, options.redraw_timeout);
        });
    }

    function redraw_timeout_handler(inst) {
        clearTimeout(resize_timeout);
        _init_canvas();
        _draw();
    }

    function update(data) {
        raw_data = data;
        chart_data = data;
        _parseDataset();
        colors.domain(d3.keys(data[0]).filter(function(key) { return key !== "date"; })); // fetch all lines keys
        legend_labels = colors.domain().map(function(label) {
            return {
                text: label,
                disabled: false
            };
        });
        data_nodes = legend_labels.map(function(label) { // generate line data for each lines key
            return {
                name: label.text,
                values: data.map(function(d) {
                    return {
                        date: d.date,
                        count: +d[label.text],
                        name: label.text
                    };
                }),
                disabled: false
            };
        });
        data_nodes_active = data_nodes;
        _draw();
    }

    function _parseDataset() {
        if (typeof chart_data === 'string') {
            chart_data = d3.csv.parse(chart_data, function(d){
                var parsed_date = timeFormatter(d.date);
                return { timestamp: Math.floor(parsed_date.getTime() / 1000), date: parsed_date, value : parseFloat(d.value) }
            });
        } else if (Array.isArray(chart_data)){
            chart_data.forEach(function(entry, i) {
                chart_data[i].date = timeFormatter(entry.date);
            })
        }
    }

    function _draw() {
        data_nodes_active = data_nodes.filter(function(d) {
            return !d.disabled;
        })
        x.domain(d3.extent(chart_data, function(d) { return d.date; }))
        y.domain([
            d3.min(data_nodes_active, function(c) { return d3.min(c.values, function(v) { return v.count; }); }),
            d3.max(data_nodes_active, function(c) { return d3.max(c.values, function(v) { return v.count; }); })
        ]);

        xAxis = svg.select('.axis-x')
            .call(d3.svg.axis().scale(x).orient('bottom'));
        yAxis = svg.select('.axis-y')
            .call(d3.svg.axis().scale(y).orient("left"));

        svg.select('.grid-x')
            .call(xGrid);
        svg.select('.grid-y')
            .call(yGrid);

        series = svg.select('.line-group')
            .selectAll('.line')
            .data(data_nodes_active)
        series
            .enter()
            .append('path')
            .attr("class","line")
            .attr("fill", "none")
            .attr("stroke-width", 2.5);
        series
            .style("stroke", function(d) { console.log(d);return colors(d.name); })
            .attr("d", function(d) { return value_line(d.values); });
        series.exit().remove();



        pointsGroup = svg.select('.point-group')
            .selectAll('.line-point')
            .data(data_nodes_active)
        var pointsGroupEnter = pointsGroup
            .enter()
            .append('g')
            .attr('class', 'line-point')
        points = pointsGroup
            .selectAll('.d3-line-circle')
            .data(function(d){return d.values})
        points
            .enter()
            .append('circle')
            .attr('class', 'decayingGraphHandleDot useCursorPointer d3-line-circle')
            .attr('r', 5)
        points // Update
            .attr('cx', function (d) { return x(d.date); })
            .attr('cy', function (d) { return y(d.count); })
            .style("fill", function(d) { return colors(d.name); })
            .on('mouseover', function(d) {
                tooltipDate(true, this, d);
            })
            .on('mouseout', function() {
                tooltipDate(false);
            })
        pointsGroup.exit().remove();

        labels = svg.select('.legend')
            .selectAll('.labels')
            .data(legend_labels);
        var label = labels.enter()
            .append('g')
            .attr('class', 'labels')
        label.append('circle')
        label.append('text')

        labels.selectAll('circle')
            .style('fill', function(d, i){ return colors(d.text) })
            .style('stroke', function(d, i){ return colors(d.text) })
            .attr('r', 5);
        labels.selectAll('text')
            .text(function(d) { return d.text })
            .style('font-size', '16px')
            .style('text-decoration', function(d) { return d.disabled ? 'line-through' : '' })
            .attr('fill', function(d) { return d.disabled ? 'gray' : '' })
            .attr('text', 'start')
            .attr('dy', '.32em')
            .attr('dx', '8');
        labels.exit().remove();
        var ypos = 5, newxpos = 20, xpos;
        label
            .attr('transform', function(d, i) {
                var length = d3.select(this).select('text').node().getComputedTextLength() + 28;
                var xpos = newxpos;

                if (width < options.margin.left + options.margin.right + xpos + length) {
                    newxpos = xpos = 5;
                    ypos += 20;
                }

                newxpos += length;

                return 'translate(' + xpos + ',' + ypos + ')';
            })
            .on('click', function(d, i) { 
                d.disabled = !d.disabled;
                var label_text = d.text;
                var label_disabled = d.disabled;
                data_nodes.filter(function(d) { return d.name === label_text; }).forEach(function(data) {
                    data.disabled = label_disabled
                })
                _draw()
            });
    }

    function tooltipDate(show, d3Element, datum) {
        var tooltip = _toggleTooltip(show, d3Element);
        if (show) {
            tooltip.html(_generate_tooltip(datum));
        }
    }

    function _toggleTooltip(show, d3Element) {
        if (show) {
            var bb_rect = d3.select(d3Element)[0][0].getBoundingClientRect();
            var cx = bb_rect.left;
            var cy = bb_rect.top;
            tooltip_container
                .style('display', 'block')
                .style('left', (cx + 17) + 'px')
                .style('top', (cy - 6) + 'px')
                .transition()
                .duration(options.animation_short_duration)
                .delay(options.animation_short_duration/2)
                .style('opacity', '0.7');
        } else {
            tooltip_container.transition()
                .duration(options.animation_short_duration)
                .style('opacity', 0)
                .delay(options.animation_short_duration)
                .style('display', 'none');
        }
        return tooltip_container;
    }

    function _generate_tooltip(datum) {
        var formated_date = d3.time.format(options.time_format)(datum.date);
        var html = $('<p></p>').text(datum.name).html() + ': <strong>' + $('<p></p>').text(datum.count).html() + '</strong>' + ' @ ' + formated_date;
        return html;
    }
}());
</script>

<style widget-scoped>
.path_multi_line_chart {
    stroke-width: 1;
    fill: none;
    stroke-linejoin: round;
    stroke-linecap: round;
}

.path_multi_line_chart {
    stroke-width: 1;
}

.axis_multi_line_chart path,
.axis_multi_line_chart line {
    fill: none;
    stroke: grey;
    stroke-width: 1;
    shape-rendering: crispEdges;
}

.labels {
    cursor: pointer;
    background-color: white;
}
</style>
