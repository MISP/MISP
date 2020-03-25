<?php
    $seed = rand();
    if (!empty($data['formula'])) {
        echo sprintf(
            '<div style="width:100%%;text-align:center;" class="blue bold">%s</div>',
            h($data['formula'])
        );
    }
?>
<div id="chartContainer-<?= $seed ?>" style="flex-grow: 1; position:relative;"></div>
<script>
if (typeof d3 === "undefined") { // load d3.js once. This is necessary as d3.js is using global variables for its event listeners (d3.mouse & d3.event)
    $.getScript("/js/d3.js", function() {
        init();
    })
} else { // d3.js is already loaded
    init();
}

function init() { // variables and functions have their own scope (no override)
    'use strict';

    /**
     * 
     * Data expected format: Array({
     *      date: (string) "time_format",
     *      index: (int),
     *      line1: (int),
     *      line2: (int),
     *      ...
     * })
     * For abscissa linear scale, replace the date key by index
     */
    var data = <?= json_encode($data['data']) ?>;
    var default_options = {
        time_format: '%Y-%m-%d',
        abscissa_linear: false,
        show_crossair: true,
        show_datapoints: true,
        show_legend: true,
        style: {
            xlabel: "Date",
            ylabel: "Count",
            hideXAxis: false,
            hideYAxis: false,
        },
        max_datapoints: null,
        margin: {top: 10, right: 20, bottom: 35, left: 40},
        animation_short_duration: 100,
        redraw_timeout: 300, // used after resize
    };
    var offsetLeftMargin = 0;
    var container_id = "#chartContainer-<?= $seed ?>";

    var $container = $(container_id);
    var $loadingContainer, tooltip_container;
    var resize_timeout;
    var timeFormatter;
    var svg;
    var width, height, svg_width, svg_height;
    var xAxis, yAxis, cursorX, cursorY;
    var x, y, xGrid, yGrid, value_line
    var series, line_guides, points, pointsGroup, labels
    var colors = d3.scale.category10();

    var options = <?= json_encode(isset($config['widget_config']) ? $config['widget_config'] : array()) ?>;
    var options = $.extend(true, {}, default_options, options);
    options = _validateOptions(options);
    var data_nodes = [];
    var data_nodes_active = [];
    var chart_data = [];
    var legend_labels = [];
    var raw_data;
    _init();
    _init_canvas();
    if (data !== undefined) {
        update(data)
    }
    registerListener();

    function __parseTextBoolean(text) {
        if (text === "true" || text === "1") {
            return true;
        } else if (text === "false" || text === "0") {
            return false;
        } else {
            return text;
        }
    }

    function _validateOptions(options) {
        options.abscissa_linear = __parseTextBoolean(options.abscissa_linear);
        options.show_crossair = __parseTextBoolean(options.show_crossair);
        options.show_datapoints = __parseTextBoolean(options.show_datapoints);
        options.show_legend = __parseTextBoolean(options.show_legend);
        options.style.hideXAxis = __parseTextBoolean(options.style.hideXAxis);
        options.style.hideYAxis = __parseTextBoolean(options.style.hideYAxis);
        options.max_datapoints = (options.max_datapoints === null || options.max_datapoints === "null") ? null : parseInt(options.max_datapoints);
        return options;
    }

    function registerListener() {
        $container.closest('.widgetContentInner').on('widget-resized', function() {
            _init_canvas();
            _draw();
        })
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
            .style('min-width', '120px')
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
        width = svg_width - (options.margin.left+offsetLeftMargin) - options.margin.right;
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
            .x(function(d) { return x(options.abscissa_linear ? d.index : d.date); })
            .y(function(d) { return y(d.count); });

        svg = d3.select(container_id)
            .append("svg")
            .classed('svg-content-responsive', true)
            .attr("width", svg_width)
            .attr("height", svg_height)
            .append("g")
            .attr("transform", "translate(" + (options.margin.left+offsetLeftMargin) + "," + options.margin.top + ")");

        if (!options.style.hideXAxis) {
            svg.append("g")
                .attr('class', 'axis axis-x')
                .attr("transform", "translate(0," + height + ")")
            svg.append("g")
                .attr("class", "axis grid grid-y")
                .attr("transform", "translate(0," + height + ")");
            svg.append("text")
                .classed('axis-label', true)
                .attr("text-anchor", "end")
                .attr("x", width / 2)
                .attr("y", height)
                .attr("dy", '30px')
                .text(options.style.xlabel);
        }
        if (!options.style.hideYAxis) {
            svg.append("g")
                .attr('class', 'axis axis-y')

            svg.append("g")
                .attr("class", "axis grid grid-x");
            svg.append("text")
                .classed('axis-label', true)
                .attr("text-anchor", "middle")
                .attr("transform", "rotate(-90 0 " + height / 2 + ")")
                .attr("x", 0)
                .attr("dy", '-30px')
                .attr("y", height / 2)
                .text(options.style.ylabel);
        }

        svg.append('g')
            .classed('line-group', true);

        if (options.show_crossair) {
            var cursorStrokeConfig = {
                dasharray: 5,
                opacity: 0.3,
                width: 0.5
            };
            cursorX = svg.append('line')
                .attr('class', 'cursor-x')
                .attr("stroke-width", cursorStrokeConfig.width)
                .attr("stroke-dasharray", cursorStrokeConfig.dasharray)
                .style("stroke", "#000")
                .style('opacity', 0)
                .attr('x1', 0)
                .attr('y1', height)
                .attr('x2', width)
                .attr('y2', height)
            cursorY = svg.append('line')
                .attr('class', 'cursor-x')
                .attr("stroke-width", cursorStrokeConfig.width)
                .attr("stroke-dasharray", cursorStrokeConfig.dasharray)
                .style("stroke", "#000")
                .style('opacity', 0)
                .attr('x1', 0)
                .attr('y1', 0)
                .attr('x2', 0)
                .attr('y2', height)
            
            var eventContainer = svg.append('rect')
                .attr('fill', 'white')
                .attr('class', 'overlay')
                .attr('width', width)
                .attr('height', height)
                .on("mousemove", function() {
                    var d3Mouse = d3.mouse(this);
                    cursorX
                        .attr('y1', d3Mouse[1])
                        .attr('y2', d3Mouse[1])
                    cursorY
                        .attr('x1', d3Mouse[0])
                        .attr('x2', d3Mouse[0])
                })
                .on("mouseenter", function(e) {
                    cursorX.style('opacity', cursorStrokeConfig.opacity)
                    cursorY.style('opacity', cursorStrokeConfig.opacity)
                })
                .on("mouseleave", function(e) {
                    cursorX.style('opacity', 0)
                    cursorY.style('opacity', 0)
                })
        }


        svg.append('g')
            .classed('legend', true);

        svg.append('g')
            .classed('point-group', true);

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
        var labelDomain = d3.keys(data[0]).filter(function(key) { return key !== "date"; });  // fetch all lines keys
        var totalValues = [];
        var totalMax = 0;
        data_nodes = labelDomain.map(function(label) { // generate line data for each lines key
            return {
                name: label,
                values: data.map(function(d, index) {
                    if (totalValues[index] === undefined) {
                        totalValues[index] = {
                            index: d.index,
                            date: d.date,
                            count: +d[label],
                            name: "Total"
                        }
                    } else {
                        totalValues[index].count += d[label];
                        totalMax = totalMax > totalValues[index].count ? totalMax : totalValues[index].count;
                    }
                    return {
                        index: d.index,
                        date: d.date,
                        count: +d[label],
                        name: label
                    };
                }),
                disabled: false
            };
        });
        data_nodes.push({
            name: "Total",
            values: totalValues,
            disabled: true
        });
        labelDomain.unshift("Total");
        legend_labels = labelDomain.map(function(label) {
            return {
                text: label,
                disabled: label === "Total" ? true : false
            };
        });
        colors.domain(labelDomain);
        data_nodes_active = data_nodes;

        // adapt margin left for big numbers
        var tmp = svg.append('text').text(totalMax);
        offsetLeftMargin = tmp.node().getComputedTextLength() - 25;
        if (offsetLeftMargin > 0) {
            _init_canvas()
        }
        tmp.remove();
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
        x.domain(d3.extent(chart_data, function(d) { return options.abscissa_linear ? d.index : d.date; }))
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
            .style("stroke", function(d) { ;return colors(d.name); })
            .attr("d", function(d) { return value_line(d.values); });
        series.exit().remove();


        if (options.show_datapoints) {
            pointsGroup = svg.select('.point-group')
                .selectAll('.line-point')
                .data(data_nodes_active)
            var pointsGroupEnter = pointsGroup
                .enter()
                .append('g')
                .attr('class', 'line-point')
            points = pointsGroup
                .selectAll('.d3-line-circle')
                .data(function(d){
                    return options.max_datapoints === null ? d.values :
                        d.values.filter(function(v, index) {
                            var split_threshold = Math.ceil(d.values.length / (options.max_datapoints-1)); // -1 to always have first and last points
                            return (index % (split_threshold-1) == 0) || (index == d.values.length-1); // -1 to center the split in the middle
                        })
                })
            points
                .enter()
                .append('circle')
                .attr('class', 'datapoint d3-line-circle')
                .attr('r', 5)
            points // Update
                .attr('cx', function (d) { return x(options.abscissa_linear ? d.index : d.date); })
                .attr('cy', function (d) { return y(d.count); })
                .style("fill", function(d) { return colors(d.name); })
                .on('mouseover', function(d) {
                    tooltipDate(true, this, d);
                })
                .on('mouseout', function() {
                    tooltipDate(false);
                })
            pointsGroup.exit().remove();
        }


        if (options.show_legend) {
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
    
                    if (width < (options.margin.left+offsetLeftMargin) + options.margin.right + xpos + length) {
                        newxpos = xpos = 20;
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
    }

    function tooltipDate(show, d3Element, datum) {
        var tooltip = _toggleTooltip(show, d3Element);
        if (show) {
            tooltip.html(_generate_tooltip(datum));
            // Flip tooltip position if necessary
            var tooltipBR = tooltip.node().getBoundingClientRect();
            var tooltipWidth = tooltipBR.width;
            var tooltipcx = parseInt(d3.select(d3Element).attr('cx'));
            var dcx = 17;
            if (width < options.margin.right + tooltipcx - dcx + tooltipWidth) {
                var tooltipLeft = parseInt(tooltip.style('left').split('px')[0]);
                tooltip.style('left', (tooltipLeft - (17 + tooltipWidth + 15)) + 'px')
            }
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
        var html = $('<p></p>').text(datum.name).html() + ' (' + formated_date + ', <strong>' + $('<p></p>').text(datum.count).html() + '</strong>) ';
        return html;
    }
};
</script>

<style widget-scoped>
.svg-content-responsive {
    display: inline-block;
    position: absolute;
    left: 0;
}
.path_multi_line_chart {
    stroke-width: 1;
    fill: none;
    stroke-linejoin: round;
    stroke-linecap: round;
}

.path_multi_line_chart {
    stroke-width: 1;
}

.path,
.line {
    fill: none;
    stroke: grey;
    stroke-width: 2;
}

.datapoint {
    stroke: #ffffff;
    fill: steelblue;
    stroke-width: 2px;
}

.labels {
    cursor: pointer;
    background-color: white;
}

.overlay {
    fill: none;
    stroke: none;
    pointer-events: all;
}

.axis path {
    stroke-width: 2px;
    stroke: #000;
    fill: none;
}

.axis line {
  stroke: #000;
}

.axis text {
    user-select: none;
}

.axis.grid line {
    stroke: lightgrey;
    stroke-opacity: 0.7;
    shape-rendering: crispEdges;
}

.axis.grid path {
    stroke-width: 0;
}
</style>
