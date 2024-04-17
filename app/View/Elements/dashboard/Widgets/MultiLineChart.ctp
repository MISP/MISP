<?php
    $seed = rand();
    if (!empty($data['formula'])) {
        echo sprintf(
            '<div style="width:100%%;text-align:center;" class="blue bold">%s</div>',
            h($data['formula'])
        );
    }
    $y_axis = $data['y-axis'] ?? 'Count';
?>
<div id="chartContainer-<?= $seed ?>" style="flex-grow: 1; position:relative;"></div>
<script>
if (typeof d3 === "undefined") { // load d3.js once. This is necessary as d3.js is using global variables for its event listeners (d3.mouse & d3.event)
    d3 = 'loading';
    $.getScript("/js/d3.js", function() {
        init<?= $seed ?>();
    })
} else { // d3.js is already loaded or is loading
    runInitWhenReady<?= $seed ?>()
}

function runInitWhenReady<?= $seed ?>() {
    if (d3.version === undefined) { // d3.js not loaded yet
        setTimeout(function() {
            runInitWhenReady<?= $seed ?>();
        }, 50);
    } else {
        init<?= $seed ?>();
    }
}

function init<?= $seed ?>() { // variables and functions have their own scope (no override)
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
            ylabel: "<?= h($y_axis) ?>",
            hideXAxis: false,
            hideYAxis: false,
        },
        max_datapoints: null,
        margin: {top: 10, right: 20, bottom: 35, left: 50},
        animation_short_duration: 100,
        redraw_timeout: 300, // used after resize
        enable_total: false
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
    var x, y, xGrid, yGrid, value_line;
    var overlayLeft, overlayRight, tooltipPickedNodes;
    var series, line_guides, points, pointsGroup, labels;
    var colors = d3.scale.category10();

    var pickedNodes = {start: null, end: null};

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
        options.enable_total = __parseTextBoolean(options.enable_total);
        options.max_datapoints = (options.max_datapoints === null || options.max_datapoints === "null") ? null : parseInt(options.max_datapoints);
        return options;
    }

    function registerListener() {
        $container.closest('.widgetContentInner').on('widget-resized', function() {
            _init_canvas();
            _draw();
        })
    }

    function getX(datum) {
        return options.abscissa_linear ? datum.index : datum.date;
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
        tooltipPickedNodes = d3.select('body').append('div')
            .attr('class', 'tooltip tooltipPickedNodes')
            .style('opacity', 0)
            .style('min-width', '120px')
            .style('padding', '3px')
            .style('background-color', '#fff')
            .style('color', 'black')
            .style('border', '1px solid black')
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
            .x(function(d) { return x(getX(d)); })
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

        overlayLeft = svg.append('rect')
            .attr('fill', 'black')
            .attr('opacity', 0.6)
            .attr('class', 'overlay-left')
            .attr('width', 0)
            .attr('height', height)
            .attr('x', 0)
            .on('click', clearPickedNodes);
        overlayRight = svg.append('rect')
            .attr('fill', 'black')
            .attr('opacity', 0.6)
            .attr('class', 'overlay-right')
            .attr('width', 0)
            .attr('height', height)
            .attr('x', 0)
            .on('click', clearPickedNodes);

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
            disabled: !options.enable_total
        });
        labelDomain.unshift("Total");
        legend_labels = labelDomain.map(function(label) {
            return {
                text: label,
                disabled: label === "Total" ? !options.enable_total : false
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
        x.domain(d3.extent(chart_data, function(d) { return getX(d); }))
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
            .style("stroke", function(d) { return colors(d.name); })
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
                .attr('class', 'datapoint d3-line-circle useCursorPointer')
                .attr('r', 5)
            points // Update
                .attr('cx', function (d) { return x(getX(d)); })
                .attr('cy', function (d) { return y(d.count); })
                .style("fill", function(d) { return colors(d.name); })
                .on('mouseover', function(d) {
                    tooltipDate(true, this, d);
                })
                .on('click', function(d) {
                    handleMarkerClick(d);
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
                    var label_text = d.text;
                    if (d3.event.ctrlKey) { // hide all others
                        data_nodes.filter(function(fd) { return fd.name === label_text; }).forEach(function(data) {
                            data.disabled = false;
                        })
                        data_nodes.filter(function(fd) { return fd.name !== label_text; }).forEach(function(data) {
                            data.disabled = true;
                        })
                        d.disabled = false;
                        legend_labels.filter(function(fd) { return fd.text !== label_text}).forEach(function(label_data) {
                            label_data.disabled = true;
                        })
                    } else { // hide it
                        d.disabled = !d.disabled;
                        data_nodes.filter(function(fd) { return fd.name === label_text; }).forEach(function(data) {
                            data.disabled = d.disabled;
                        })
                    }
                    _draw();
                });
        }
    }

    function tooltipDate(show, d3Element, datum) {
        var $d3Element = $(d3Element);
        $d3Element.tooltip({
            html: true,
            container: 'body',
            title: _generate_tooltip(datum)
        }).tooltip('show')
    }

    function _generate_tooltip(datum) {
        var formated_x = options.abscissa_linear ? datum.index : d3.time.format(options.time_format)(datum.date);
        return $('<div></div>').append(
            $('<h6></h6>').text(formated_x).css({'margin': 0}),
            $('<h6></h6>').append(
                $('<span></span>').text(datum.name).css({'margin-right': '1em'}).prepend(
                    $('<svg height="10px" width="15px"></svg>').append($('<circle></circle>')
                        .attr('cx', 5)
                        .attr('cy', 5)
                        .attr('r', 5)
                        .css('fill', colors(datum.name))
                    )
                ),
                $('<span></span>').text(datum.count)
            ).css({'margin': 0})
        )[0].outerHTML
    }

    function handleMarkerClick(datum) {
        var xVal = getX(datum);
        if (pickedNodes.start === null) {
            pickedNodes.start = datum;
        } else {
            if (getX(pickedNodes.start) < xVal) {
                pickedNodes.end = datum;
            } else {
                pickedNodes.end = pickedNodes.start;
                pickedNodes.start = datum;
            }
        }
        updatePickedNodesOverlays();
    }

    function clearPickedNodes() {
        pickedNodes.start = null;
        pickedNodes.end = null;
        updatePickedNodesOverlays();
    }

    function updatePickedNodesOverlays() {
        if (pickedNodes.start === null) {
            overlayLeft.attr('width', 0);
            overlayRight.attr('x', 0)
                .attr('width', 0);
            togglePickedNodeTooltip(false);
        } else {
            overlayLeft.attr('width', x(getX(pickedNodes.start)));
            if (pickedNodes.end !== null) {
                overlayRight.attr('x', x(getX(pickedNodes.end)))
                    .attr('width', width - x(getX(pickedNodes.end)));
                togglePickedNodeTooltip(true);
            }
        }
    }

    function togglePickedNodeTooltip(show) {
        if (show) {
            tooltipPickedNodes.html(genTooltipPickedNodeHtml());
            tooltipPickedNodes
                .style('display', 'block')
                .style('opacity', '0.8');

            var overlayLeftBCR = overlayLeft.node().getBoundingClientRect();
            var overlayRightBCR = overlayRight.node().getBoundingClientRect();
            var tooltipBCR = tooltipPickedNodes.node().getBoundingClientRect();
            var left = (overlayLeftBCR.width - overlayRightBCR.width > 0 ?
                overlayLeftBCR.left + overlayLeftBCR.width/2 :
                overlayRightBCR.left + overlayRightBCR.width/2) - tooltipBCR.width / 2;
            var top = overlayLeftBCR.top + window.scrollY + 30;

            tooltipPickedNodes
                .style('left', left + 'px')
                .style('top', top + 'px')
        } else {
            tooltipPickedNodes.style('display', 'none');
        }
        return tooltipPickedNodes;
    }

    function genTooltipPickedNodeHtml() {
        var xValueStart = getX(pickedNodes.start)
        var xValueEnd = getX(pickedNodes.end)
        var yValues = []
        data_nodes_active.forEach(function(serie) {
            var startPoint = serie.values.find(function(point) {
                return getX(point) == xValueStart;
            })
            var endPoint = serie.values.find(function(point) {
                return getX(point) == xValueEnd;
            })
            if (startPoint !== undefined && endPoint !== undefined)
            var deltaY = endPoint.count - startPoint.count;
            var deltaYPerc = startPoint.count != 0 ? Math.abs(100*deltaY / startPoint.count).toFixed(2) : '-';
            yValues.push({
                name: serie.name,
                nameColor: colors(serie.name),
                deltaY: deltaY,
                deltaYPerc: deltaYPerc + '%',
                yColor: deltaY == 0 ? '' : (deltaY > 0 ? 'success' : 'error')
            })
        })
        if (!options.abscissa_linear) {
            xValueStart = d3.time.format(options.time_format)(xValueStart);
            xValueEnd = d3.time.format(options.time_format)(xValueEnd);
        }
        var $content = $('<div></div>').append(
                $('<div style="display: flex; justify-content: space-between;"></div>').append(
                    $('<span class="bold"></span>').text(xValueStart),
                    $('<i class="fas fa-arrow-right"></i>'),
                    $('<span class="bold"></span>').text(xValueEnd)
                )
        );
        var $table = $('<table class="table table-condensed" style="margin-bottom: 0;"></table>').append(
                $('<thead></thead>').append($('<tr></tr>').append(
                        $('<th></th>').text('Name'),
                        $('<th></th>').text('Delta'),
                        $('<th></th>').text('Delta %')
                    )
                )
        );
        yValues.forEach(function(serie) {
            $table.append(
                $('<tbody></tbody>').append($('<tr></tr>').append(
                        $('<td></td>').append(
                            $('<svg height="10px" width="15px"></svg>').append($('<circle></circle>')
                                .attr('cx', 5)
                                .attr('cy', 5)
                                .attr('r', 5)
                                .css('fill', serie.nameColor)
                            ),
                            $('<span></span>').text(serie.name)
                        ),
                        $('<td></td>')
                            .addClass('text-'+serie.yColor)
                            .text(serie.deltaY)
                            .append($('<i></i>').addClass(serie.deltaY > 0 ? 'fas fa-caret-up' : 'fas fa-caret-down')),
                        $('<td></td>')
                            .addClass('text-'+serie.yColor)
                            .text(serie.deltaYPerc)
                            .append($('<i></i>').addClass(serie.deltaY > 0 ? 'fas fa-caret-up' : 'fas fa-caret-down')),
                    )
                )
            );
        });
        $content.append($table);
        return $content[0].outerHTML;
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

.overlay-right, .overlay-left {
    cursor: pointer;
}
</style>
