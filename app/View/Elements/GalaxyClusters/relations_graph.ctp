<div style="margin-bottom: 10px; position: relative">
    <div id="graphContainer" style="height: 70vh; border: 1px solid #ddd; "></div>
    <div id="tooltipContainer" style="max-height: 400px; min-width: 200px; max-width:300px; position: absolute; top: 10px; right: 10px; border: 1px solid #999; border-radius: 3px; background-color: #f5f5f5ee; overflow: auto;"></div>
</div>

<?php
echo $this->element('genericElements/assetLoader', array(
    'js' => array('d3')
));
?>

<script>
var graph = <?= json_encode($relations) ?>;
var nodes, links;
var width, height, margin;
var vis, svg, plotting_area, force, container, zoom;
var legendLabels, labels;
var graphElementScale = 1;
var graphElementTranslate = [0, 0];
var nodeHeight = 20;
var nodeWidth = 120;
var colors = d3.scale.category10();

$(document).ready( function() {
    margin = {top: 5, right: 5, bottom: 5, left: 5},
    width = $('#graphContainer').width() - margin.left - margin.right,
    height = $('#graphContainer').height() - margin.top - margin.bottom;
    $('#tooltipContainer').hide();
    if (graph.nodes.length > 0) {
        initGraph();
    }
});

function initGraph() {
    var correctLink = [];
    var groupDomain = {};
    graph.links.forEach(function(link) {
        var tmpNode = graph.nodes.filter(function(node) {
            return node.id == link.source;
        })
        link.source = tmpNode[0]
        tmpNode = graph.nodes.filter(function(node) {
            return node.id == link.target;
        })
        link.target = tmpNode[0]
        groupDomain[link.source.group] = 1;
        groupDomain[link.target.group] = 1;
        correctLink.push(link)
    })
    groupDomain = Object.keys(groupDomain);
    colors.domain(groupDomain);
    graph.links = correctLink;
    force = d3.layout.force()
        .size([width, height])
        .charge(-1000)
        .friction(0.3)
        .theta(0.3)
        // .theta(0.9)
        .linkDistance(80)
        // .linkStrength(0.7)
        .on("tick", tick)

    vis = d3.select("#graphContainer");

    svg = vis.append("svg")
        .attr("id", "relationGraphSVG")
        .attr("width", width)
        .attr("height", height)
    container = svg.append("g").attr("class", "zoomContainer");
    svg.on('click', clickHandlerSvg);
    zoom = d3.behavior.zoom()
        .on("zoom", zoomHandler);
    svg.call(zoom);

    defs = svg.append("defs")
    defs.append("marker")
        .attr({
            "id":"arrowEnd",
            "viewBox":"0 -5 10 10",
            "refX": 10+5,
            "refY": 0,
            "markerWidth": 8,
            "markerHeight": 8,
            "markerUnits": "userSpaceOnUse",
            "orient":"auto"
        })
        .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .attr("class","arrowHead");

    svg.append('g')
        .classed('legendContainer', true)
        .append('g')
        .classed('legend', true);
    legendLabels = groupDomain.map(function(domain) {
        return {
            text: domain,
            color: colors(domain)
        }
    })
    drawLabels();

    update();
}

function zoomHandler() {
    container.attr("transform",
        "translate(" + d3.event.translate + ")"
        + " scale(" + d3.event.scale + ")");
    graphElementScale = d3.event.scale;
    graphElementTranslate = d3.event.translate;
}

function update() {
    force
        .nodes(graph.nodes)
        .links(graph.links)

    links = container.append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(graph.links)
        links.exit().remove();

    var linkEnter = links.enter()
        .append("line")
        .on('click', clickHandlerLink)
        .attr("class", "link")
        .classed('useCursorPointer', true)
        .attr("marker-end", "url(#arrowEnd)")
        .attr("stroke", "#999")
        .attr("stroke-width", function(d) {
            var linkWidth = 1;
            var linkMaxWidth = 5;
            if (d.tag !== undefined && d.tag.numerical_value !== undefined) {
                linkWidth = d.tag.numerical_value / 100 * linkMaxWidth;
            }
            return linkWidth + 'px';
        })
        .attr("stroke-opacity", function(d) {
            var opacity = 0.6;
            if (d.tag !== undefined && d.tag.numerical_value !== undefined) {
                opacity = Math.min(0.8, Math.max(0.2, d.tag.numerical_value / 100));
            }
            return opacity;
        })
        
    nodes = container.append("g")
        .attr("class", "nodes")
        .selectAll("div")
        .data(graph.nodes);
    nodes.exit().remove();
    var nodesEnter = nodes.enter()
        .append('g')
        .classed('useCursorPointer node', true)
        .call(drag(force))
        .on('click', clickHandlerNode);

    nodesEnter.append("circle")
        .attr("r", 5)
        .style("fill", function(d) { return colors(d.group); })
        .style("stroke", "black")
        .style("stroke-width", "1px");
    nodesEnter.append("text")
        .attr("dy", "20px")
        .attr("dx", "")
        .attr("x", "")
        .attr("y", "")
        .attr("text-anchor", "middle")
        .style("fill-opacity", 1)
        .text(function(d) { return d.value });


    force.start();
}

function tick() {
    links.attr("x1", function(d) { return d.source.x; })
        .attr("y1", function(d) { return d.source.y; })
        .attr("x2", function(d) { return d.target.x; })
        .attr("y2", function(d) { return d.target.y; });

    nodes.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
}

function drag(force) {
    function dragstart(d, i) {
        force.stop();
        d3.event.sourceEvent.stopPropagation();
        // if (!d3.event.active) {
        //     force.resume()
        // }

    }

    function dragmove(d, i) {
        d.px += d3.event.dx;
        d.py += d3.event.dy;
        d.x += d3.event.dx;
        d.y += d3.event.dy;
        tick();
    }

    function dragend(d, i) {
        d.fixed = true;
        // tick();
        force.resume();
    }
    
    return d3.behavior.drag()
        // .filter(dragfilter)
        .on("dragstart", dragstart)
        .on("drag", dragmove)
        .on("dragend", dragend)
}

function unselectAll() {
    $('#graphContainer g.nodes > g.node').removeClass('selected');
    $('#graphContainer g.links > line.link').removeClass('selected');
}

function clickHandlerSvg(e) {
    // if (d3.event.target.id == 'relationGraphSVG') {
    //     generateTooltip(null, 'hide');
    // }
}

function clickHandlerNode(d) {
    var $d3Element = $(this);
    unselectAll();
    $d3Element.addClass('selected');
    generateTooltip(d, 'node');
}

function clickHandlerLink(d) {
    var $d3Element = $(this);
    unselectAll();
    $d3Element.addClass('selected');
    generateTooltip(d, 'link');
}

function generateTooltip(d, type) {
    $div =  $('#tooltipContainer');
    $div.empty();
    tableArray = [];
    title = '';
    $div.show();
    if (type === 'node') {
        title = d.value;
        tableArray = [
            {label: '<?= __('Name') ?>', value: d.value, url: {path: '<?= sprintf('%s/galaxy_clusters/view/', $baseurl) ?>', id: d.id}},
            {label: '<?= __('Galaxy') ?>', value: d.type, url: {path: '<?= sprintf('%s/galaxies/view/', $baseurl) ?>', id: d.galaxy_id}},
            {label: '<?= __('Default') ?>', value: d.default},
            {label: '<?= __('Tag name') ?>', value: d.tag_name},
            {label: '<?= __('Version') ?>', value: d.version},
            {label: '<?= __('UUID') ?>', value: d.uuid}
        ]
    } else if (type === 'link') {
        title = d.type;
        tableArray = [
            {label: '<?= __('Source') ?>', value: d.source.value},
            {label: '<?= __('Target') ?>', value: d.target.value},
            {label: '<?= __('Type') ?>', value: d.type},
        ]
        if (d.tag !== undefined) {
            tableArray.push({label: '<?= __('Tag name') ?>', value: (d.tag.name !== undefined ? d.tag.name : '- none -')});
            if (d.tag.numerical_value !== undefined) {
                tableArray.push({label: '<?= __('Numerical value') ?>', value: d.tag.numerical_value});
            }
        }
    } else if (type == 'hide') {
        $div.hide();
        return;
    }
    $div.append($('<button></button>').css({'margin-right': '2px'}).addClass('close').text('×').click(function() { generateTooltip(null, 'hide') }));
    $div.append($('<h6></h6>').css({'text-align': 'center'}).text(title));
    if (tableArray.length > 0) {
        var $table = $('<table class="table table-condensed"></table>');
        $body = $('<tbody></tbody>');
        tableArray.forEach(function(row) {
            var $cell1 = $('<td></td>').text(row.label);
            var $cell2 = $('<td></td>');
            if (row.url !== undefined) {
                var completeUrl = row.url.path + (row.url.id !== undefined ? row.url.id : '');
                $cell2.append($('<a></a>').attr('href', completeUrl).attr('target', '_blank').text(row.value));
            } else {
                $cell2.text(row.value);
            }
            $body.append(
                $('<tr></tr>').append(
                    $cell1,
                    $cell2
                )
            );
        })
        $table.append($body);
        $div.append(
            $table
        );
    }
}

function drawLabels() {
    labels = svg.select('.legend')
        .selectAll('.labels')
        .data(legendLabels);
    var label = labels.enter()
        .append('g')
        .attr('class', 'labels')
    label.append('circle')
    label.append('text')

    labels.selectAll('circle')
        .style('fill', function(d, i){ return d.color })
        .style('stroke', function(d, i){ return d.color })
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
    var ypos = 10, newxpos = 20, xpos;
    label
        .attr('transform', function(d, i) {
            var length = d3.select(this).select('text').node().getComputedTextLength() + 28;
            var xpos = newxpos;

            if (width < (margin.left) + margin.right + xpos + length) {
                newxpos = xpos = 20;
                ypos += 20;
            }

            newxpos += length;

            return 'translate(' + xpos + ',' + ypos + ')';
        })
    var legendBB = svg.select('.legend').node().getBBox();
    var pad = 3;
    svg.select('.legendContainer').insert('rect', ':first-child')
        .style('fill', '#fff')
        .attr('x', legendBB.x - pad)
        .attr('y', legendBB.y - pad)
        .attr('width', legendBB.width + pad)
        .attr('height', legendBB.height + pad)
        .style('stroke', '#eee');
}
</script>

<style>
#graphContainer g.node.selected > circle {
    r: 7;
    stroke-width: 2px !important;
}

#graphContainer g.node.selected > text {
    font-weight: bold;
}

#graphContainer line.link.selected {
    stroke-width: 3;
}
</style>