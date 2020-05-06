<?php
echo $this->element('genericElements/assetLoader', array(
    'js' => array('d3')
));
?>
<h6>
    <a class="" href="<?= sprintf('%s/galaxies/view/%s/context:all', $baseurl, $galaxy_id) ?>">
        <i class="<?php echo $this->FontAwesome->findNamespace('arrow-left'); ?> fa-arrow-left"></i>
        <?= __('Back to galaxy') ?>
    </a>
</h6>
<?php if (empty($relations)): ?>
<div class="alert alert-info">
    <?= __('There are no relations in this Galaxy'); ?>
</div>
<?php else: ?>
<div style="margin-bottom: 10px;">
    <div id="graphContainer" style="height: 70vh; border: 1px solid #ddd; "></div>
</div>

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
        .theta(0.9)
        .linkDistance(60)
        .on("tick", tick)

    vis = d3.select("#graphContainer");

    svg = vis.append("svg")
        .attr("width", width)
        .attr("height", height)
    container = svg.append("g").attr("class", "zoomContainer")
    zoom = d3.behavior.zoom()
        .on("zoom", zoomHandler);
    svg.call(zoom);

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
        .attr("class", "link")
        .attr("class", d => { return "link" })
        .attr("stroke", "#999")
        .attr("stroke-opacity", 0.6)
        .style("stroke-width", function(d) { return Math.sqrt(d.weight ? d.weight : 1) })
        
    nodes = container.append("g")
        .attr("class", "nodes")
        .selectAll("div")
        .data(graph.nodes);
    nodes.exit().remove();
    var nodesEnter = nodes.enter()
        .append('g')
        .call(drag(force))

    // nodesEnter.append("foreignObject")
    //     .attr("height", nodeHeight)
    //     .attr("width", nodeWidth)
    //     .classed("nodeFO", true)
    //     .append("xhtml:div")
    //     .html(function(d) {
    //         return '<span class="label label-info">' + d.value + '</span>'
    //     })
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
<?php endif; ?>