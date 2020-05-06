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
<div style="border: 1px solid #ddd">
    <div id="graphContainer" style="height: 70vh;"></div>
</div>

<script>
var graph = <?= json_encode($relations) ?>;
var nodes, links;
var width, height, margin;
var vis, svg, plotting_area, force, container, zoom;
var graphElementScale = 1;
var graphElementTranslate = [0, 0];
var nodeHeight = 20;
var nodeWidth = 120;

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
    graph.links.forEach(function(link) {
        var tmpNode = graph.nodes.filter(function(node) {
            return node.id == link.source;
        })
        link.source = tmpNode[0]
        if (tmpNode[0] === undefined) {
            console.log(link);
        }
        tmpNode = graph.nodes.filter(function(node) {
            return node.id == link.target;
        })
        if (tmpNode[0] === undefined) {
            console.log(link);
        }
        link.target = tmpNode[0]
        correctLink.push(link)
    })
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
        .style("fill", "lightsteelblue")
        .style("stroke", "steelblue")
        .style("stroke-width", "2px");
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
</script>
<?php endif; ?>