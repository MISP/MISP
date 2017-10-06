<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);

echo $this->Html->script('d3'); ?>
<style>

	.node circle {
		cursor: pointer;
		stroke: #3182bd;
		stroke-width: 1.5px;
	}
	.node text {
		font: 10px sans-serif;
		pointer-events: none;
		text-anchor: middle;
	}
	line.link {
		fill: none;
		stroke: #9ecae1;
		stroke-width: 1.5px;
	}
	#main {
		display: inline-block;
		background-color: grey;
		position: relative;
	}
	.menu {
		border: 1px solid black;
		background-color: grey;
		display: none;
		position: relative;
	}
	.menu,
	.menu li {
		padding: 0px;
		margin: 0px;
		width: 250px;
	}
	.menu li {
		color: white;
	}
	.menu > li:hover {
		background-color: lightblue;
		color: black;
	}
	.menu li {
		display: block;
	}
	.menu li:hover ul {
		display:inline-block;
		position: relative;
		top: 0;
	}
	.menu > li > a {
		color:white;
	}
	.graphMenuTitle {
		background-color:#0088cc;
		font-weight:bold;
		color:white;
	}
	.graphMenuActions {
		background-color:#0088cc;
		color:white;
	}
	.graphMenuAction {
		cursor: hand;
	}

	.menu-container {
		position:absolute;
		width:300px;
	}
</style>
<div class="view">
<div id="chart" style="width:100%;height:100%"></div>
	<div id="hover-menu-container" class="menu-container">
		<span class="bold hidden" id="hover-header">Hover target</span><br />
		<ul id="hover-menu" class="menu">
		</ul>
	</div>
	<div id="selected-menu-container" class="menu-container">
		<span class="bold hidden" id="selected-header">Selected</span><br />
		<ul id = "selected-menu" class="menu">
		</ul>
	</div>
	<ul id="context-menu" class="menu">
		<li id="expand">Expand</li>
		<li id="context-delete">Delete</li>
	</ul>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'viewEventGraph', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>
<script>
var currentMousePos = { x: -1, y: -1 };
$(document).mousemove(function(event) {
	currentMousePos.x = event.pageX;
	currentMousePos.y = event.pageY;
});

var margin = {top: -5, right: -5, bottom: -5, left: -5},
width = $(window).width() - margin.left - margin.right,
height = $(window).height() - 160 - margin.top - margin.bottom;
var menu_x_buffer_ = width - 150;
var menu_y_buffer = height - 100;
$('.menu-container').css('left', '200px');
$('#hover-menu-container').css('top', '100px');
$('#selected-menu-container').css('top', '400px');

var root;

var highlighted;

var icon_sizes = {
	"event": 24,
	"object": 12,
	"attribute": 12,
	"galaxy": 24,
	"tag": 12
}

var selection_radius_sizes = {
	"event": 18,
	"object": 12,
	"attribute": 12,
	"galaxy": 18,
	"tag": 12
}

var force = d3.layout.force()
	.linkDistance(function (d) {
  	return d.linkDistance;
  })
	.linkStrength(0.9)
	.friction(0.5)
	.theta(0.9)
	.charge(-500)
	.gravity(0.21)
	.size([width, height])
	.on("tick", tick);

var vis = d3.select("#chart");

var svg	= vis.append("svg:svg")
		.attr("width", width)
		.attr("height", height)
		.attr("pointer-events", "all");

var rect = svg.append("svg:rect")
	.attr('width', width)
	.attr('height', height)
	.attr('fill', 'white')
	.call(d3.behavior.zoom().on("zoom", zoomhandler));

var plotting_area = svg.append("g")
		.attr("class", "plotting-area");

var drag1 = d3.behavior.drag()
	.on("dragstart", dragstart)
	.on("drag", dragmove)
	.on("dragend", dragend);

var link = plotting_area.selectAll(".link");
var node = plotting_area.selectAll(".node");

d3.json("/events/updateGraph/<?php echo $id; ?>.json", function(error, json) {
	root = json;
	update();
});

var graphElementScale = 1;
var graphElementTranslate = [0, 0];

function zoomhandler() {
	plotting_area.attr("transform",
		"translate(" + d3.event.translate + ")"
		+ " scale(" + d3.event.scale + ")");
	graphElementScale = d3.event.scale;
	graphElementTranslate = d3.event.translate;
}

function update() {
	var nodes = root['nodes'], links = root['links'];


	// Restart the force layout.
	force.nodes(nodes).links(links).start();

	// Update links.
	link = link.data(links);
	link.exit().remove();
	link.enter().insert("line", ".node").attr("class", "link");
	// Update nodes.
	node = node.data(nodes);
	node.exit().remove();

	var nodeEnter = node.enter().append("g").attr("class", "node").call(drag1);

	nodeEnter.insert("circle", ".circle")
		.classed("highlighted_circle", true)
		.attr("cx", function(d) { return d.x_axis; })
		.attr("cy", function(d) { return d.y_axis; })
		.attr("r", function(d) { return selection_radius_sizes[d.type] })
		.attr("stroke", "red")
		.attr("stroke-opacity", "0")
		.attr("fill-opacity", "0")
		.attr("fill", "red");

	nodeEnter.append("svg:image")
	.attr("class", "circle")
	.attr("xlink:href", function(d) {
		return d.image
	})
	.attr("x", function(d) {
		return (0 - (icon_sizes[d.type]/2)) + "px";
	})
	.attr("y", function(d) {
		return (0 - (icon_sizes[d.type]/2)) + "px";
	})
	.attr("width", function(d) {
		return ((icon_sizes[d.type])) + "px";
	})
	.attr("height", function(d) {
		return ((icon_sizes[d.type])) + "px";
	});

	nodeEnter.append("text")
		.attr("dy", ".35em")
		.attr("fill", function(d) {
			if (d.type == "event") {
				if (d.expanded == 1) {
					return "#0000ff";
				} else {
					return "#ff0000";
				}
			}
		})
		.text(function(d) {
			return d.type + ': ' + d.name;
		});

	node.selectAll("text")
	.attr("y", 20);

	node.on('mouseover', function(d) {
		link.style('stroke', function(l) {
			if (d === l.source || d === l.target)
				return "#ff0000";
			else
				return "#9ecae1";
		});
		link.style('stroke-width', function(l) {
			if (d === l.source || d === l.target)
				return 2;
			else
				return 1;
		});
		showPane(d, 'hover');
	});

	node.on('mouseout', function() {
		  link.style('stroke-width', 1);
		  link.style('stroke', "#9ecae1");
	});

	node.on("click", function(d) {
		highlighted = d;
		showPane(d, 'selected')
		d3.selectAll('.highlighted_circle')
		.style("stroke-opacity", 0);
		d3.select(this)
		.select('.highlighted_circle')
		.style("stroke", "red")
		.style("stroke-opacity", 0.5);
	});

	node.on("dblclick", function(d) {
		contextMenu(d, 'node');
		d3.event.preventDefault();
	});
}

function contextMenu(d, newContext) {
	d3.event.preventDefault();
	if (d.type == 'event') showPane(d, 'context');
}

function showPane(d, type) {
	$('#' + type + '-header').show();
	d3.select("#" + type + "-menu").style('display', 'inline-block');
	$("#" + type + "-menu").empty();
	if (d.type== 'attribute') {
		$("#" + type + "-menu").append('<li class="graphMenuTitle">Attribute: ' + d.id + '</li>');
		$("#" + type + "-menu").append('<li>Value: ' + d.name + '</li>');
		$("#" + type + "-menu").append('<li>Category: ' + d.att_category + '</li>');
		$("#" + type + "-menu").append('<li>Type: ' + d.att_type + '</li>');
		$("#" + type + "-menu").append('<li>Comment: ' + d.att_comment + '</li>');
	}
	if (d.type== 'event') {
		var tempid = parseInt(d.id);
		$("#" + type + "-menu").append('<li class="graphMenuTitle">Event: '+ d.id + '</li>');
		$("#" + type + "-menu").append('<li>Info: ' + d.info + '</li>');
		$("#" + type + "-menu").append('<li>Date: ' + d.date + '</li>');
		$("#" + type + "-menu").append('<li>Analysis: ' + d.analysis + '</li>');
		$("#" + type + "-menu").append('<li>Organisation: ' + d.org + '</li>');
		$("#" + type + "-menu").append('<li>Value: ' + d.name + '</li>');
		$("#" + type + "-menu").append('<li class="graphMenuActions">Actions</li>');
		$("#" + type + "-menu").append('<li><a href="/events/' + parseInt(d.id) + '"> Go to event </a></li>');
		if (!d.expanded) {
			$("#" + type + "-menu").append('<li id="expand_' + type + '_' + d.id +'" class="graphMenuAction">Expand</li>');
			d3.select('#expand_' + type + '_' + d.id)
				.on('click', function() {
					expand(d);
				});
		}
	}
	if (d.type == 'tag') {
		$("#" + type + "-menu").append('<li class="graphMenuTitle">Tag: '+ d.id + '</li>');
		$("#" + type + "-menu").append('<li>Name: ' + d.name + '</li>');
		$("#" + type + "-menu").append('<li>Colour: ' + d.colour + '</li>');
	}
	if (d.type == 'galaxy') {
		$("#" + type + "-menu").append('<li class="graphMenuTitle">' + d.galaxy + ': '+ d.id + '</li>');
		$("#" + type + "-menu").append('<li>Name: ' + d.name + '</li>');
		$("#" + type + "-menu").append('<li>Synonyms: ' + d.synonyms + '</li>');
		$("#" + type + "-menu").append('<li>Authors: ' + d.authors + '</li>');
		$("#" + type + "-menu").append('<li>Description: ' + d.description + '</li>');
		$("#" + type + "-menu").append('<li>Source: ' + d.source + '</li>');
	}
	if (d.type == 'object') {
		$("#" + type + "-menu").append('<li class="graphMenuTitle">' + d.name + ' object: '+ d.id + '</li>');
		$("#" + type + "-menu").append('<li>Meta-category: ' + d.metacategory + '</li>');
		$("#" + type + "-menu").append('<li>Description: ' + d.description + '</li>');
		$("#" + type + "-menu").append('<li>Comment: ' + d.comment + '</li>');
	}
}

function expand(d) {
	d3.event.stopPropagation();
	d3.event.preventDefault();
	if (d.type == 'event') {
		d3.xhr("/events/updateGraph/" + d.id + "/" + d.type + ".json")
	    .header("Content-Type", "application/json")
	    .post(
	        JSON.stringify(root),
	        function(err, rawData){
		        root = JSON.parse(rawData.response);
		        update();
	        }
	    );
	}
}

function tick() {
	link.attr("x1", function(d) { return d.source.x; })
		.attr("y1", function(d) { return d.source.y; })
		.attr("x2", function(d) { return d.target.x; })
		.attr("y2", function(d) { return d.target.y; });

	node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
}

// Returns a list of all nodes under the root.
function flatten(root) {
	var nodes = [], i = 0;

	function recurse(node) {
		if (node.children) node.children.forEach(recurse);
		if (!node.id) node.id = ++i;
		nodes.push(node);
	}

	recurse(root);
	return nodes;
}


function dragstart(d, i) {
	force.stop();
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
	tick();
	force.resume();
}
</script>
