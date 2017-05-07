<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);

echo $this->Html->script('d3');?>
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
</style>
<div class="view">
<div id="chart" style="width:100%;height:100%"></div>
<ul id="context-menu" class="menu">
	<li id="expand">Expand</li>
	<li id="context-delete">Delete</li>
</ul>
<ul id="event-info-pane" class="menu" style="width:200px;">
	<li id="event-info-pane-title" style="background-color:#0088cc;color:white;"></li>
	<li id="event-info-pane-org"></li>
	<li id="event-info-pane-date"></li>
	<li id="event-info-pane-analysis"></li>
	<li id="event-info-pane-distribution"></li>
	<li id="event-info-pane-info"></li>
	<li id="event-info-pane-url-container"><a href="/" id="event-info-pane-url" style="color:white;text-decoration:underline;"></a></li>
</ul>
<ul id="attribute-info-pane" class="menu" style="width:200px;">
	<li id="attribute-info-pane-title" style="background-color:#0088cc;color:white;"></li>
	<li id="attribute-info-pane-value"></li>
	<li id="attribute-info-pane-category"></li>
	<li id="attribute-info-pane-type"></li>
	<li id="attribute-info-pane-comment"></li>
</ul>
<ul id="tag-info-pane" class="menu" style="width:200px;">
	<li id="tag-info-pane-title" style="background-color:#0088cc;color:white;"></li>
	<li id="tag-info-pane-name"></li>
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
height = $(window).height() - 200 - margin.top - margin.bottom;

var root;

var force = d3.layout.force()
	.linkDistance(150)
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

	nodeEnter.append("svg:image")
	.attr("class", "circle")
	.attr("xlink:href", function(d) {
		return d.image
	})
	.attr("x", function(d) {
		if (d.type == 'event') return "-12px";
		else return "-6px";
	})
	.attr("y", function(d) {
		if (d.type == 'event') return "-12px";
		else return "-7px";
	})
	.attr("width", function(d) {
		if (d.type == 'event') return "24px";
		else return "12px";
	})
	.attr("height", function(d) {
		if (d.type == 'event') return "24px";
		else return "14px";
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
			return d.name;
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
		showPane('#' + d.type + '-info-pane', d, 'left');
	});

	node.on('mouseout', function() {
		  link.style('stroke-width', 1);
		  link.style('stroke', "#9ecae1");
	});

	node.on("dblclick", function(d) {
		contextMenu(d, 'node');
		d3.event.preventDefault();
	});
}

function contextMenu(d, newContext) {
	d3.event.preventDefault();
	// hide all other panes
	if (d.type == 'event') {
		showPane('#context-menu', d, 'right')
		d3.select('#expand')
			.on('click', function() {
				expand(d);
			});
	}
}

function showPane(context, d, side) {
	d3.select('#attribute-info-pane').style('display', 'none');
	d3.select('#context-menu').style('display', 'none');
	d3.select('#event-info-pane').style('display', 'none');
	d3.select('#tag-info-pane').style('display', 'none');
	var offset = (graphElementScale * 24) + 6;
	var offsety = -10;
	if (side == 'left') {
		offset = - (graphElementScale * 24) - 206;
		offsety = -60;
	}
	d3.select(context)
	.style('position', 'absolute')
	.style('left', currentMousePos.x + offset + "px")
	.style('top', currentMousePos.y + offsety + "px")
	.style('display', 'inline-block')
	.on('mouseleave', function() {
		d3.select(context).style('display', 'none');
	});
	if (d.type== 'attribute') {
		$('#attribute-info-pane-title').text('Attribute: ' + d.id);
		$('#attribute-info-pane-value').text('Value: ' + d.name);
		$('#attribute-info-pane-category').text('Category: ' + d.att_category);
		$('#attribute-info-pane-type').text('Type: ' + d.att_type);
		$('#attribute-info-pane-comment').text('Comment: ' + d.comment);
	}
	if (d.type== 'event') {
		var tempid = parseInt(d.id);
		$('#event-info-pane-title').text('Event: ' + d.id);
		$('#event-info-pane-info').text('Info: ' + d.info);
		$('#event-info-pane-date').text('Date: ' + d.date);
		$('#event-info-pane-analysis').text('Analysis: ' + d.analysis);
		$('#event-info-pane-org').text('Organisation: ' + d.org);
		$('#event-info-pane-url').attr('href', '/events/' + tempid);
		$('#event-info-pane-url').text('Go to event');
	}
	if (d.type == 'tag') {
		$('#tag-info-pane-title').text('Tag: ' + d.name);
	}
}

function expand(d) {
	d3.event.stopPropagation();
	d3.event.preventDefault();
	if (d.type == 'event') {
		d3.xhr("/events/updateGraph/" + d.id + ".json")
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
