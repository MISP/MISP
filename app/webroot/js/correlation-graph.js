$(document).ready( function() {

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
  $('#hover-menu-container').css('top', '50px');
  $('#hover-menu-container').css('z-index', 0);
  $('#selected-menu-container').css('top', '400px');
  $('#selected-menu-container').css('z-index', 1);

  var root;

  var highlighted;
  var hovered;

  var icon_sizes = {
  	"event": 24,
  	"object": 12,
  	"attribute": 12,
  	"galaxy": 32,
  	"tag": 24
  }

  var selection_radius_sizes = {
  	"event": 18,
  	"object": 12,
  	"attribute": 12,
  	"galaxy": 18,
  	"tag": 18
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

  var scope_id = $('#graph_init').data('id');
  var scope = $('#graph_init').data('scope');

  d3.json("/events/updateGraph/" + scope_id + "/" + scope + ".json", function(error, json) {
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

  	nodeEnter.attr('id', function(d) { return 'id-' + d.unique_id; })

  	nodeEnter.insert("circle", ".circle")
  		.classed("highlighted_circle", true)
  		.attr("cx", function(d) { return d.x_axis; })
  		.attr("cy", function(d) { return d.y_axis; })
  		.attr("r", function(d) { return selection_radius_sizes[d.type] })
  		.attr("stroke", "red")
  		.attr("stroke-opacity", "0")
  		.attr("fill-opacity", "0")
  		.attr("fill", "red");

  	nodeEnter.filter(function(d) {return d.image !== undefined})
  	.append("svg:image")
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

  	nodeEnter.filter(function(d) {return d.imgClass !== undefined})
  	.append("g")
  	.append('svg:foreignObject')
  	.attr("width", 12)
  	.attr("height", 12)
  	.attr("x", function(d) {
  			if (d.type == 'galaxy' || d.type == 'tag') {
  				return '-10px';
  			} else {
  				return '-6px';
  			}
  		}
  	)
  	.attr("y", function(d) {
  			if (d.type == 'galaxy' || d.type == 'tag') {
  				return '-12px';
  			} else {
  				return '-8px';
  			}
  		}
  	)
  	.append("xhtml:body")
  	.html(function (d) {
  		var result = 'fa-' + d.imgClass;
  		if (d.type == 'galaxy' || d.type == 'tag') result = 'fa-2x ' + result;
  		return '<i class="fa ' + result + '"></i>';
  	});

  	nodeEnter.append("text")
  		.attr("dy", function(d) {
  				if (d.type == "event" || d.type == "galaxy") {
  					return "10px";
  				} else {
  					return "0px";
  				}
  		})
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
  		showPane(d, 'selected');
  	});
  }

  function highlightNode(d) {
  	d3.selectAll('.highlighted_circle')
  	.style("stroke-opacity", 0);
  	d3.select('#id-' + d.unique_id)
  	.select('.highlighted_circle')
  	.style("stroke", "red")
  	.style("stroke-opacity", 0.5);
  }

  function contextMenu(d, newContext) {
  	d3.event.preventDefault();
  	if (d.type == 'event') showPane(d, 'context');
  }

  function bindExpand(d, type) {
  	if (!d.expanded) {
  		var expandName = 'Expand (ctrl+x)';
  		if (type == 'selected') {
  			expandName = 'Expand (x)';
  		}
  		$("#" + type + "-menu").append('<li id="expand_' + type + '_' + d.id +'" class="graphMenuAction"><span>' + expandName + '</span></li>');
  		d3.select('#expand_' + type + '_' + d.id)
  			.on('click', function() {
  				expand(d);
  		});
  	}
  }

  function remove_node(d) {
    var index = root.nodes.indexOf(d);
    if (index > -1) {
      root.nodes.splice(index, 1);
    }
    var temp = [];
    root['links'].forEach(function(n) {
      if (n.source != d && n.target != d) {
        temp.push(n);
      }
    });
    root['links'] = temp;

    var i = 0;
    var links = [];
    root.links.forEach(function(l) {
      var j = 0;
      var temp = {};
      root.nodes.forEach(function(n) {
        if (l.source == n) {
          temp.source = j;
        }
        if (l.target == n) {
          temp.target = j;
        }
        var j = j+1;
      });
      temp.linkDistance = l.linkDistance;
      links.push(temp);
      var i = i+1;
    });
    root = {
      'nodes': root['nodes'],
      'links': root['links']
    };
    update();
  }

/*
  function bindDelete(d, type) {
  	var deleteName = 'Delete (ctrl+d)';
  	if (type == 'selected') {
  		deleteName = 'Delete (d)';
  	}
  	$("#" + type + "-menu").append('<li id="remove_' + type + '_' + d.id +'" class="graphMenuAction"><span>' + deleteName + '</span></li>');
  	d3.select('#remove_' + type + '_' + d.id)
  		.on('click', function() {
  			remove_node(d);
  	});
  }
  */

  function createInfoPane(d, data, type) {
  	var i = 0;
  	var view_urls = {
  		'event': '/events/view/' + parseInt(d.id),
  		'tag': '/tags/view/' + parseInt(d.id),
  		'galaxy': '/galaxy_clusters/view/' + parseInt(d.id)
  	};
  	data["fields"].forEach(function(e) {
  		var title = e;
  		if (i == 0) title = d.type;
  		title = title.split("_").join(" ");
  		title = title.charAt(0).toUpperCase() + title.slice(1);
  		var span1 = $('<span />').text(title + ': ');
  		var span2 = $('<span />').text(d[e]);
  		var li = $('<li />');
  		li.append(span1);
  		li.append(span2);
  		if (i == 0) li.addClass('graphMenuTitle');
  		i++;
  		$("#" + type + "-menu").append(li);
  	});
  	$("#" + type + "-menu").append('<li class="graphMenuActions">Actions</li>');
  	if ($.inArray("navigate", data["actions"]) !== -1) {
  		$("#" + type + "-menu").append('<li><span><a href="' + view_urls[d.type] + '">Go to ' + d.type + '</a></span></li>');
  	}
  	if ($.inArray("expand", data["actions"]) !== -1) {
  		bindExpand(d, type);
  	}
  	if ($.inArray("delete", data["actions"]) !== -1) {
  		bindDelete(d, type);
  	}
  }

  function showPane(d, type) {
  	if (type == 'hover') {
  		hovered = d;
  	} else {
  		highlighted = d;
  		highlightNode(d);
  	}
  	$('#' + type + '-header').show();
  	d3.select("#" + type + "-menu").style('display', 'inline-block');
  	$("#" + type + "-menu").empty();
  	if (d.type== 'attribute') {
  		var data = {
  			"fields": ["id", "name", "category", "type", "comment"],
  			"actions": ["delete"]
  		}
  	}
  	if (d.type== 'event') {
  		var tempid = parseInt(d.id);
  		var data = {
  			"fields": ["id", "info", "date", "analysis", "org"],
  			"actions": ["expand", "delete", "navigate"]
  		}
  	}
  	if (d.type == 'tag') {
  		var data = {
  			"fields": ["id", "name"],
  			"actions": ["expand", "delete"]
  		}
  		if (d.taxonomy !== undefined) {
  			data["fields"].push("taxonomy");
  			data["fields"].push("taxonomy_description");
  			if (d.description !== "") {
  				data["fields"].push("Description");
  			}
  		}
  	}
  	if (d.type == 'galaxy') {
  		var data = {
  			"fields": ["id", "name", "galaxy", "synonyms", "authors", "description", "source"],
  			"actions": ["expand", "delete", "navigate"]
  		}
  	}
  	if (d.type == 'object') {
  		var data = {
  			"fields": ["id", "name", "metacategory", "description", "comment"],
  			"actions": ["delete"]
  		}
  	}
  	createInfoPane(d, data, type);
  }

  function expand(d) {
  	if (d.type == 'event' || d.type == 'galaxy' || d.type == 'tag') {
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

  function searchArray(arr, val) {
  	for (var i=0; i < arr.length; i++)
  		if (arr[i] === val)
  				return i;
  	return false;
  }

  $(document).on('keydown', function(e) {
  	if (e.which == 69) {
  		if (highlighted == undefined) {
  			showPane(root['nodes'][0], 'selected');
  		} else {
  			var current = searchArray(root['nodes'], highlighted);
  			if (current == root['nodes'].length-1) {
  				showPane(root['nodes'][0], 'selected');
  			} else {
  				showPane(root['nodes'][current+1], 'selected');
  			}
  		}
  	}
  	if (e.which == 81) {
  		if (highlighted == undefined) {
  			showPane(root['nodes'][root['nodes'].length-1], 'selected');
  		} else {
  			var current = searchArray(root['nodes'], highlighted);
  			if (current == 0) {
  				showPane(root['nodes'][root['nodes'].length-1], 'selected');
  			} else {
  				showPane(root['nodes'][current-1], 'selected');
  			}
  		}
  	}
  });

  /*
  $(document).on('keydown', function(e) {
  	if (e.which == 68) {
  		e.preventDefault();
  		if (e.ctrlKey) {
  			if (hovered != undefined) {
  				remove_node(hovered);
  			}
  		} else {
  			if (highlighted != undefined) {
  				remove_node(highlighted);
  			}
  		}
  	}
  });
  */

  $(document).on('keydown', function(e) {
  	if (e.which == 88) {
  		e.preventDefault();
  		if (e.ctrlKey) {
  			if (hovered != undefined) {
  				expand(hovered);
  			}
  		} else {
  			if (highlighted != undefined) {
  				expand(highlighted);
  			}
  		}
  	}
  });
});
