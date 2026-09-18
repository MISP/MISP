// correlation-graph.js without jquery

var pinNodes = true;

function togglePhysics() {
    d3.selectAll(".node").each(function(d) {
        d.fixed = pinNodes;
    });
    pinNodes = !pinNodes;
}

document.addEventListener('DOMContentLoaded', function() {
    var currentMousePos = { x: -1, y: -1 };
    document.addEventListener('mousemove', function(event) {
        currentMousePos.x = event.pageX;
        currentMousePos.y = event.pageY;
    });

    function getGraphSize() {
        const el = document.getElementById('correlationgraph_div');
        return {
            width: el.clientWidth,
            height: el.clientHeight
        };
    }

    var size = getGraphSize();
    var width = size.width;
    var height = size.height;

    var graphInitEl = document.getElementById('graph_init');

    if (graphInitEl.dataset.ajax) {
        document.querySelectorAll('.menu-container').forEach(function(el) {
            el.style.left = '20px';
        });
        document.getElementById('hover-menu-container').style.top = '20px';
        document.getElementById('selected-menu-container').style.top = '270px';
    } else {
        document.querySelectorAll('.menu-container').forEach(function(el) {
            el.style.left = '200px';
        });
        document.getElementById('hover-menu-container').style.top = '50px';
        document.getElementById('selected-menu-container').style.top = '400px';
    }

    document.getElementById('hover-menu-container').style.zIndex = 0;
    document.getElementById('selected-menu-container').style.zIndex = 1;

    const fullscreenBtn = document.getElementById('fullscreen-btn-correlation');
    const graphContainer = document.getElementById('correlationgraph_div');

    if (fullscreenBtn && graphContainer) {
        fullscreenBtn.addEventListener('click', () => {

            const isFullscreen = graphContainer.classList.toggle('fullscreen');

            const icon = fullscreenBtn.querySelector('i');
            if (isFullscreen) {
                icon.classList.replace('fa-expand', 'fa-compress');
            } else {
                icon.classList.replace('fa-compress', 'fa-expand');
            }

            setTimeout(() => {
                window.dispatchEvent(new Event('resize'));
            }, 100);
        });
    }

    var root;
    var toIdsOnly = false;
    var highlighted;
    var hovered;

    var icon_sizes = {
        "event": 24,
        "object": 12,
        "attribute": 12,
        "galaxy": 32,
        "tag": 24
    };

    var selection_radius_sizes = {
        "event": 18,
        "object": 12,
        "attribute": 12,
        "galaxy": 18,
        "tag": 18
    };

    var force = d3.layout.force()
        .linkDistance(function(d) {
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

    var svg = vis.append("svg:svg")
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

    var scope_id = graphInitEl.dataset.id;
    var scope = graphInitEl.dataset.scope;

    d3.json(baseurl + "/events/updateGraph/" + scope_id + "/" + scope + ".json", function(error, json) {
        root = json;
        resolveLinkEnds(root);
        update();
    });

    const toIdsBtn = document.getElementById('correlation-toids-btn');

    if (toIdsBtn) {
        toIdsBtn.addEventListener('click', function() {
            toIdsOnly = !toIdsOnly;
            toIdsBtn.classList.toggle('active', toIdsOnly);
            toIdsBtn.setAttribute('aria-pressed', toIdsOnly ? 'true' : 'false');
            update();
        });
    }

    var graphElementScale = 1;
    var graphElementTranslate = [0, 0];

    function zoomhandler() {
        plotting_area.attr("transform",
            "translate(" + d3.event.translate + ")"
            + " scale(" + d3.event.scale + ")");
        graphElementScale = d3.event.scale;
        graphElementTranslate = d3.event.translate;
    }

    // The graph JSON ships the to_ids flag of every attribute node as att_ids.
    // CakePHP casts the tinyint(1) to_ids column to a boolean, so the value on
    // the wire is true/false - 1 and "1" are accepted defensively.
    function isToIdsNode(d) {
        return d.att_ids === true || d.att_ids === 1 || d.att_ids === '1';
    }

    // The server sends link endpoints as node indexes; d3 replaces them with
    // node references on force.start(). Resolve them up front so that the filter
    // can always look at the node objects, including before the first render.
    function resolveLinkEnds(graph) {
        graph['links'].forEach(function(l) {
            if (typeof l.source === 'number') l.source = graph['nodes'][l.source];
            if (typeof l.target === 'number') l.target = graph['nodes'][l.target];
        });
    }

    // Never mutate root: it is posted back to the server on expand() so that the
    // already known part of the graph can be deduplicated there.
    function visibleGraph() {
        if (!toIdsOnly) {
            return root;
        }
        var kept = {};
        var nodes = root['nodes'].filter(function(d) {
            var keep = d.type !== 'attribute' || isToIdsNode(d);
            if (keep) kept[d.unique_id] = true;
            return keep;
        });
        var links = root['links'].filter(function(l) {
            return kept[l.source.unique_id] && kept[l.target.unique_id];
        });
        return {'nodes': nodes, 'links': links};
    }

    function update() {
        var graph = visibleGraph();
        var nodes = graph['nodes'], links = graph['links'];

        force.nodes(nodes).links(links).start();

        link = link.data(links);
        link.exit().remove();
        link.enter().insert("line", ".node").attr("class", "link");

        node = node.data(nodes, function(d) { return d.unique_id; });
        node.exit().remove();

        var nodeEnter = node.enter().append("g").attr("class", "node").call(drag1);

        nodeEnter.attr('id', function(d) { return 'id-' + d.unique_id; });

        nodeEnter.insert("circle", ".circle")
            .classed("highlighted_circle", true)
            .attr("cx", function(d) { return d.x_axis; })
            .attr("cy", function(d) { return d.y_axis; })
            .attr("r", function(d) { return selection_radius_sizes[d.type]; })
            .attr("stroke", "red")
            .attr("stroke-opacity", "0")
            .attr("fill-opacity", "0")
            .attr("fill", "red");

        nodeEnter.filter(function(d) { return d.image !== undefined; })
            .append("svg:image")
            .attr("class", "circle")
            .attr("xlink:href", function(d) { return d.image; })
            .attr("x", function(d) { return (0 - (icon_sizes[d.type] / 2)) + "px"; })
            .attr("y", function(d) { return (0 - (icon_sizes[d.type] / 2)) + "px"; })
            .attr("width", function(d) { return (icon_sizes[d.type]) + "px"; })
            .attr("height", function(d) { return (icon_sizes[d.type]) + "px"; });

        nodeEnter.filter(function(d) { return d.imgClass !== undefined; })
            .append("g")
            .append('svg:foreignObject')
            .attr("width", 12)
            .attr("height", 12)
            .attr("x", function(d) {
                return (d.type === 'galaxy' || d.type === 'tag') ? '-10px' : '-6px';
            })
            .attr("y", function(d) {
                return (d.type === 'galaxy' || d.type === 'tag') ? '-12px' : '-8px';
            })
            .append("xhtml:div")
            .html(function(d) {
                var result = 'fa-' + d.imgClass;
                var namespace = getFontAwesomeNamespace(d.imgClass);
                if (d.type === 'galaxy' || d.type === 'tag') result = 'fa-2x ' + result;
                return '<i class="' + namespace + ' ' + result + '"></i>';
            });

        nodeEnter.append("text")
            .attr("dy", function(d) {
                return (d.type === "event" || d.type === "galaxy") ? "10px" : "0px";
            })
            .attr("fill", function(d) {
                if (d.type === "event") {
                    return d.expanded === 1 ? "#0000ff" : "#ff0000";
                }
            })
            .text(function(d) {
                return d.type + ': ' + d.name;
            });

        node.selectAll("text").attr("y", 20);

        node.on('mouseover', function(d) {
            link.style('stroke', function(l) {
                return (d === l.source || d === l.target) ? "#ff0000" : "#9ecae1";
            });
            link.style('stroke-width', function(l) {
                return (d === l.source || d === l.target) ? 2 : 1;
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
        d3.selectAll('.highlighted_circle').style("stroke-opacity", 0);
        d3.select('#id-' + d.unique_id)
            .select('.highlighted_circle')
            .style("stroke", "red")
            .style("stroke-opacity", 0.5);
    }

    function bindExpand(d, type) {
        if (!d.expanded) {
            var expandName = (type === 'selected') ? 'Expand (x)' : 'Expand (ctrl+x)';
            var li = document.createElement('li');
            li.id = 'expand_' + type + '_' + d.id;
            li.className = 'graphMenuAction';
            li.innerHTML = '<span>' + expandName + '</span>';
            li.addEventListener('click', function() { expand(d); });
            document.getElementById(type + "-menu").appendChild(li);
        }
    }

    function remove_node(d) {
        var index = root.nodes.indexOf(d);
        if (index > -1) {
            root.nodes.splice(index, 1);
        }
        var temp = [];
        root['links'].forEach(function(n) {
            if (n.source !== d && n.target !== d) {
                temp.push(n);
            }
        });
        root['links'] = temp;

        root = {
            'nodes': root['nodes'],
            'links': root['links']
        };
        update();
    }

    function createInfoPane(d, data, type) {
        var i = 0;
        var view_urls = {
            'event': baseurl + '/events/view/' + parseInt(d.id),
            'tag': baseurl + '/tags/view/' + parseInt(d.id),
            'galaxy': baseurl + '/galaxy_clusters/view/' + parseInt(d.id)
        };
        var menu = document.getElementById(type + "-menu");

        data["fields"].forEach(function(e) {
            var title = e;
            if (i === 0) title = d.type;
            title = title.split("_").join(" ");
            title = title.charAt(0).toUpperCase() + title.slice(1);

            var span1 = document.createElement('span');
            span1.textContent = title + ': ';
            var span2 = document.createElement('span');
            span2.textContent = d[e];
            var li = document.createElement('li');
            li.appendChild(span1);
            li.appendChild(span2);
            if (i === 0) li.className = 'graphMenuTitle';
            i++;
            menu.appendChild(li);
        });

        var actionsLi = document.createElement('li');
        actionsLi.className = 'graphMenuActions';
        actionsLi.textContent = 'Actions';
        menu.appendChild(actionsLi);

        if (data["actions"].indexOf("navigate") !== -1) {
            var navLi = document.createElement('li');
            navLi.innerHTML = '<span><a href="' + view_urls[d.type] + '">Go to ' + d.type + '</a></span>';
            menu.appendChild(navLi);
        }
        if (data["actions"].indexOf("expand") !== -1) {
            bindExpand(d, type);
        }
        if (data["actions"].indexOf("delete") !== -1) {
            bindDelete(d, type);
        }
    }

    function showPane(d, type) {
        if (type === 'hover') {
            hovered = d;
        } else {
            highlighted = d;
            highlightNode(d);
        }

        var headerEl = document.getElementById(type + '-header');
        if (headerEl) headerEl.style.display = '';

        d3.select("#" + type + "-menu").style('display', 'inline-block');
        document.getElementById(type + "-menu").innerHTML = '';

        var data;
        if (d.type === 'attribute') {
            data = {
                "fields": ["id", "name", "category", "type", "comment"],
                "actions": ["delete"]
            };
        }
        if (d.type === 'event') {
            data = {
                "fields": ["id", "info", "date", "analysis", "org"],
                "actions": ["expand", "delete", "navigate"]
            };
        }
        if (d.type === 'tag') {
            data = {
                "fields": ["id", "name"],
                "actions": ["expand", "delete"]
            };
            if (d.taxonomy !== undefined) {
                data["fields"].push("taxonomy");
                data["fields"].push("taxonomy_description");
                if (d.description !== "") {
                    data["fields"].push("Description");
                }
            }
        }
        if (d.type === 'galaxy') {
            data = {
                "fields": ["id", "name", "galaxy", "synonyms", "authors", "description", "source"],
                "actions": ["expand", "delete", "navigate"]
            };
        }
        if (d.type === 'object') {
            data = {
                "fields": ["id", "name", "metacategory", "description", "comment"],
                "actions": ["delete"]
            };
        }
        createInfoPane(d, data, type);
    }

    function expand(d) {
        if (d.type === 'event' || d.type === 'galaxy' || d.type === 'tag') {
            d3.xhr(baseurl + "/events/updateGraph/" + d.id + "/" + d.type + ".json")
                .header("Content-Type", "application/json")
                .post(
                    JSON.stringify(root),
                    function(err, rawData) {
                        root = JSON.parse(rawData.response);
                        resolveLinkEnds(root);
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

        node.attr("transform", function(d) {
            return "translate(" + d.x + "," + d.y + ")";
        });
    }

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
        for (var i = 0; i < arr.length; i++) {
            if (arr[i] === val) return i;
        }
        return false;
    }

    var chartEl = document.getElementById('chart');

    chartEl.addEventListener('keydown', function(e) {
        if (e.which === 69) {
            if (highlighted === undefined) {
                showPane(root['nodes'][0], 'selected');
            } else {
                var current = searchArray(root['nodes'], highlighted);
                if (current === root['nodes'].length - 1) {
                    showPane(root['nodes'][0], 'selected');
                } else {
                    showPane(root['nodes'][current + 1], 'selected');
                }
            }
        }
        if (e.which === 81) {
            if (highlighted === undefined) {
                showPane(root['nodes'][root['nodes'].length - 1], 'selected');
            } else {
                var current = searchArray(root['nodes'], highlighted);
                if (current === 0) {
                    showPane(root['nodes'][root['nodes'].length - 1], 'selected');
                } else {
                    showPane(root['nodes'][current - 1], 'selected');
                }
            }
        }
    });

    chartEl.addEventListener('keydown', function(e) {
        if (e.which === 88) {
            e.preventDefault();
            if (e.ctrlKey) {
                if (hovered !== undefined) {
                    expand(hovered);
                }
            } else {
                if (highlighted !== undefined) {
                    expand(highlighted);
                }
            }
        }
    });

    window.addEventListener('resize', () => {
        const size = getGraphSize();

        svg
            .attr("width", size.width)
            .attr("height", size.height);

        rect
            .attr("width", size.width)
            .attr("height", size.height);

        force.size([size.width, size.height]).resume();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === "Escape") {
            graphContainer.classList.remove('fullscreen');
            fullscreenBtn.querySelector('i').classList.replace('fa-compress', 'fa-expand');
            window.dispatchEvent(new Event('resize'));
        }
    });
});