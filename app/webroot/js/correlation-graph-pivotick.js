function truncate(str, max) {
    if (!str) return '';
    return str.length > max
        ? str.substring(0, max) + '\u2026'
        : str;
}

function getNodeLabel(d) {
    switch (d.type) {
        case 'event':
            return truncate(
                '[' + d.id + '] ' + (d.info || ''), 20
            );
        case 'attribute':
            return truncate(d.name || '', 20);
        case 'tag':
            return truncate(d.name || '', 20);
        case 'galaxy':
            return truncate(d.name || '', 20);
        case 'object':
            return truncate(d.name || '', 20);
        default:
            return truncate(d.name || '', 20);
    }
}

var defined_node_styles = {
    'event': {
        shape: 'hexagon',
        color: '#1a5276',
        size: 20,
        strokeColor: '#2980b9',
        strokeWidth: 2,
        textColor: '#fff',
        imagePath: function(node) {
            var d = node.getData();
            return d.image || baseurl + '/img/misp-org.png';
        }
    },
    'tag': {
        shape: 'square',
        color: function(node) {
            var d = node.getData();
            return d.colour || '#6c757d';
        },
        size: 14,
        strokeColor: '#fff',
        strokeWidth: 2,
        textColor: '#fff',
        iconClass: function(node) {
            var d = node.getData();
            var icon = d.imgClass || 'tag';
            return getFontAwesomeNamespace(icon)
                + ' fa-' + icon;
        }
    },
    'galaxy': {
        shape: 'hexagon',
        color: '#6c3483',
        size: 22,
        strokeColor: '#a569bd',
        strokeWidth: 2,
        textColor: '#fff',
        iconClass: function(node) {
            var d = node.getData();
            var icon = d.imgClass || 'globe';
            return getFontAwesomeNamespace(icon)
                + ' fa-' + icon;
        }
    },
    'attribute': {
        shape: 'circle',
        color: '#e67e22',
        size: 10,
        strokeColor: '#f39c12',
        strokeWidth: 1,
        textColor: '#fff',
        iconClass: 'fas fa-crosshairs'
    },
    'object': {
        shape: 'square',
        color: '#808080',
        size: 10,
        strokeColor: '#aaa',
        strokeWidth: 1,
        textColor: '#fff',
        iconClass: 'fas fa-th-list'
    }
};

$(document).ready(function() {
    var Graph = Pivotick.default;
    var PNode = Pivotick.Node;
    var PEdge = Pivotick.Edge;

    var scope_id = $('#graph_init').data('id');
    var scope = $('#graph_init').data('scope');
    var isAjax = $('#graph_init').data('ajax');

    var container = document.getElementById('correlation-graph-container');
    var graph = null;
    var root = null;
    var nodeMap = {};

    var view_urls = {
        'event': baseurl + '/events/view/',
        'tag': baseurl + '/tags/view/',
        'galaxy': baseurl + '/galaxy_clusters/view/'
    };

    function getNodeProperties(node) {
        var d = node.getData();
        var props = [];
        var fieldMap = {
            'event': [
                'id', 'info', 'date', 'analysis',
                'distribution', 'org'
            ],
            'tag': ['id', 'name', 'taxonomy',
                'taxonomy_description', 'description'
            ],
            'galaxy': [
                'id', 'name', 'galaxy', 'synonyms',
                'authors', 'description', 'source'
            ],
            'attribute': [
                'id', 'name', 'att_category',
                'att_type', 'att_ids', 'comment'
            ],
            'object': [
                'id', 'name', 'metacategory',
                'description', 'comment'
            ]
        };
        var fields = fieldMap[d.type] || Object.keys(d);
        fields.forEach(function(field) {
            if (d[field] !== undefined && d[field] !== ''
                && d[field] !== null) {
                var label = field.replace(/_/g, ' ');
                label = label.charAt(0).toUpperCase()
                    + label.slice(1);
                props.push({
                    name: label,
                    value: String(d[field])
                });
            }
        });
        return props;
    }

    function convertToGraphData(root) {
        var nodes = [];
        var edges = [];

        if (!root || !root.nodes) {
            return { nodes: [], edges: [] };
        }
        root.nodes.forEach(function(n) {
            nodes.push({
                id: n.unique_id,
                data: n
            });
        });

        if (root.links) {
            root.links.forEach(function(l, i) {
                var sourceNode = root.nodes[l.source];
                var targetNode = root.nodes[l.target];
                if (sourceNode && targetNode) {
                    edges.push({
                        id: 'link-' + sourceNode.unique_id
                            + '-' + targetNode.unique_id,
                        from: sourceNode.unique_id,
                        to: targetNode.unique_id,
                        data: {
                            label: '',
                            linkDistance: l.linkDistance
                        }
                    });
                }
            });
        }
        return { nodes: nodes, edges: edges };
    }

    function prepareRootForPost(root) {
        var prepared = {
            nodes: root.nodes,
            links: []
        };
        if (root.links) {
            root.links.forEach(function(l) {
                var src = l.source;
                var tgt = l.target;
                if (typeof src === 'number') {
                    src = root.nodes[src];
                }
                if (typeof tgt === 'number') {
                    tgt = root.nodes[tgt];
                }
                prepared.links.push({
                    source: src,
                    target: tgt,
                    linkDistance: l.linkDistance
                });
            });
        }
        return prepared;
    }

    function expand(node) {
        var d = node.getData();
        if (d.type !== 'event' && d.type !== 'galaxy'
            && d.type !== 'tag') {
            return;
        }
        if (d.expanded) {
            return;
        }
        var postData = prepareRootForPost(root);
        $.ajax({
            url: baseurl + '/events/updateGraph/'
                + d.id + '/' + d.type + '.json',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(postData),
            success: function(json) {
                root = json;
                rebuildGraph(root);
            },
            error: function(xhr) {
                console.error(
                    'Failed to expand node:', xhr
                );
            }
        });
    }

    function buildContextMenuItems() {
        return {
            menuNode: {
                topbar: [
                    {
                        iconClass: 'fas fa-expand-arrows-alt',
                        text: 'Expand',
                        title: 'Load correlations for this node',
                        variant: 'outline-primary',
                        visible: function(element) {
                            if (!element) return false;
                            var d = element.getData();
                            return !d.expanded
                                && (d.type === 'event'
                                    || d.type === 'galaxy'
                                    || d.type === 'tag');
                        },
                        onclick: function(evt, element) {
                            if (element) expand(element);
                        }
                    },
                    {
                        iconClass: 'fas fa-external-link-alt',
                        text: 'View',
                        title: 'Navigate to this element',
                        variant: 'outline-info',
                        visible: function(element) {
                            if (!element) return false;
                            var d = element.getData();
                            return d.type === 'event'
                                || d.type === 'tag'
                                || d.type === 'galaxy';
                        },
                        onclick: function(evt, element) {
                            if (!element) return;
                            var d = element.getData();
                            var url = view_urls[d.type];
                            if (url) {
                                window.location.href
                                    = url + parseInt(d.id);
                            }
                        }
                    }
                ],
                menu: [
                    {
                        iconClass: 'fas fa-trash',
                        text: 'Remove from graph',
                        title: 'Remove this node',
                        variant: 'outline-danger',
                        onclick: function(evt, element) {
                            if (!element) return;
                            graph.removeNode(element.id);
                        }
                    }
                ]
            },
            menuCanvas: {
                topbar: [],
                menu: [
                    {
                        iconClass: 'fas fa-compress-arrows-alt',
                        text: 'Fit to screen',
                        title: 'Fit all nodes to the viewport',
                        variant: 'outline-primary',
                        onclick: function() {
                            graph.renderer.fitAndCenter();
                        }
                    }
                ]
            }
        };
    }

    function buildGraphOptions() {
        return {
            isDirected: true,
            render: {
                type: 'svg',
                nodeTypeAccessor: function(node) {
                    return node.getData().type;
                },
                nodeStyleMap: defined_node_styles,
                defaultNodeStyle: {
                    shape: 'circle',
                    color: '#666',
                    size: 12,
                    strokeColor: '#fff',
                    strokeWidth: 2,
                    textColor: '#fff'
                },
                defaultEdgeStyle: {
                    strokeColor: '#9ecae1',
                    strokeWidth: 1.5,
                    opacity: 0.8,
                    curveStyle: 'straight',
                    markerEnd: '',
                    markerStart: '',
                    rotateLabel: false
                },
                defaultLabelStyle: {
                    backgroundColor: 'transparent',
                    fontSize: 10,
                    color: '#666'
                },
                enableFocusMode: true,
                enableNodeExpansion: false,
                zoomEnabled: true,
                dragEnabled: true,
                selectionBox: {
                    enabled: false
                }
            },
            simulation: {
                enabled: true,
                useWorker: false,
                d3LinkDistance: 120,
                d3ManyBodyStrength: -400,
                d3CollideRadius: 25,
                d3VelocityDecay: 0.4,
                d3AlphaDecay: 0.03,
                d3GravityStrength: 0.08,
                d3CenterStrength: 1,
                cooldownTime: 3000,
                freezeNodesOnDrag: true
            },
            callbacks: {
                onNodeDbclick: function(event, node) {
                    expand(node);
                }
            },
            UI: {
                mode: 'full',
                sidebar: {
                    collapsed: 'auto'
                },
                mainHeader: {
                    nodeHeaderMap: {
                        title: function(node) {
                            var d = node.getData();
                            var t = d.type
                                ? d.type.charAt(0)
                                    .toUpperCase()
                                    + d.type.slice(1)
                                : 'Node';
                            return t + ': '
                                + (d.name || d.unique_id);
                        },
                        subtitle: function(node) {
                            var d = node.getData();
                            if (d.type === 'event') {
                                return (d.org || '')
                                    + (d.date
                                        ? ' | ' + d.date
                                        : '');
                            }
                            if (d.type === 'galaxy') {
                                return d.galaxy || '';
                            }
                            if (d.type === 'tag'
                                && d.taxonomy) {
                                return 'Taxonomy: '
                                    + d.taxonomy;
                            }
                            if (d.type === 'attribute') {
                                return (d.att_category || '')
                                    + ':'
                                    + (d.att_type || '');
                            }
                            return '';
                        }
                    },
                    edgeHeaderMap: {
                        title: 'Correlation',
                        subtitle: ''
                    }
                },
                propertiesPanel: {
                    nodePropertiesMap: getNodeProperties,
                    edgePropertiesMap: function() {
                        return [];
                    }
                },
                extraPanels: [
                    {
                        title: 'Actions',
                        alwaysVisible: false,
                        render: function(element) {
                            if (!element
                                || !element.getData) {
                                return '';
                            }
                            var d = element.getData();
                            var html = '';
                            var canExpand
                                = !d.expanded
                                && (d.type === 'event'
                                    || d.type === 'galaxy'
                                    || d.type === 'tag');
                            var canNav
                                = d.type === 'event'
                                || d.type === 'tag'
                                || d.type === 'galaxy';
                            if (canExpand) {
                                html += '<button class="pvt-action-expand" '
                                    + 'style="margin:4px;padding:4px 12px;'
                                    + 'cursor:pointer;background:#2980b9;'
                                    + 'color:#fff;border:none;'
                                    + 'border-radius:3px;">'
                                    + '<i class="fas fa-expand-arrows-alt">'
                                    + '</i> Expand correlations'
                                    + '</button>';
                            }
                            if (canNav) {
                                var url = view_urls[d.type]
                                    + parseInt(d.id);
                                html += '<a href="' + url + '" '
                                    + 'style="margin:4px;padding:4px 12px;'
                                    + 'display:inline-block;'
                                    + 'background:#17a2b8;color:#fff;'
                                    + 'border:none;border-radius:3px;'
                                    + 'text-decoration:none;">'
                                    + '<i class="fas fa-external-link-alt">'
                                    + '</i> View '
                                    + d.type + '</a>';
                            }
                            var div
                                = document.createElement('div');
                            div.innerHTML = html;
                            var expandBtn
                                = div.querySelector(
                                    '.pvt-action-expand'
                                );
                            if (expandBtn) {
                                expandBtn.addEventListener(
                                    'click',
                                    function() {
                                        expand(element);
                                    }
                                );
                            }
                            return div;
                        }
                    }
                ],
                tooltip: {
                    enabled: true,
                    allowPinning: true,
                    nodeHeaderMap: {
                        title: function(node) {
                            var d = node.getData();
                            var t = d.type
                                ? d.type.charAt(0)
                                    .toUpperCase()
                                    + d.type.slice(1)
                                : '';
                            return t + ': '
                                + (d.name || '');
                        }
                    },
                    nodePropertiesMap: function(node) {
                        return getNodeProperties(node)
                            .slice(0, 4);
                    },
                    edgePropertiesMap: function() {
                        return [];
                    }
                },
                contextMenu: buildContextMenuItems(),
                keybindings: [
                    {
                        key: 'x',
                        description: 'Expand selected node',
                        callback: function() {
                            var nodes
                                = graph.renderer
                                    .getSelectedNodes
                                    ? graph.renderer
                                        .getSelectedNodes()
                                    : [];
                            if (nodes && nodes.length > 0) {
                                expand(nodes[0]);
                            }
                        }
                    }
                ]
            }
        };
    }

    function addNodeLabels() {
        if (!graph) return;
        var nodes = graph.getMutableNodes();
        nodes.forEach(function(node) {
            var el = node.getGraphElement();
            if (!el) return;
            if (el.querySelector('.misp-node-label')) {
                return;
            }
            var d = node.getData();
            var label = getNodeLabel(d);
            if (!label) return;
            var size = (defined_node_styles[d.type]
                && defined_node_styles[d.type].size)
                || 12;
            if (typeof size === 'function') {
                size = size(node);
            }
            var ns = 'http://www.w3.org/2000/svg';
            var text = document.createElementNS(ns, 'text');
            text.setAttribute('class', 'misp-node-label');
            text.setAttribute('text-anchor', 'middle');
            text.setAttribute('dominant-baseline', 'hanging');
            text.setAttribute('y', String(size + 4));
            text.setAttribute('font-size', '9');
            text.setAttribute(
                'font-family', 'system-ui, sans-serif'
            );
            text.setAttribute('fill', '#333');
            text.setAttribute('pointer-events', 'none');
            text.textContent = label;
            el.appendChild(text);
        });
    }

    function rebuildGraph(data) {
        var graphData = convertToGraphData(data);
        if (graph) {
            graph.setData(
                graphData.nodes, graphData.edges
            );
            setTimeout(addNodeLabels, 300);
        }
    }

    function initGraph(json) {
        root = json;
        var graphData = convertToGraphData(root);
        var options = buildGraphOptions();
        graph = new Graph(
            container, graphData, options
        );
        graph.on('ready', addNodeLabels);
    }

    // Set container height
    if (isAjax) {
        container.style.height = '500px';
    } else {
        container.style.height
            = 'calc(100vh - 42px - 42px - 10px)';
    }

    // Fullscreen toggle
    $('#fullscreen-btn-correlation').click(function() {
        var isFullscreen = $(container).data('fullscreen');
        isFullscreen = !isFullscreen;
        $(container).data('fullscreen', isFullscreen);
        container.style.height = isFullscreen
            ? 'calc(100vh - 42px - 42px - 10px)'
            : '500px';
        container.scrollIntoView({ behavior: 'smooth' });
        if (graph && graph.renderer) {
            setTimeout(function() {
                graph.renderer.fitAndCenter();
            }, 300);
        }
    });

    // Fetch initial data and initialize graph
    $.getJSON(
        baseurl + '/events/updateGraph/'
            + scope_id + '/' + scope + '.json',
        function(json) {
            initGraph(json);
        }
    ).fail(function(xhr) {
        console.error(
            'Failed to load correlation graph data:', xhr
        );
        container.innerHTML
            = '<div style="padding:20px;color:#c0392b;">'
            + 'Failed to load correlation graph data.'
            + '</div>';
    });
});
