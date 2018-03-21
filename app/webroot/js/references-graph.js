var max_displayed_char = 32;

var mapping_meta_fa = new Map();
mapping_meta_fa.set('file', {"meta-category": "file","fa_text": "file","fa-hex": "f15b"});
mapping_meta_fa.set('financial', {"meta-category": "financial","fa_text": "money-bil-alt","fa-hex": "f3d1"});
mapping_meta_fa.set('network', {"meta-category": "network","fa_text": "server","fa-hex": "f223"});
mapping_meta_fa.set('misc', {"meta-category": "misc","fa_text": "cube","fa-hex": "f1b2"});

// Util
function getRandomColor() {
	var letters = '0123456789ABCDEF';
	var color = '#';
	for (var i = 0; i < 6; i++) {
		color += letters[Math.floor(Math.random() * 16)];
	}
	return color;
}

function getTextColour(hex) {
	hex = hex.slice(1);
	var r = parseInt(hex.substring(0,2), 16);
	var g = parseInt(hex.substring(2,4), 16);
	var b = parseInt(hex.substring(4,6), 16);
	var avg = ((2 * r) + b + (3 * g))/6;
	if (avg < 128) {
		return 'white';
	} else {
		return 'black';
	}
}

function get_node_color(uuid) {
	return nodes.get(uuid).icon.color;
}


// Global var
var shortcut_text = "<b>V:</b> Center camera"
		+ "\n<b>X:</b> Expaned node"
		+ "\n<b>C:</b> Collapse node"
		+ "\n<b>SHIFT+E:</b> Edit node"
		+ "\n<b>SHIFT+F:</b> Search for value"
		+ "\n<b>SHIFT:</b> Hold to add a reference"
		+ "\n<b>DEL:</b> Delete selected item";

var scope_id = $('#references_network').data('event-id');
var container = document.getElementById('references_network');
var nodes = new vis.DataSet();
var edges = new vis.DataSet();
var mapping_value_to_nodeID = new Map();
var map_id_to_uuid = new Map();
var map_fromto_to_rel_id = new Map();
var all_obj_relation = new Map();
var user_manipulation = $('#references_network').data('user-manipulation');
var user_manipulation = true;
var data = {
	nodes: nodes,
	edges: edges
};


// Options
var network_options = {
	interaction: {
		hover: true
	},
	manipulation: {
		enabled: user_manipulation,
		initiallyActive: false,
		addEdge: add_reference,
		editEdge: false,
		addNode: add_item,
		editNode: edit_item,
		deleteNode: delete_item,
		deleteEdge: remove_reference
	},
	physics: {
		enabled: true,
		barnesHut: {
			gravitationalConstant: -10000,
			centralGravity: 5,
			springLength: 150,
			springConstant: 0.24,
			damping: 1.0,

		},
		minVelocity: 2.0
	},
	edges: {
		width: 3,
		arrows: 'to'
	},
	nodes: {
		chosen: {
			node: function(values, id, selected, hovering) {
				values.shadow = true;
				values.shadowSize = 5;
				values.shadowX = 2;
				values.shadowY = 2;
				values.shadowColor = "rgba(0,0,0,0.1)";
			}
		}
	},
	groups: {
		object: {
			shape: 'icon',
			icon: {
				face: 'FontAwesome',
				size: 50
			},
			font: {
				size: 18, // px
				background: 'rgba(255, 255, 255, 0.7)'
			},
		},
		obj_relation: {
			size: 10,
			color: { 
				border:'black'
			}
		},
		attribute: {
			shape: 'box',
			color: { 
				background:'orange', 
				border:'black'
			},
			size: 15
		},
	},
	locales: {
		en: {
			edit: 'Edit',
			del: 'Delete selected',
			back: 'Back',
			addNode: 'Add Object or Attribute',
			editNode: 'Edit selected item',
			addDescription: 'Click in an empty space to place a new node.',
			addEdge: 'Add Reference',
			edgeDescription: 'Click on an Object and drag the edge to another Object (or Attribute) to connect them.'
		}
	}
};

var typeaheadData;
var typeaheadOption = {
	source: function (query, process) {
		if (typeaheadData === undefined) { // caching
			typeaheadData = get_typeaheadData();
		}
		process(typeaheadData);
	},
	updater: function(value) {
		var nodeID = mapping_value_to_nodeID.get(value);
		// select node and focus on it
		network.selectNodes([nodeID]);
		network.focus(nodeID, {animation: true, scale: 1});
		// set focus to the network
		$("#network-typeahead").blur();
	},
	autoSelect: true
}

function get_typeaheadData() {
	var to_ret = []
	for( entry of mapping_value_to_nodeID) {
		var value = entry[0];
		to_ret.push(value);
	}
	return to_ret;
}

// Graph interaction
function collapse_node(parent_id) {
	if (parent_id === undefined) { //  No node selected
		return
	}
	var connected_nodes = network.getConnectedNodes(parent_id);
	var connected_edges = network.getConnectedEdges(parent_id);
	// Remove nodes
	for (var nodeID of connected_nodes) {
 		// Object's attribute are in UUID format (while other object or in simple integer)
		if (nodeID.length > 10) {
			nodes.remove(nodeID);
		}
	}

	// Remove edges
	for (var edgeID of connected_edges) {
 		// Object's attribute (edge) are in UUID format (while other object or in simple integer)
		if (edgeID.length > 10) {
			edges.remove(edgeID);
		}
	}
}

function expand_node(parent_id) {
	if (parent_id === undefined) { //  Node node selected
		return;
	} else if (nodes.get(parent_id).group == "attribute" || nodes.get(parent_id).group == "obj_relation") { //  Cannot expand attribute
		return;
	}

	newNodes = [];
	newRelations = [];

	var parent_pos = network.getPositions([parent_id])[parent_id];
	for(var attr of all_obj_relation.get(parent_id)) {
		var parent_color = get_node_color(parent_id);
				
		// Ensure unicity of nodes
		if (nodes.get(attr.uuid) !== null) {
			continue;
		}
				
		var striped_value = attr.value.substring(0, max_displayed_char) + (attr.value.length < max_displayed_char ? "" : "[...]");
		var node = { 
			id: attr.uuid,
			x: parent_pos.x,
			y: parent_pos.y,
			label: attr.type + ': ' + striped_value,
			title: attr.type + ': ' + attr.value,
			group: 'obj_relation',
			color: { 
				background: parent_color
			},
			font: {
				color: getTextColour(parent_color)
			}
		};
		newNodes.push(node);
				
		var rel = {
			from: parent_id,
			to: attr.uuid,
			arrows: '',
			color: {
				opacity: 0.5,
				color: parent_color
			},
			length: 40
		};
		newRelations.push(rel);
	}
		
	nodes.add(newNodes);
	edges.add(newRelations);
}
			
function remove_reference(edgeData, callback) {
	edge_id = edgeData.edges[0];
	var fromto = edge_id;
	var relation_id = map_fromto_to_rel_id.get(fromto);
	deleteObject('object_references', 'delete', relation_id, scope_id);
}

function add_reference(edgeData, callback) {
	var uuid = map_id_to_uuid.get(edgeData.to);
	if (!can_create_reference(edgeData.from) || !can_be_referenced(edgeData.to)) {
		return;
	}
	genericPopup('/objectReferences/add/'+edgeData.from, '#popover_form', function() {
		$('#targetSelect').val(uuid);
		$('option[value='+uuid+']').click()
	});
}

function can_create_reference(id) {
	return nodes.get(id).group == "object";
}
function can_be_referenced(id) {
	var res;
	if (nodes.get(id).group == "object") {
		res = true;
	} else if (nodes.get(id).group == "attribute") {
		res = true;
	} else {
		res = false;
	}
	return res;
}

function add_item(nodeData, callback) {
	choicePopup("Add an element", [
		{
			text: "Add an Object",
			onclick: "getPopup('"+scope_id+"', 'objectTemplates', 'objectChoice');"
		},
		{
			text: "Add an Attribute",
			onclick: "simplePopup('/attributes/add/"+scope_id+"');"
		},
	]);
}

function delete_item(nodeData, callback) {
	var selected_nodes = nodeData.nodes;
	for (nodeID of selected_nodes) {
		node = nodes.get(nodeID)
		if (node.group == "attribute") {
			deleteObject('attributes', 'delete', nodeID, scope_id);
		} else if (node.group == "object") {
			deleteObject('objects', 'delete', nodeID, scope_id);
		}
	}
	
}

function edit_item(nodeData, callback) {
	var id = nodeData.id
	simplePopup('/attributes/edit/'+id);
}

function genericPopupCallback(result) {
	if (result == "success") {
		fetch_data_and_update();
		reset_view_on_stabilized();
	}
}

function reset_graphs() {
	nodes.clear();
	edges.clear();
}

function update_graph(data) {
	var total = data.items.length + data.relations.length;
	network_loading(0, total);
	
	// New nodes will be automatically added
	// removed references will be deleted
	var node_conf;
	newNodes = [];
	newNodeIDs = [];
	for(var node of data.items) {
		var group, label;
		if ( node.node_type == 'object' ) {
			group =  'object';
			label = node.type;
			var striped_value = label.substring(0, max_displayed_char) + (label.length < max_displayed_char ? "" : "[...]");
			node_conf = { 
				id: node.id,
				label: striped_value,
				title: label,
				group: group,
				mass: 5,
				icon: {
					color: getRandomColor(),
					face: 'FontAwesome',
					code: String.fromCharCode(parseInt(mapping_meta_fa.get(node['meta-category'])['fa-hex'], 16)),
				}
			};
			mapping_value_to_nodeID.set(striped_value, node.id);
		} else {
			group =  'attribute';
			label = node.type + ': ' + node.val;
			var striped_value = label.substring(0, max_displayed_char) + (label.length < max_displayed_char ? "" : "[...]");
			node_conf = { 
				id: node.id,
				label: striped_value,
				title: label,
				group: group,
				mass: 5,
			};
			mapping_value_to_nodeID.set(striped_value, node.id);
		}

		newNodes.push(node_conf);
		newNodeIDs.push(node.id);
	}
	// check if nodes got deleted
	var old_node_ids = nodes.getIds();
	for (var old_id of old_node_ids) {
		// This old node got removed
		if (newNodeIDs.indexOf(old_id) == -1) {
			nodes.remove(old_id);
		}
	}

	nodes.update(newNodes);
	network_loading(data.items.length, total);
	
	// New relations will be automatically added
	// removed references will be deleted
	newRelations = [];
	newRelationIDs = [];
	for(var rel of data.relations) {
		var fromto = rel.from + '-' + rel.to;
		var rel = {
			id: fromto,
			from: rel.from,
			to: rel.to,
			label: rel.type,
			title: rel.comment,
			color: {
				opacity: 1.0
			}
		};
		newRelations.push(rel);
		newRelationIDs.push(fromto);
	}
	// check if nodes got deleted
	var old_rel_ids = edges.getIds();
	for (var old_id of old_rel_ids) {
		// This old node got removed
		if (newRelationIDs.indexOf(old_id) == -1) {
			edges.remove(old_id);
		}
	}

	edges.update(newRelations);
	network_loading(total, total);
}

function reset_view() {
	network.fit({animation: true });
}

function reset_view_on_stabilized() {
	network.on("stabilized", function(params) {
		network.fit({ animation: true });
		network.off("stabilized"); //  Removed listener
	});
}

// Data
function extract_references(data) {
	var items = [];
	var relations = [];

	if (data.Attribute !== undefined) {
		for (var attr of data.Attribute) {
			map_id_to_uuid.set(attr.id, attr.uuid);
			items.push({
				'id': attr.id,
				'type': attr.type,
				'val': attr.value,
				'node_type': 'attribute'
			});
		}
	}

	if (data.Object !== undefined) {
		for (var obj of data.Object) {
			map_id_to_uuid.set(obj.id, obj.uuid);
			all_obj_relation.set(obj.id, obj.Attribute);
			items.push({
				'id': obj.id,
				'type': obj.name,
				'val': obj.value,
				'node_type': 'object',
				'meta-category': obj['meta-category']
			});
			
			for (var rel of obj.ObjectReference) {
				var fromto = obj.id + '-' + rel.referenced_id;
				map_fromto_to_rel_id.set(fromto, rel.id);
				relations.push({
					'from': obj.id,
					'to': rel.referenced_id,
					'type': rel.relationship_type,
					'comment': rel.comment != "" ? rel.comment : "[Comment not set]"
				});
			}
		}
	}

	return {
		items: items,
		relations: relations
	}
}

function fetch_data_and_update() {
	network_loading(-1, 0);
	$.getJSON( "/events/getReferences/"+scope_id+"/event.json", function( data ) {
		extracted = extract_references(data);
		network_loading(1, 0);
		update_graph(extracted, reset_view);
	});
}

// -1: Undefined state
// 0<=iterations<total: state known
// iterations>=total: finished
function network_loading(iterations, total) {
	var progressbar_length = 3; // divided by 100
	if(iterations == -1) {
		var loadingText = 'Fetching data';
		$('.loading-network-div').show();
		$('.spinner-network').show();
		$('.loadingText-network').text(loadingText);
		$('.loadingText-network').show();
	} else if (iterations >= 0 && iterations < total) {
		var loadingText = 'Constructing network';
		$('.loading-network-div').show();
		$('.loadingText-network').text(loadingText);
		$('.loadingText-network').show();
		$('.spinner-network').hide();
		// pb
		var percentage = parseInt(iterations*100/total);
		$('.progressbar-network-div').show();
		$('#progressbar-network').show();
		$('#progressbar-network').width(percentage*progressbar_length);
		$('#progressbar-network').text(percentage+' %');

	} else if (iterations >= total) {
		$('#progressbar-network').width(100*progressbar_length);
		$('#progressbar-network').text(100+' %');
		setTimeout(function() {
			$('.loading-network-div').hide();
			$('.spinner-network').hide();
			$('.loadingText-network').hide();
			$('.progressbar-network-div').hide();
			$('#progressbar-network').hide();
		}, 1000)
	}
}

function enable_interactive_graph() {
	// unregister onclick
	$('#references_toggle').removeAttr('onclick');

	// Defer the loading of the network to let some time for the DIV to appear
	setTimeout(function() {
		$('.shortcut-help').popover({
			container: 'body',
			title: 'Shortcuts',
			content: shortcut_text,
			placement: 'left',
			trigger: 'hover',
			html: true,
		});
		$('.fullscreen-btn').click(function() {
			var network_div = $('#references_div');
			var fullscreen_enabled = !network_div.data('fullscreen');
			network_div.data('fullscreen', fullscreen_enabled);
			var height_val = fullscreen_enabled == true ? "calc(100vh - 42px - 42px - 10px)" : "500px";

			network_div.css("height", height_val);
			network_div[0].scrollIntoView({
				behavior: "smooth",

			});
			setTimeout(function() { reset_view(); }, 400);
		});
		$('#network-typeahead').typeahead(typeaheadOption);

		network = new vis.Network(container, data, network_options);
		network.on("selectNode", function (params) {
			network.moveTo({
				position: {
					x: params.pointer.canvas.x,
					y: params.pointer.canvas.y
				},
				animation: true,
			});
		});
		// Fit view only when page is loading for the first time
		reset_view_on_stabilized();

		$(document).on("keydown", function(evt) {
			switch(evt.keyCode) {
				case 88: // x
					var selected_id = network.getSelectedNodes()[0]; 
					expand_node(selected_id);
					break;

				case 67: // c
					var selected_id = network.getSelectedNodes()[0]; 
					collapse_node(selected_id);
					break;
				case 86: // v
					reset_view();
					break;

				case 69: // e
					if (evt.shiftKey) {
						var selected_id = network.getSelectedNodes()[0]; 
						data = { id: selected_id };
						edit_item(data);
					}
					break;

				case 70: // f
					if (evt.shiftKey) {
						// set focus to search input
						network.disableEditMode(); // un-toggle edit mode
						$('#network-typeahead').focus();
						$('#network-typeahead').text('');
						evt.preventDefault(); // avoid writting a 'F' in the input field
					}
					break;

				case 16: // <SHIFT>
					if (!user_manipulation) { // user can't modify references
						break;
					}
					network.addEdgeMode(); // toggle edit mode
					break;

				case 46: // <Delete>
					if (!user_manipulation) { // user can't modify references
						break;
					}
					//  References
					var selected_ids = network.getSelectedEdges(); 
					for (var selected_id of selected_ids) {
						var edge = { edges: [selected_id] }; // trick to use the same function
						remove_reference(edge);
					}

					//  Objects or Attributes
					selected_ids = network.getSelectedNodes();
					data = { nodes: selected_ids };
					delete_item(data);
					break;

				default:
					break;
			}
		});

		$(document).on("keyup", function(evt) {
			switch(evt.keyCode) {
				case 16: // <SHIFT>
					if (!user_manipulation) { // user can't modify references
						break;
					}
					network.disableEditMode(); // un-toggle edit mode
					break;
				default:
					break;
			}

			
		});

		fetch_data_and_update();
	}, 1);
}
