function log(m) {
	console.log(m);
}
/*=============
 * GLOBAL VARS
 * ============*/
var eventGraph;
var dataHandler;
var mispInteraction;
var nodes = new vis.DataSet();
var edges = new vis.DataSet();

var typeaheadData;
var scope_id = $('#eventgraph_network').data('event-id');
var container = document.getElementById('eventgraph_network');
var user_manipulation = $('#eventgraph_network').data('user-manipulation');

/*=========
 * CLASSES
 * ========*/
// network class (handle the event graph manipulation and events)
class EventGraph {
	constructor(network_options, nodes, edges) {
		// FIXME: Do the mapping between meta-catory and fa-icons.
		// Should be replaced later on.
		this.mapping_meta_fa = new Map();
		this.mapping_meta_fa.set('file', {"meta-category": "file","fa_text": "file","fa-hex": "f15b"});
		this.mapping_meta_fa.set('financial', {"meta-category": "financial","fa_text": "money-bil-alt","fa-hex": "f3d1"});
		this.mapping_meta_fa.set('network', {"meta-category": "network","fa_text": "server","fa-hex": "f223"});
		this.mapping_meta_fa.set('misc', {"meta-category": "misc","fa_text": "cube","fa-hex": "f1b2"});
		// FIXME
		this.nodes = nodes;
		this.edges = edges;
		var data = { // empty
			nodes: this.nodes,
			edges: this.edges
		};

		this.network = new vis.Network(container, data, network_options);
		var that = this;
		this.network.on("selectNode", function (params) {
			that.network.moveTo({
				position: {
					x: params.pointer.canvas.x,
					y: params.pointer.canvas.y
				},
				animation: true,
			});
		});
		// Fit view only when page is loading for the first time
		//this.reset_view_on_stabilized();
	}

	// Util
	get_node_color(uuid) {
		return this.nodes.get(uuid).icon.color;
	}

	// Graph interaction
	reset_graphs() {
		this.nodes.clear();
		this.edges.clear();
	}
	
	update_graph(data) {
		this.network_loading(true, loadingText_creating);
		
		// New nodes will be automatically added
		// removed references will be deleted
		var node_conf;
		var newNodes = [];
		var newNodeIDs = [];
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
						code: String.fromCharCode(parseInt(this.mapping_meta_fa.get(node['meta-category'])['fa-hex'], 16)),
					}
				};
				dataHandler.mapping_value_to_nodeID.set(striped_value, node.id);
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
				dataHandler.mapping_value_to_nodeID.set(striped_value, node.id);
			}
	
			newNodes.push(node_conf);
			newNodeIDs.push(node.id);
		}
		// check if nodes got deleted
		var old_node_ids = this.nodes.getIds();
		for (var old_id of old_node_ids) {
			// This old node got removed
			if (newNodeIDs.indexOf(old_id) == -1) {
				this.nodes.remove(old_id);
			}
		}
	
		this.nodes.update(newNodes);
		
		// New relations will be automatically added
		// removed references will be deleted
		var newRelations = [];
		var newRelationIDs = [];
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
		var old_rel_ids = this.edges.getIds();
		for (var old_id of old_rel_ids) {
			// This old node got removed
			if (newRelationIDs.indexOf(old_id) == -1) {
				this.edges.remove(old_id);
			}
		}
	
		this.edges.update(newRelations);
		this.network_loading(false, "");
	}
	
	reset_view() {
		this.network.fit({animation: true });
	}
	
	reset_view_on_stabilized() {
		var that = this;
		this.network.on("stabilized", function(params) {
			that.network.fit({ animation: true });
			that.network.off("stabilized"); //  Removed listener
		});
	}

	// state true: loading
	// state false: finished
	network_loading(state, message) {
		if(state) {
			$('.loading-network-div').show();
			$('.loadingText-network').text(message);
		} else {
			setTimeout(function() {
				$('.loading-network-div').hide();
			}, 500)
		}
	}


	collapse_node(parent_id) {
		var node_group = this.nodes.get(parent_id).group;
		if (parent_id === undefined || node_group != 'object') { //  No node selected  or collapse not permitted
			return
		}
		var connected_nodes = this.network.getConnectedNodes(parent_id);
		var connected_edges = this.network.getConnectedEdges(parent_id);
		// Remove nodes
		for (var nodeID of connected_nodes) {
	 		// Object's attribute are in UUID format (while other object or in simple integer)
			if (nodeID.length > 10) {
				this.nodes.remove(nodeID);
			}
		}
	
		// Remove edges
		for (var edgeID of connected_edges) {
	 		// Object's attribute (edge) are in UUID format (while other object or in simple integer)
			if (edgeID.length > 10) {
				this.edges.remove(edgeID);
			}
		}
	}
	
	expand_node(parent_id) {
		if (parent_id === undefined //  Node node selected
		    || this.nodes.get(parent_id).group != "object") { //  Cannot expand attribute
			return;
		}
	
		var newNodes = [];
		var newRelations = [];
	
		var parent_pos = this.network.getPositions([parent_id])[parent_id];
		for(var attr of dataHandler.mapping_all_obj_relation.get(parent_id)) {
			var parent_color = eventGraph.get_node_color(parent_id);
					
			// Ensure unicity of nodes
			if (this.nodes.get(attr.uuid) !== null) {
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
			
		this.nodes.add(newNodes);
		this.edges.add(newRelations);
	}

}

// data class (handle data)
class DataHandler {
	constructor(network) {
		this.network = network;
		this.mapping_value_to_nodeID = new Map();
		this.mapping_id_to_uuid = new Map();
		this.mapping_fromto_to_rel_id = new Map();
		this.mapping_all_obj_relation = new Map();
	}

	extract_references(data) {
		var items = [];
		var relations = [];
	
		if (data.Attribute !== undefined) {
			for (var attr of data.Attribute) {
				this.mapping_id_to_uuid.set(attr.id, attr.uuid);
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
				this.mapping_id_to_uuid.set(obj.id, obj.uuid);
				this.mapping_all_obj_relation.set(obj.id, obj.Attribute);
				items.push({
					'id': obj.id,
					'type': obj.name,
					'val': obj.value,
					'node_type': 'object',
					'meta-category': obj['meta-category']
				});
				
				for (var rel of obj.ObjectReference) {
					var fromto = obj.id + '-' + rel.referenced_id;
					this.mapping_fromto_to_rel_id.set(fromto, rel.id);
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
	
	fetch_data_and_update() {
		eventGraph.network_loading(true, loadingText_fetching);
		$.getJSON( "/events/getReferences/"+scope_id+"/event.json", function( data ) {
			var extracted = dataHandler.extract_references(data);
			eventGraph.update_graph(extracted);
			eventGraph.reset_view_on_stabilized();
		});
	}

	get_typeaheadData() {
		var to_ret = []
		for( var entry of this.mapping_value_to_nodeID) {
			var value = entry[0];
			to_ret.push(value);
		}
		return to_ret;
	}
}


// MISP interaction class (handle interaction with misp)
class MispInteraction {
	constructor(nodes, edges) {
		this.nodes = nodes;
		this.edges = edges;
	}

	remove_reference(edgeData, callback) {
		var edge_id = edgeData.edges[0];
		var fromto = edge_id;
		var relation_id = dataHandler.mapping_fromto_to_rel_id.get(fromto);
		deleteObject('object_references', 'delete', relation_id, scope_id);
	}
	
	add_reference(edgeData, callback) {
		var that = mispInteraction;
		var uuid = dataHandler.mapping_id_to_uuid.get(edgeData.to);
		if (!that.can_create_reference(edgeData.from) || !that.can_be_referenced(edgeData.to)) {
			return;
		}
		genericPopup('/objectReferences/add/'+edgeData.from, '#popover_form', function() {
			$('#targetSelect').val(uuid);
			$('option[value='+uuid+']').click()
		});
	}
	
	can_create_reference(id) {
		return this.nodes.get(id).group == "object";
	}

	can_be_referenced(id) {
		var res;
		if (this.nodes.get(id).group == "object") {
			res = true;
		} else if (this.nodes.get(id).group == "attribute") {
			res = true;
		} else {
			res = false;
		}
		return res;
	}

	add_item(nodeData, callback) {
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
	
	delete_item(nodeData, callback) {
		var selected_nodes = nodeData.nodes;
		for (var nodeID of selected_nodes) {
			var node = this.nodes.get(nodeID)
			if (node.group == "attribute") {
				deleteObject('attributes', 'delete', nodeID, scope_id);
			} else if (node.group == "object") {
				deleteObject('objects', 'delete', nodeID, scope_id);
			}
		}
		
	}
	
	edit_item(nodeData, callback) {
		var id = nodeData.id
		simplePopup('/attributes/edit/'+id);
	}
}


/*=========
 * UTILS
 * ========*/
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


function genericPopupCallback(result) {
	if (result == "success") {
		dataHandler.fetch_data_and_update();
		//eventGraph.reset_view_on_stabilized();
	}
}



// Called when the user click on the 'Event graph' toggle
function enable_interactive_graph() {
	// unregister onclick
	$('#eventgraph_toggle').removeAttr('onclick');

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
			var network_div = $('#eventgraph_div');
			var fullscreen_enabled = !network_div.data('fullscreen');
			network_div.data('fullscreen', fullscreen_enabled);
			var height_val = fullscreen_enabled == true ? "calc(100vh - 42px - 42px - 10px)" : "500px";

			network_div.css("height", height_val);
			network_div[0].scrollIntoView({
				behavior: "smooth",

			});
		});
		$('#network-typeahead').typeahead(typeaheadOption);

		eventGraph = new EventGraph(network_options, nodes, edges);
		dataHandler = new DataHandler(eventGraph.network);

		$(document).on("keydown", function(evt) {
			switch(evt.keyCode) {
				case 88: // x
					var selected_id = eventGraph.network.getSelectedNodes()[0]; 
					eventGraph.expand_node(selected_id);
					break;

				case 67: // c
					var selected_id = eventGraph.network.getSelectedNodes()[0]; 
					eventGraph.collapse_node(selected_id);
					break;
				case 86: // v
					eventGraph.reset_view();
					break;

				case 69: // e
					if (evt.shiftKey) {
						var selected_id = eventGraph.network.getSelectedNodes()[0]; 
						data = { id: selected_id };
						mispInteraction.edit_item(data);
					}
					break;

				case 70: // f
					if (evt.shiftKey) {
						// set focus to search input
						eventGraph.network.disableEditMode(); // un-toggle edit mode
						$('#network-typeahead').focus();
						$('#network-typeahead').text('');
						evt.preventDefault(); // avoid writting a 'F' in the input field
					}
					break;

				case 16: // <SHIFT>
					if (!user_manipulation) { // user can't modify references
						break;
					}
					eventGraph.network.addEdgeMode(); // toggle edit mode
					break;

				case 46: // <Delete>
					if (!user_manipulation) { // user can't modify references
						break;
					}
					//  References
					var selected_ids = eventGraph.network.getSelectedEdges(); 
					for (var selected_id of selected_ids) {
						var edge = { edges: [selected_id] }; // trick to use the same function
						mispInteraction.remove_reference(edge);
					}

					//  Objects or Attributes
					selected_ids = eventGraph.network.getSelectedNodes();
					data = { nodes: selected_ids };
					mispInteraction.delete_item(data);
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
					eventGraph.network.disableEditMode(); // un-toggle edit mode
					break;
				default:
					break;
			}

			
		});

		dataHandler.fetch_data_and_update();
	}, 1);
}

/*=========
 * OPTIONS
 * ========*/
mispInteraction = new MispInteraction(nodes, edges);

var network_options = {
	interaction: {
		hover: true
	},
	manipulation: {
		enabled: user_manipulation,
		initiallyActive: false,
		addEdge: mispInteraction.add_reference,
		editEdge: false,
		addNode: mispInteraction.add_item,
		editNode: mispInteraction.edit_item,
		deleteNode: mispInteraction.delete_item,
		deleteEdge: mispInteraction.remove_reference
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

var typeaheadOption = {
	source: function (query, process) {
		if (typeaheadData === undefined) { // caching
			typeaheadData = dataHandler.get_typeaheadData();
		}
		process(typeaheadData);
	},
	updater: function(value) {
		var nodeID = dataHandler.mapping_value_to_nodeID.get(value);
		// select node and focus on it
		eventGraph.network.selectNodes([nodeID]);
		eventGraph.network.focus(nodeID, {animation: true, scale: 1});
		// set focus to the network
		$("#network-typeahead").blur();
	},
	autoSelect: true
}
var max_displayed_char = 32;
var progressbar_length = 3; // divided by 100
var loadingText_fetching = 'Fetching data';
var loadingText_creating = 'Constructing network';

var shortcut_text = "<b>V:</b> Center camera"
		+ "\n<b>X:</b> Expaned node"
		+ "\n<b>C:</b> Collapse node"
		+ "\n<b>SHIFT+E:</b> Edit node"
		+ "\n<b>SHIFT+F:</b> Search for value"
		+ "\n<b>SHIFT:</b> Hold to add a reference"
		+ "\n<b>DEL:</b> Delete selected item";



