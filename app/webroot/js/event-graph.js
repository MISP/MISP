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
var root_id_attr = "rootNode:attribute"
var root_id_object = "rootNode:object"
var mapping_root_id_to_type = {};
mapping_root_id_to_type[root_id_attr] = 'attribute';
mapping_root_id_to_type[root_id_object] = 'object';
var root_node_x_pos = 800;
var cluster_expand_threshold = 100;

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
		this.mapping_meta_fa.set('network', {"meta-category": "network","fa_text": "server","fa-hex": "f233"});
		this.mapping_meta_fa.set('misc', {"meta-category": "misc","fa_text": "cube","fa-hex": "f1b2"});
		// FIXME
		this.first_draw = true;
		this.layout = 'default';
		this.backup_connection_edges = {};
		this.network_options = network_options;
		this.nodes = nodes;
		this.edges = edges;
		var data = { // empty
			nodes: this.nodes,
			edges: this.edges
		};
		this.cluster_index = 0; // use to get uniq cluster ID
		this.clusters = [];

		this.network = new vis.Network(container, data, this.network_options);
		this.add_unreferenced_root_node();

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

	}

	// Util
	get_node_color(uuid) {
		return this.nodes.get(uuid).icon.color;
	}

	// Graph interaction
	
	// Clusterize the specified node with its connected childs 
	clusterize(rootID) {
		var that = eventGraph;
		var type = mapping_root_id_to_type[rootID];
		var clusterOptionsByData = {
			processProperties: global_processProperties,
			clusterNodeProperties: {borderWidth: 3, shape: 'database', font: {size: 30}},
			joinCondition: function(nodeOptions) {
				return nodeOptions.unreferenced == type || nodeOptions.id == rootID;
			}

		};
		that.network.cluster(clusterOptionsByData);
	}

	init_clusterize() {
		for(var key of Object.keys(mapping_root_id_to_type)) {
			this.clusterize(key);
		}
	}

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
			// Ignore root node
			if (old_id == "rootNode:attribute" || old_id == "rootNode:object") {
				continue;
			}
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
			var rel = {
				id: rel.id,
				from: rel.from,
				to: rel.to,
				label: rel.type,
				title: rel.comment,
				color: {
					opacity: 1.0,
				}
			};
			newRelations.push(rel);
			newRelationIDs.push(rel.id);
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

		// links unreferenced attributes and object to root nodes
		if (this.first_draw) {
			this.link_not_referenced_nodes();
			this.first_draw = !this.first_draw
		}

		this.network_loading(false, "");
	}
	
	reset_view() {
		this.network.fit({animation: true });
	}
	
	reset_view_on_stabilized() {
		var that = eventGraph;
		this.network.once("stabilized", function(params) {
			that.network.fit({ animation: true });
		});
	}

	focus_on_stabilized(nodeID) {
		this.network.once("stabilized", function(params) {
			eventGraph.network.focus(nodeID, {animation: true, scale: 1});
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
		if(parent_id === undefined) { return; }
		
		if (!(parent_id == root_id_attr || parent_id == root_id_object)) { // Is not a root node
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
		} else { // Is a root node
			this.clusterize(parent_id);
		}
	}
	
	expand_node(parent_id) {
		if (!this.network.isCluster(parent_id)) {

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

		} else { // is a cluster
			if(this.network.getNodesInCluster(parent_id).length > cluster_expand_threshold) {
				if(!confirm("The cluster contains lots of nodes. Are you sure you want to expand it?")) {
					return;
				}
			}
			// expand cluster
			this.network.openCluster(parent_id);
		}
	}

	link_not_referenced_nodes() {
		var newEdges = [];
		var that = this;
		this.nodes.forEach(function(nodeData) {
			var cur_id = nodeData.id;
			var cur_group = nodeData.group;
			var prev_nodeID = cur_group == 'attribute' ? root_id_attr : root_id_object;

			// Do not link already connected nodes
			if (that.network.getConnectedEdges(cur_id).length > 0) {
				return;
			}

			var new_edge = {
				to: cur_id,
				arrows: '',
				color: {
					opacity: 0.7,
					color: '#d9d9d9'
				},
				length: 150
			}
			if (cur_group == 'attribute') {
				new_edge.from = that.layout == 'default' ? root_id_attr : prev_nodeID;
				that.nodes.update({id: nodeData.id, unreferenced: 'attribute'});
			} else if (cur_group == 'object') {
				new_edge.from = that.layout == 'default' ? root_id_object : prev_nodeID;
				that.nodes.update({id: nodeData.id, unreferenced: 'object'});
			}
			newEdges.push(new_edge);
			prev_nodeID = cur_id;
		});
		this.edges.add(newEdges);
		this.init_clusterize();
	}

	add_unreferenced_root_node() {
		var root_node_attr = {
			id: root_id_attr,
			fixed: true,
			x: -root_node_x_pos,
			y: 0,
			label: 'Unreferenced Attributes',
			title: 'All Attributes not being referenced',
			group: 'rootNodeAttribute'
		};
		var root_node_obj = {
			id: root_id_object,
			fixed: true,
			x: root_node_x_pos,
			y: 0,
			label: 'Unreferenced Objects',
			title: 'All Objects not being referenced',
			group: 'rootNodeObject'
		};
		this.nodes.add([root_node_attr, root_node_obj]);
	}

	switch_unreferenced_nodes_connection() {
		var that = eventGraph;
		var to_update = [];
		for(var root_id of [root_id_attr, root_id_object]) {
			if(that.layout == 'default') {
				var all_edgesID = that.backup_connection_edges[root_id]
			} else {
				that.network.storePositions();
				var prev_node = root_id;
				var all_edgesID = that.network.getConnectedEdges(root_id)
				that.backup_connection_edges[root_id] = all_edgesID;
			}
			var all_edges = that.edges.get(all_edgesID);

			for(var i=0; i<all_edges.length; i++ ) {
				var edge = all_edges[i];
				if(that.layout == 'default') {
					// restore all edges connected to root node
					edge.from = root_id;
				} else {
					// change edges so that they are linked one node after the other
					edge.from = prev_node;
					prev_node = edge.to;
				}
				to_update.push(edge);
			}
		}
		that.edges.update(to_update);
	}

	change_layout_type(layout) {
		var that = eventGraph;
		if (that.layout == layout) { // Hasn't changed
			return;
		}

		if (layout == 'default') {
			that.network_options.layout.hierarchical.enabled = false;
			that.network_options.physics.solver = 'barnesHut';
			that.layout = layout;
		} else {
			that.network_options.layout.hierarchical.enabled = true;
			that.network_options.layout.hierarchical.sortMethod = layout;
			that.layout = layout;
		}
		that.network_loading(true, loadingText_redrawing);
		that.switch_unreferenced_nodes_connection();
		that.destroy_and_redraw();
		that.network_loading(false, "");
	}

	destroy_and_redraw() {
		var that = eventGraph;
               	that.network.destroy();
                that.network = null;
		var data = {nodes: that.nodes, edges: that.edges};
		that.network = new vis.Network(container, data, that.network_options);
		that.init_clusterize();
	}

}

// data class (handle data)
class DataHandler {
	constructor(network) {
		this.network = network;
		this.mapping_value_to_nodeID = new Map();
		this.mapping_attr_id_to_uuid = new Map();
		this.mapping_all_obj_relation = new Map();
		this.mapping_rel_id_to_uuid = new Map();
	}

	extract_references(data) {
		var items = [];
		var relations = [];
	
		if (data.Attribute !== undefined) {
			for (var attr of data.Attribute) {
				this.mapping_attr_id_to_uuid.set(attr.id, attr.uuid);
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
				this.mapping_attr_id_to_uuid.set(obj.id, obj.uuid);
				this.mapping_all_obj_relation.set(obj.id, obj.Attribute);
				items.push({
					'id': obj.id,
					'type': obj.name,
					'val': obj.value,
					'node_type': 'object',
					'meta-category': obj['meta-category']
				});
				
				for (var rel of obj.ObjectReference) {
					this.mapping_rel_id_to_uuid.set(rel.id, rel.uuid);
					relations.push({
						'id': rel.id,
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
	
	fetch_data_and_update(stabilize) {
		eventGraph.network_loading(true, loadingText_fetching);
		$.getJSON( "/events/getReferences/"+scope_id+"/event.json", function( data ) {
			var extracted = dataHandler.extract_references(data);
			eventGraph.update_graph(extracted);
			if ( stabilize === undefined || stabilize) {
				eventGraph.reset_view_on_stabilized();
			}
		});
	}

	fetch_reference_data(rel_uuid, callback) {
		$.getJSON( "/events/getReferenceData/"+rel_uuid+"/reference.json", function( data ) {
			callback(data);
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
		// Dirty way to know what modif was successful as the callback gives no information
		// May be changed in the futur
		this.callback_to_be_called = null;
	}
	
	register_callback(callback) {
		this.callback_to_be_called = callback;
	}

	apply_callback() {
		var that = mispInteraction;
		if (that.callback_to_be_called !== null) {
			that.callback_to_be_called(that.callback_data);
		}
		that.callback_to_be_called = null;
		that.callback_data = null;
	}

	remove_reference(edgeData, callback) {
		var that = mispInteraction;
		var edge_id = edgeData.edges[0];
		var relation_id = edge_id;
		deleteObject('object_references', 'delete', relation_id, scope_id);
	}
	
	add_reference(edgeData, callback) {
		var that = mispInteraction;
		var uuid = dataHandler.mapping_attr_id_to_uuid.get(edgeData.to);
		if (!that.can_create_reference(edgeData.from) || !that.can_be_referenced(edgeData.to)) {
			return;
		}
		genericPopup('/objectReferences/add/'+edgeData.from, '#popover_form', function() {
			$('#targetSelect').val(uuid);
			$('option[value='+uuid+']').click()
		});
	}

	edit_reference(edgeData, callback) {
		if (callback !== undefined) {
			callback();
		}
		var that = mispInteraction;
		var rel_id = edgeData.id;
		var rel_uuid = dataHandler.mapping_rel_id_to_uuid.get(rel_id);
		
		that.register_callback(function() {
			var relation_id = edgeData.id;
			submitDeletion(scope_id, 'delete', 'object_references', relation_id);
		});

		dataHandler.fetch_reference_data(rel_uuid, function(data) {
			data = data[0].ObjectReference;
			var uuid = data.referenced_uuid;
			genericPopup('/objectReferences/add/'+data.object_id, '#popover_form', function() {
				$('#targetSelect').val(uuid);
				$('#ObjectReferenceComment').val(data.comment);
				$('#ObjectReferenceRelationshipTypeSelect').val(data.relationship_type);
				$('option[value='+uuid+']').click();
			});
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
		var that = mispInteraction;
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
		var that = mispInteraction;
		var id = nodeData.id
		var group = nodes.get(id).group;
		if (group == 'attribute') {
			simplePopup('/attributes/edit/'+id);
		} else if (group == 'object') {
			window.location = '/objects/edit/'+id;
		}
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
 	// sucess and eventgraph is enabled
	if (result == "success" && dataHandler !== undefined) {
		mispInteraction.apply_callback();
		dataHandler.fetch_data_and_update(false);
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
			if($('#network-typeahead').is(":focus")) {
				return;
			}
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
						if (selected_id !== undefined) { // A node is selected
							var data = { id: selected_id };
							mispInteraction.edit_item(data);
							break;
						}
						selected_id = eventGraph.network.getSelectedEdges()[0]; 
						if (selected_id !== undefined) { // A edge is selected
							var data = { id: selected_id };
							mispInteraction.edit_reference(data);
							break;
						}
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

		$("#network-layout-type").change(function() {
			var selected = $(this).val();
			switch(selected) {
				case "default":
					eventGraph.change_layout_type('default');
					break;
					
				case "hierarchical.directed":
					eventGraph.change_layout_type('directed');
					break;

				case "hierarchical.hubsize":
					eventGraph.change_layout_type('hubsize');
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
	layout: {
		improvedLayout: false,
		hierarchical: {
			      enabled: false,
			      levelSeparation: 150,
			      nodeSpacing: 5,
			      treeSpacing: 200,
			      blockShifting: true,
			      edgeMinimization: true,
			      parentCentralization: true,
			      direction: 'UD',        // UD, DU, LR, RL
			      sortMethod: 'directed'   // hubsize, directed
		}

	},
	manipulation: {
		enabled: user_manipulation,
		initiallyActive: false,
		addEdge: mispInteraction.add_reference,
		editEdge: { editWithoutDrag: mispInteraction.edit_reference },
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
		hierarchicalRepulsion: {
			centralGravity: 0,
			springLength: 150,
			springConstant: 0.24,
			nodeDistance: 120,
			damping: 1
		},
		minVelocity: 3.0,
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
		rootNodeObject: {
			shape: 'icon',
			icon: {
				face: 'FontAwesome',
				code: '\uf00a',
			},
			font: {
				size: 18, // px
				background: 'rgba(255, 255, 255, 0.7)'
			},

		},
		rootNodeAttribute: {
			shape: 'icon',
			icon: {
				face: 'FontAwesome',
				code: '\uf1c0',
			},
			font: {
				size: 18, // px
				background: 'rgba(255, 255, 255, 0.7)'
			},
		},
		clustered_object: {
			shape: 'icon',
			icon: {
				face: 'FontAwesome',
				code: '\uf009',
			},
			font: {
				size: 18, // px
				background: 'rgba(255, 255, 255, 0.7)'
			},
		}
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
			editEdge: 'Edit Reference',
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
		// check if node in cluster
		nested_length = eventGraph.network.findNode(nodeID).length;
		if (nested_length > 1) { // Node is in cluster
			// As vis.js cannot supply a way to uncluster a single node, we remove it and add it again
			searched_node = eventGraph.nodes.get(nodeID);
			// Remove old node and edges
			eventGraph.nodes.remove(nodeID);
			eventGraph.nodes.add(searched_node);
			/* don't need to re-add the edge as it is the same */
			eventGraph.focus_on_stabilized(nodeID);
		} else {
			// set focus to the network
			eventGraph.network.focus(nodeID, {animation: true, scale: 1});
		}
		// select node and focus on it
		eventGraph.network.selectNodes([nodeID]);
		$("#network-typeahead").blur();
	},
	autoSelect: true
}
var max_displayed_char = 32;
var progressbar_length = 3; // divided by 100
var loadingText_fetching = 'Fetching data';
var loadingText_creating = 'Constructing network';
var loadingText_redrawing = 'Redrawing network';

var shortcut_text = "<b>V:</b> Center camera"
		+ "\n<b>X:</b> Expaned node"
		+ "\n<b>C:</b> Collapse node"
		+ "\n<b>SHIFT+E:</b> Edit node"
		+ "\n<b>SHIFT+F:</b> Search for value"
		+ "\n<b>SHIFT:</b> Hold to add a reference"
		+ "\n<b>DEL:</b> Delete selected item";

function global_processProperties(clusterOptions, childNodes) {
	var concerned_root_node;
	var that = eventGraph;
	that.cluster_index = that.cluster_index + 1;
	var childrenCount = 0;
	for (var i = 0; i < childNodes.length; i++) {
		var childNodeID = childNodes[i].id
		if ( childNodeID == "rootNode:object" || childNodeID == "rootNode:attribute") {
			concerned_root_node = childNodeID;
		}
		childrenCount += childNodes[i].childrenCount || 1;
	}
	childrenCount--; // -1 because 2 nodes merged into 1
	clusterOptions.childrenCount = childrenCount;
	clusterOptions.font = {size: Math.sqrt(childrenCount)*0.5+30}
	clusterOptions.id = 'cluster:' + that.cluster_index;
	if (concerned_root_node !== undefined) {
		clusterOptions.icon = { size: Math.sqrt(childrenCount)*5+100 };
		if (concerned_root_node == "rootNode:object") {
			clusterOptions.label = "Unreferenced Objects (" + childrenCount + ")";
			clusterOptions.x =  root_node_x_pos;
			clusterOptions.group = 'rootNodeObject';
		} else if (concerned_root_node == "rootNode:attribute") {
			clusterOptions.label = "Unreferenced Attributes (" + childrenCount + ")";
			clusterOptions.x =  -root_node_x_pos;
			clusterOptions.group = 'rootNodeAttribute';
		}
		clusterOptions.fixed = true;
	}
	clusterOptions.y = 0
	that.clusters.push({id:'cluster:' + that.cluster_index, scale: that.cur_scale, group: clusterOptions.group});
	return clusterOptions;
}
