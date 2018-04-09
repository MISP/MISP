/*=============
 * GLOBAL VARS
 * ============*/
var eventGraph;
var dataHandler;
var mispInteraction;
var nodes = new vis.DataSet();
var edges = new vis.DataSet();

var typeaheadDataSearch;
var scope_id = $('#eventgraph_network').data('event-id');
var container = document.getElementById('eventgraph_network');
var user_manipulation = $('#eventgraph_network').data('user-manipulation');
var root_id_attr = "rootNode:attribute";
var root_id_object = "rootNode:object";
var root_id_tag = "rootNode:tag";
var root_id_keyType = "rootNode:keyType";
var mapping_root_id_to_type = {};
mapping_root_id_to_type[root_id_attr] = 'attribute';
mapping_root_id_to_type[root_id_object] = 'object';
mapping_root_id_to_type[root_id_tag] = 'tag';
mapping_root_id_to_type[root_id_keyType] = 'keyType';
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
		this.mapping_meta_fa.set('misc', {"meta-category": "misc","fa_text": "cube","fa-hex": "f1b2"}); // Also considered as default
		// FIXME
		this.network_options = network_options;
		this.scope_name;
		this.scope_keyType;
		this.globalCounter = 0;
		this.first_draw = true;
		this.root_node_shown = false;
		this.is_filtered = false;
		this.menu_scope = this.init_scope_menu();
		this.menu_physic = this.init_physic_menu();
		this.menu_display = this.init_display_menu();
		this.menu_filter = this.init_filter_menu();
		this.new_edges_for_unreferenced_nodes = [];
		this.layout = 'default';
		this.solver = 'barnesHut';
		this.backup_connection_edges = {};
		this.nodes = nodes;
		this.edges = edges;
		var data = { // empty
			nodes: this.nodes,
			edges: this.edges
		};
		this.object_templates = {};

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
	get_FA_icon(metaCateg) {
		var dict = this.mapping_meta_fa.get(metaCateg);
		dict = dict === undefined ? this.mapping_meta_fa.get('misc') : dict; // if unknown meta-categ, take default
		return String.fromCharCode(parseInt(dict['fa-hex'], 16))
	}
	getUniqId() {
		this.globalCounter++;
		return this.globalCounter-1;
	}
	update_scope(value) {
		if (value === undefined) {
			value = $("#select_graph_scope").val();
		} else {
			$("#select_graph_scope").val(value);
		}
		$("#network-scope-badge").text(value);
		this.scope_name = value;
		dataHandler.scope_name = value;
	}
	
	init_scope_menu() {
		var menu_scope = new ContextualMenu({
			trigger_container: document.getElementById("network-scope"),
			bootstrap_popover: true,
		});
		menu_scope.add_select({
			id: "select_graph_scope",
			label: "Scope",
			tooltip: "The scope represented by the network",
			event: function(value) {
				if (value == "JSON key" && $('#input_graph_scope_jsonkey').val() == "") { // no key selected  for JSON key scope
					return;
				} else {
					eventGraph.update_scope(value);
					dataHandler.fetch_data_and_update();
				}
			},
			options: ["Reference", "Correlation", "Tag", "JSON key"],
			default: "Reference"
		});
		menu_scope.add_input({
			id: "input_graph_scope_jsonkey",
			label: "JSON key",
			tooltip: "The JSON key to be graphed",
			placeholder: "E.g. distribution",
			typeahead: {
				source: function(query, process) {
					process(dataHandler.available_JSON_key);
				},
				updater: function (value) {
					// change scope to JSON key
					eventGraph.update_scope("JSON key");
					eventGraph.scope_keyType = value;
					dataHandler.fetch_data_and_update();
				},
				autoSelect: true
			}
		});
		return menu_scope;
	}

	init_physic_menu() {
		var menu_physic = new ContextualMenu({
			trigger_container: document.getElementById("network-physic"),
			bootstrap_popover: true
		});
		menu_physic.add_select({
			id: "select_physic_solver",
			label: "Solver",
			tooltip: "Physics solver to use",
			event: function(value) {
				eventGraph.physics_change_solver(value);
			},
			options: ["barnesHut", "repulsion"],
			default: "barnesHut"
		});
		menu_physic.add_slider({
			id: 'slider_physic_node_repulsion',
			label: "Node repulsion",
			min: 0,
			max: 1000,
			value: this.network_options.physics.barnesHut.springLength,
			step: 10,
			event: function(value) {
				eventGraph.physics_change_repulsion(parseInt(value));
			},
			tooltip: "Correspond to spring length for barnesHut and node spacing for hierachical"
		});
		menu_physic.add_checkbox({
			label: "Enable physics",
			event: function(checked) {
				eventGraph.physics_state(checked);
			},
			checked: true
		});
		return menu_physic;
	}

	init_display_menu() {
		var menu_display = new ContextualMenu({
			trigger_container: document.getElementById("network-display"),
			bootstrap_popover: true
		});
		menu_display.add_select({
			id: "select_display_layout",
			label: "Layout",
			event: function(value) {
				switch(value) {
					case "default":
						eventGraph.change_layout_type("default");
						break;
					case "hierarchical.directed":
						eventGraph.change_layout_type("directed");
						break;
					case "hierarchical.hubsize":
						eventGraph.change_layout_type("hubsize");
						break;
					default:
						eventGraph.change_layout_type("default");
				}
			},
			options: [
				{text: "Default layout", value: "default"}, 
				{text: "Hierachical directed", value: "hierarchical.directed"}, 
				{text: "Hierachical hubsize", value: "hierarchical.hubsize"}
			],
			default: "default"
		});
		menu_display.add_select({
			id: "select_display_object_field",
			label: "Object-relation in label",
			event: function(value) {
				dataHandler.selected_type_to_display = value;
				dataHandler.fetch_data_and_update();
			},
			options: [],
			title: "If no item is selected, display the first requiredOneOf of the object"
		});
		menu_display.add_button({
			label: "Expand all nodes",
			type: "danger",
			event: function() {
				var objectIds = eventGraph.nodes.getIds({
					filter: function(item) { return item.group == 'object'; }
				})
				for(var nodeId of objectIds) {
					eventGraph.expand_node(nodeId);
				}
			}
		});
		menu_display.add_button({
			label: "Collapse all nodes",
			type: "danger",
			event: function() {
				var objectIds = eventGraph.nodes.getIds({
					filter: function(item) { return item.group == 'object'; }
				});
				for(var nodeId of objectIds) {
					eventGraph.collapse_node(nodeId);
				}
			}
		});
		menu_display.add_slider({
			id: 'slider_display_max_char_num',
			label: "Charater to show",
			title: "Maximum number of charater to display in the label",
			min: 8,
			max: 1024,
			value: max_displayed_char,
			step: 8,
			applyButton: true,
			event: function(value) {
				$("#slider_display_max_char_num").parent().find("span").text(value);
			},
			eventApply: function(value) {
				dataHandler.fetch_data_and_update();
			}
		});
		return menu_display;
	}

	init_filter_menu() {
		var menu_filter = new ContextualMenu({
			trigger_container: document.getElementById("network-filter"),
			bootstrap_popover: true
		});
		menu_filter.add_action_table({
			id: "table_attr_presence",
			container: menu_filter.menu,
			title: "Filter on Attribute presence",
			header: ["Relation", "Attribute"],
			control_items: [
				{
					DOMType: "select",
					item_options: {
						options: ["Contains", "Do not contain"]
					}
				},
				{
					DOMType: "select",
					item_options: {
						id: "table_control_select_attr_presence",
						options: []
					}
				},
			],
			data: [],
		});
		menu_filter.create_divider(3);
		menu_filter.add_action_table({
			id: "table_attr_value",
			container: menu_filter.menu,
			title: "Filter on Attribute value",
			header: ["Attribute", "Comparison", "Value"],
			control_items: [
				{
					DOMType: "select",
					item_options: {
						id: "table_control_select_attr_value",
						options: []
					}
				},
				{
					DOMType: "select",
					item_options: {
						options: ["<", "<=", "==", ">=", ">"]
					}
				},
				{
					DOMType: "input",
					item_options: {}
				}
			],
			data: [],
			onAddition: function(data) {
				eventGraph.menu_filter.items["table_attr_presence"].add_row(["Contains", data[0]]);
			}
		});
		menu_filter.items["table_attr_value"].table.style.minWidth = "550px";
		menu_filter.add_button({
			label: "Filter",
			type: "primary",
			event: function() {
				dataHandler.fetch_data_and_update();
			}
		});
		return menu_filter;
	}

	get_filtering_rules() {
		var rules_presence = eventGraph.menu_filter.items["table_attr_presence"].get_data();
		var rules_value = eventGraph.menu_filter.items["table_attr_value"].get_data();
		var rules = { presence: rules_presence, value: rules_value };
		return rules;
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

	reset_graphs(hard) {
		this.nodes.clear();
		this.edges.clear();
		if (hard) {
			this.backup_connection_edges = {};
		}
	}
	
	update_graph(data) {
		setTimeout(function() { eventGraph.network_loading(true, loadingText_creating); });
		
		// New nodes will be automatically added
		// removed references will be deleted
		var node_conf;
		var newNodes = [];
		var newNodeIDs = [];
		for(var node of data.items) {
			var group, label;
			if ( node.node_type == 'object' ) {
				var group =  'object';
				var label = dataHandler.generate_label(node);
				var striped_value = this.strip_text_value(label);
				node_conf = { 
					id: node.id,
					uuid: node.uuid,
					Attribute: node.Attribute,
					label: striped_value,
					title: label,
					group: group,
					mass: 5,
					icon: {
						color: getRandomColor(),
						face: 'FontAwesome',
						code: this.get_FA_icon(node['meta-category']),
					}
				};
				dataHandler.mapping_value_to_nodeID.set(striped_value, node.id);
			} else if (node.node_type == 'tag') {
				var tag_color = node.tagContent.colour;
				group =  'tag';
				label = node.label;
				node_conf = { 
					id: node.id,
					uuid: node.uuid,
					label: label,
					title: label,
					group: group,
					mass: 20,
					color: { 
						background: tag_color,
						border: tag_color
					},
					font: {
						color: getTextColour(tag_color),
						bold: true,
						size: 28
					},
					shapeProperties: {
						borderRadius: 6
					}
				};
				dataHandler.mapping_value_to_nodeID.set(striped_value, node.id);
			} else if (node.node_type == 'keyType') {
				group = 'keyType';
				label = this.scope_keyType + ": " + node.label;
				var striped_value = this.strip_text_value(label);
				node_conf = {
					id: node.id,
					label: striped_value,
					title: label,
					group: group
				};
				dataHandler.mapping_value_to_nodeID.set(striped_value, node.id);
			} else {
				group =  'attribute';
				label = node.type + ': ' + node.label;
				var striped_value = this.strip_text_value(label);
				node_conf = { 
					id: node.id,
					uuid: node.uuid,
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
			if (old_id == "rootNode:attribute" || old_id == "rootNode:object" || old_id == "rootNode:tag" || old_id == "rootNode:keyType") {
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
		
		this.remove_root_nodes();
		if (this.scope_name == 'Reference') {
			this.add_unreferenced_root_node();
			// links unreferenced attributes and object to root nodes
			if (this.first_draw) {
				this.link_not_referenced_nodes();
				this.first_draw = !this.first_draw
			}
		} else if (this.scope_name == 'Tag') {
			this.add_tag_root_node();
			// links untagged attributes and object to root nodes
			if (this.first_draw) {
				this.link_not_referenced_nodes();
				this.first_draw = !this.first_draw
			}
		} else if (this.scope_name == 'Distribution') {
		} else if (this.scope_name == 'Correlation') {
		} else {
			this.add_keyType_root_node();
			if (this.first_draw) {
				this.link_not_referenced_nodes();
				this.first_draw = !this.first_draw
			}
		}

		this.network_loading(false, "");
	}

	strip_text_value(text) {
		var max_num = $("#slider_display_max_char_num").val();
		return text.substring(0, max_num) + (text.length < max_num ? "" : "[...]")
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

	physics_state(state) {
		var that = eventGraph;
		that.network_options.physics.enabled = state;
		if(that.layout == "default") {
			$("#select_physic_solver").prop('disabled', !state);
		}
		$("#slider_physic_node_repulsion").prop('disabled', !state);
		that.network.setOptions({physics: { enabled: state} })
	}

	physics_change_repulsion(value) {
		var that = eventGraph;
		if(that.layout == 'default') { // repulsion on default is related to spring length
			if(that.solver == "barnesHut") {
				that.network.setOptions({physics: { barnesHut: {springLength: value} } })
			} else {
				that.network.setOptions({physics: { repulsion: {nodeDistance: value} } })
			}
		} else {
			that.network.setOptions({physics: { hierarchicalRepulsion: {nodeDistance: value} } })
		}
	}

	physics_change_solver(solver) {
		var that = eventGraph;
		if(that.layout == 'default') { // only hierachical repulsion for other layout
			that.network.setOptions({physics: { solver: solver } })
			// update physics slider value
			if(solver == "barnesHut") {
				$("#slider_physic_node_repulsion").val(that.network_options.physics.barnesHut.springLength);
				$("#slider_physic_node_repulsion").parent().find("span").text(that.network_options.physics.barnesHut.springLength);
			} else {
				$("#slider_physic_node_repulsion").val(that.network_options.physics.repulsion.nodeDistance);
				$("#slider_physic_node_repulsion").parent().find("span").text(that.network_options.physics.repulsion.nodeDistance);
			}
		}
		that.solver = solver;
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
		
		if (!(parent_id == root_id_attr || parent_id == root_id_object || parent_id == root_id_tag || parent_id == root_id_keyType)) { // Is not a root node
			var node_group = this.nodes.get(parent_id).group;
			if (parent_id === undefined || node_group != 'object') { //  No node selected  or collapse not permitted
				return
			}
			var connected_nodes_ids = this.network.getConnectedNodes(parent_id);
			var connected_nodes = this.nodes.get(connected_nodes_ids);
			for (var node of connected_nodes) {
				if (node.group == "obj_relation") {
					// remove edge
					var connected_edges = this.network.getConnectedEdges(node.id);
					for (var edgeID of connected_edges) {
						this.edges.remove(edgeID);
					}
					this.nodes.remove(node.id);
				}
			}
		} else { // Is a root node
			this.clusterize(parent_id);
		}
	}
	
	expand_node(parent_id) {
		if (!this.network.isCluster(parent_id)) {

			var parent_node = this.nodes.get(parent_id);
			if (parent_id === undefined //  Node node selected
			    || parent_node.group != "object") { //  Cannot expand attribute
				return;
			}

			var objAttributes = parent_node.Attribute;
			var newNodes = [];
			var newRelations = [];
	
			var parent_pos = this.network.getPositions([parent_id])[parent_id];
			for(var attr of objAttributes) {
				var parent_color = eventGraph.get_node_color(parent_id);
						
				// Ensure unicity of nodes
				if (this.nodes.get(attr.uuid) !== null) {
					continue;
				}
						
				var striped_value = this.strip_text_value(attr.value);
				var node = { 
					id: attr.uuid,
					x: parent_pos.x,
					y: parent_pos.y,
					label: attr.object_relation + ': ' + striped_value,
					title: attr.object_relation + ': ' + attr.value,
					group: 'obj_relation',
					color: { 
						background: parent_color
					},
					font: {
						color: getTextColour(parent_color)
					}
				};
				newNodes.push(node);
				dataHandler.mapping_obj_relation_value_to_nodeID.set(striped_value, node.id);
						
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
		// unlink previously linked
		this.edges.remove(this.new_edges_for_unreferenced_nodes)
		this.new_edges_for_unreferenced_nodes = [];

		// link not referenced nodes
		var newEdges = [];
		var that = this;
		this.nodes.forEach(function(nodeData) {
			var cur_id = nodeData.id;
			var cur_group = nodeData.group;

			// Do not link already connected nodes
			if (that.network.getConnectedEdges(cur_id).length > 0) {
				return;
			}

			var new_edge = {
				to: cur_id,
				id: "temp_edge_unreferenced_" + that.getUniqId(),
				arrows: '',
				color: {
					opacity: 0.7,
					color: '#d9d9d9'
				},
				length: 150
			}


			if (that.scope_name == 'Reference') {
				if (cur_group == 'attribute' || cur_group == 'object') {
					new_edge.from = cur_group == 'attribute' ? root_id_attr : root_id_object;
					that.nodes.update({id: nodeData.id, unreferenced: cur_group});
				}
			} else if (that.scope_name == 'Tag') {
				if (cur_group == 'attribute' || cur_group == 'object') {
					new_edge.from = root_id_tag;
					that.nodes.update({id: nodeData.id, unreferenced: 'tag'});
				}
			} else if (that.scope_name == 'Correlation') {
			} else {  // specified key
				if (cur_group == 'attribute' || cur_group == 'object') {
					new_edge.from = root_id_keyType;
					that.nodes.update({id: nodeData.id, unreferenced: that.scope_name});
				}
			}
			
			newEdges.push(new_edge);
			that.new_edges_for_unreferenced_nodes.push(new_edge.id);
		});
		this.edges.add(newEdges);
		this.init_clusterize();
	}

	remove_root_nodes() {
		this.remove_unreferenced_root_node();
		this.remove_tag_root_node();
		this.remove_keyType_root_node();
	}

	add_unreferenced_root_node() {
		if (this.root_node_shown) {
			return;
		}
		var root_node_attr = {
			id: root_id_attr,
			x: -root_node_x_pos,
			y: 0,
			label: 'Unreferenced Attributes',
			title: 'All Attributes not being referenced',
			group: 'rootNodeAttribute'
		};
		var root_node_obj = {
			id: root_id_object,
			x: root_node_x_pos,
			y: 0,
			label: 'Unreferenced Objects',
			title: 'All Objects not being referenced',
			group: 'rootNodeObject'
		};
		this.nodes.add([root_node_attr, root_node_obj]);
		this.root_node_shown = true;
	}
	remove_unreferenced_root_node() {
		this.nodes.remove([root_id_attr, root_id_object]);
		this.root_node_shown = false;
	}

	add_tag_root_node() {
		if (this.root_node_shown) {
			return;
		}
		var root_node_tag = {
			id: root_id_tag,
			x: -root_node_x_pos,
			y: 0,
			label: 'Untagged Attribute',
			title: 'All Attributes not being tagged',
			group: 'rootNodeTag'
		};
		this.nodes.add([root_node_tag]);
		this.root_node_shown = true;
	}
	remove_tag_root_node() {
		this.nodes.remove([root_id_tag]);
		this.root_node_shown = false;
	}

	add_keyType_root_node() {
		if (this.root_node_shown) {
			return;
		}
		var root_node_keyType = {
			id: root_id_keyType,
			x: -root_node_x_pos,
			y: 0,
			label: this.scope_name + ': No value',
			title: 'All Attributes not having a value for the specified field',
			group: 'rootNodeKeyType'
		};
		this.nodes.add([root_node_keyType]);
		this.root_node_shown = true;

	}
	remove_keyType_root_node() {
		this.nodes.remove([root_id_keyType]);
		this.root_node_shown = false;
	}

	switch_unreferenced_nodes_connection() {
		var that = eventGraph;
		var to_update = [];
		var root_ids;
		switch(that.scope_name) {
			case "Reference":
				root_ids = [root_id_attr, root_id_object];
				break;
			case "Tag":
				root_ids = [root_id_tag];
				break;
			default:
				root_ids = [root_id_keyType];
				break;
		}

		for(var root_id of root_ids) {
			if(that.layout == 'default') {
				var all_edgesID = that.backup_connection_edges[root_id]
				if (all_edgesID === undefined) { // edgesID was not saved (happen if we switch scope then layout)
					// redraw everything
					eventGraph.destroy_and_redraw();
					return;
				}
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
			that.network_options = $.extend(true, {}, default_layout_option);;
			// update physics slider value
			$("#slider_physic_node_repulsion").val(that.network_options.physics.barnesHut.springLength);
			$("#slider_physic_node_repulsion").parent().find("span").text(that.network_options.physics.barnesHut.springLength);
			$("#select_physic_solver").prop('disabled', false);
		} else {
			that.network_options.layout.hierarchical.enabled = true;
			that.network_options.layout.hierarchical.sortMethod = layout;
			// update physics slider value
			$("#slider_physic_node_repulsion").val(that.network_options.physics.hierarchicalRepulsion.nodeDistance);
			$("#slider_physic_node_repulsion").parent().find("span").text(that.network_options.physics.hierarchicalRepulsion.nodeDistance);
			$("#select_physic_solver").prop('disabled', true);
		}
		that.layout = layout;
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
	constructor() {
		this.mapping_value_to_nodeID = new Map();
		this.mapping_obj_relation_value_to_nodeID = new Map();
		this.mapping_uuid_to_template = new Map();
		this.selected_type_to_display = "";
		this.scope_name;
	}

	get_scope_url() {
		switch(this.scope_name) {
			case "Reference":
				return "getEventGraphReferences";
			case "Tag":
				return "getEventGraphTags";
			case "Correlation":
				return "getEventGraphReferences";
			default:
				return "getEventGraphGeneric";
		}
	}

	generate_label(obj) {
		var label = obj.type;
		for (var attr of obj.Attribute) { // for each field
			if (attr.object_relation == this.selected_type_to_display) {
				label += ": " + attr.value;
				return label;
			}
		}
		if(this.selected_type_to_display !== "") { // User explicitly choose the type to display
			return label;
		}
		// no matching, taking the first requiredOff
		var template_uuid = obj.template_uuid;
		var template_req = this.mapping_uuid_to_template.get(template_uuid);
		if (template_req === undefined) { // template not known
			return label;
		}
		// search if this field exists in the object
		for (var attr of obj.Attribute) { // for each field
			var attr_type = attr.type;
			if (template_req.indexOf(attr_type) != -1) {
				label += ": " + attr.value;
				return label;
			}
		}
		return label;
	}

	update_available_object_references(available_object_references) {
		eventGraph.menu_display.add_options("select_display_object_field", available_object_references);
		eventGraph.menu_filter.items["table_attr_presence"].add_options("table_control_select_attr_presence", available_object_references);
		eventGraph.menu_filter.items["table_attr_value"].add_options("table_control_select_attr_value", available_object_references);
	}
	
	fetch_data_and_update(stabilize) {
		eventGraph.network_loading(true, loadingText_fetching);
		$.when(this.fetch_objects_template()).done(function() {
			var filtering_rules = eventGraph.get_filtering_rules();
			//var keyType = dataHandler.scope_name == "JSON key" ? eventGraph.scope_keyType : dataHandler.scope_name;
			var keyType = eventGraph.scope_keyType;
			var payload = {};
			payload.filtering = filtering_rules;
			payload.keyType = keyType;
			$.ajax({
				url: "/events/"+dataHandler.get_scope_url()+"/"+scope_id+"/event.json",
				dataType: 'json',
				type: 'post',
				contentType: 'application/json',
				data: JSON.stringify( payload ),
				processData: false,
				success: function( data, textStatus, jQxhr ){
					eventGraph.reset_graphs(true);
					eventGraph.is_filtered = (filtering_rules.presence.length > 0 || filtering_rules.value.length > 0);
					eventGraph.first_draw = true;
					var available_object_references = Object.keys(data.existing_object_relation);
					dataHandler.update_available_object_references(available_object_references);
					dataHandler.available_JSON_key = data.available_JSON_key;
					eventGraph.update_graph(data);
					if ( stabilize === undefined || stabilize) {
						eventGraph.reset_view_on_stabilized();
					}
				},
				error: function( jqXhr, textStatus, errorThrown ){
					console.log( errorThrown );
				}
			});
		});
	}

	fetch_reference_data(rel_uuid, callback) {
		$.getJSON( "/events/getReferenceData/"+rel_uuid+"/reference.json", function( data ) {
			callback(data);
		});
	}

	fetch_objects_template() {
		return $.getJSON( "/events/getObjectTemplate/templates.json", function( data ) {
			for (var i in data) {
				var template = data[i].ObjectTemplate;
				dataHandler.mapping_uuid_to_template.set(template.uuid, template.requirements.requiredOneOf);
			}
		});
	}

	get_typeaheadData_search() {
		var to_ret = []
		for( var entry of this.mapping_value_to_nodeID) {
			var value = entry[0];
			to_ret.push(value);
		}
		// object relation
		for( var entry of this.mapping_obj_relation_value_to_nodeID) {
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
		if (callback !== undefined) {
			callback();
		}
	}
	
	add_reference(edgeData, callback) {
		var that = mispInteraction;
		//var uuid = dataHandler.mapping_attr_id_to_uuid.get(edgeData.to);
		var uuid = that.nodes.get(edgeData.to).uuid;
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
		var rel_uuid = edgeData.uuid;
		
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

		dataHandler = new DataHandler();
		eventGraph = new EventGraph(network_options, nodes, edges);

		$(document).on("keydown", function(evt) {
			if($('#network-typeahead').is(":focus")) {
				if (evt.keyCode == 27) { // <ESC>
					$('#network-typeahead').blur();
				}
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

		eventGraph.update_scope();
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
		repulsion: {
			centralGravity: 5,
			springLength: 150,
			springConstant: 0.04,
			nodeDistance: 240,
			damping: 0.3
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
			mass: 3,
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
		tag: {
			shape: 'box',
			size: 15,
			shadow: {
				enabled: true,
				size: 3,
				x: 3, y: 3
			},
			mass: 20
		},
		keyType: {
			shape: 'box',
			color: {
				border: '#303030',
				background: '#808080',
			},
			font: {
				size: 18, //px
				color: 'white'
			},
			mass: 25

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
			mass: 5
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
			mass: 5
		},
		rootNodeKeyType: {
			shape: 'icon',
			icon: {
				face: 'FontAwesome',
				code: '\uf111',
			},
			font: {
				size: 22, // px
				background: 'rgba(255, 255, 255, 0.7)'
			},
			mass: 5
		},
		rootNodeTag: {
			shape: 'icon',
			icon: {
				face: 'FontAwesome',
				code: '\uf02b',
			},
			font: {
				size: 22, // px
				background: 'rgba(255, 255, 255, 0.7)'
			},
			mass: 5
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
			mass: 5
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
var default_layout_option = $.extend(true, {}, network_options);

var typeaheadOption = {
	source: function (query, process) {
		if (typeaheadDataSearch === undefined) { // caching
			typeaheadDataSearch = dataHandler.get_typeaheadData_search();
		}
		process(typeaheadDataSearch);
	},
	updater: function(value) {
		var nodeID = dataHandler.mapping_value_to_nodeID.get(value);
		// in case we searched for an object relation
		nodeID = nodeID === undefined ? dataHandler.mapping_obj_relation_value_to_nodeID.get(value) : nodeID;
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
		if ( childNodeID.includes("rootNode:")) {
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
		} else if (concerned_root_node == "rootNode:tag") {
			clusterOptions.label = "Untagged elements (" + childrenCount + ")";
			clusterOptions.x =  -root_node_x_pos;
			clusterOptions.group = 'rootNodeTag';
		} else if (concerned_root_node == "rootNode:keyType") {
			clusterOptions.label = "Empty value elements (" + childrenCount + ")";
			clusterOptions.x =  -root_node_x_pos;
			clusterOptions.group = 'rootNodeKeyType';
		}
	}
	clusterOptions.y = 0
	that.clusters.push({id:'cluster:' + that.cluster_index, scale: that.cur_scale, group: clusterOptions.group});
	return clusterOptions;
}
