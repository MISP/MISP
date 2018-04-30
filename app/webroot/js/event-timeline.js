var eventTimeline;
var container_timeline = document.getElementById('event_timeline');
var options = {
	template: function (item, element, data) {
		switch(item.group) {
			case "attribute":
				return item.content;

			case "object":
				return build_object_template(item);

			case "object_attribute":
				console.log('Error');
				break;

			default:
				break;
		}
	},
	verticalScroll: true,
	zoomKey: 'altKey',
	maxHeight: 400,
	multiselect: true,
	editable: true,
	editable: {
		add: true,         // add new items by double tapping
		updateTime: true,  // drag items horizontally
	},

};

/* UTIL */

function build_object_template(obj) {
	var table = $('<table>');
	table.append($('<tr class="timeline-objectName"><th>'+obj.content+'</th><th></th></tr>'));
	for (var attr of obj.Attribute) {
		table.append(
			$('<tr>').append(
				$('<td class="timeline-objectAttrType">' + attr.contentType + '</td>'
				    +'<td class="timeline-objectAttrVal">' + attr.content+ '</td>'
				)
			)
		)
	}
	var html = table[0].outerHTML;
	return html;
}

function enable_timeline() {
	if (eventTimeline !== undefined) {
		return;
	}

	init_popover();
	var payload = {};
	$.ajax({
		url: "/events/"+"getEventTimeline"+"/"+scope_id+"/event.json",
		dataType: 'json',
		type: 'post',
		contentType: 'application/json',
		data: JSON.stringify( payload ),
		processData: false,
		beforeSend: function (XMLHttpRequest) {
			$(".loadingTimeline").show();
		},
		success: function( data, textStatus, jQxhr ){
			console.log(data);
			for (var item of data.items) {
				item.start = new Date(item.timestamp*1000);
				item.className = item.group;
			}
			var items_timeline = new vis.DataSet(data.items);
			eventTimeline = new vis.Timeline(container_timeline, items_timeline, options);
			$(".loadingTimeline").hide();
		},
		error: function( jqXhr, textStatus, errorThrown ){
			console.log( errorThrown );
		}
	});
}

$('#fullscreen-btn-timeline').click(function() {
	var timeline_div = $('#eventtimeline_div');
	var fullscreen_enabled = !timeline_div.data('fullscreen');
	timeline_div.data('fullscreen', fullscreen_enabled);
	var height_val = fullscreen_enabled == true ? "calc(100vh - 42px - 42px - 10px)" : "400px";

	timeline_div.css("max-height", height_val);
	setTimeout(function() { // timeline takes time to be drawn
		timeline_div[0].scrollIntoView({
			behavior: "smooth",
		});
	}, 1);
	eventTimeline.setOptions({maxHeight: height_val});
});

// init_scope_menu
var menu_scope_timeline;
function init_popover() {
	menu_scope_timeline = new ContextualMenu({
		trigger_container: document.getElementById("timeline-scope"),
		bootstrap_popover: true,
		style: "z-index: 1",
		container: document.getElementById("eventtimeline_div")
	});
	menu_scope_timeline.add_select({
		id: "select_timeline_scope",
		label: "Scope",
		tooltip: "The time scope represented by the timeline",
		event: function(value) {
			console.log(value);
			//if (value == "Rotation key" && $('#input_graph_scope_jsonkey').val() == "") { // no key selected  for Rotation key scope
			//	return;
			//} else {
			//	eventGraph.update_scope(value);
			//	dataHandler.fetch_data_and_update();
			//}
		},
		options: ["Item's last update", "Time attached to the object"],
		default: "Item's last update"
	});
	menu_scope_timeline.add_select({
		id: "select_timeline_scope_jsonkey",
		label: "Object relation",
		tooltip: "The object relation to be consider as time reference",
		event: function(value) {
			console.log(value);
			//if (value == "Rotation key" && $('#input_graph_scope_jsonkey').val() == "") { // no key selected for Rotation key scope
			//	return;
			//} else {
			//	eventGraph.scope_keyType = value;
			//	eventGraph.update_scope("Rotation key");
			//	dataHandler.fetch_data_and_update();
			//}
		},
		options: undefined ? dataHandler.available_rotation_key : [],
		default: ""
	});

	var menu_display_timeline = new ContextualMenu({
		trigger_container: document.getElementById("timeline-display"),
		bootstrap_popover: true,
		style: "z-index: 1",
		container: document.getElementById("eventtimeline_div")
	});
	menu_display_timeline.add_action_table({
		id: "table_timeline_display_object_field",
		container: menu_display_timeline.menu,
		title: "Object's Attributes to be shown",
		header: ["Object attribute type"],
		control_items: [
			{
				DOMType: "select",
				item_options: {
					id: "table_timeline_control_select_obj_attr",
					options: ['All']
				}
			},
		],
		data: [['All']],
	});
	menu_display_timeline.add_slider({
		id: 'slider_timeline_display_max_char_num',
		label: "Charater to show",
		title: "Maximum number of charater to display",
		min: 8,
		max: 1024,
		value: max_displayed_char,
		step: 8,
		applyButton: true,
		event: function(value) {

		},
		eventApply: function(value) {

		}
	});
	menu_display_timeline.add_checkbox({
		id: 'checkbox_timeline_allow_edit',
		label: "Edit Object's time",
		title: "Allow to edit the time attached to the object",
		event: function(value) {
			console.log(value);
		}
	});
}
