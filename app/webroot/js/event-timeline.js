var eventTimeline;
var container_timeline = document.getElementById('event_timeline');
var options = {
	template: function (item, element, data) {
		switch(item.group) {
			case "attribute":
				return build_attr_template(item);

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
		add: false,         // add new items by double tapping
		updateTime: true,  // drag items horizontally
		remove: true
	},
	onRemove: function(item, callback) { // clear timestamps
		update_seen_attr(item.group+'s', 'first', item.id, null, callback);
		update_seen_attr(item.group+'s', 'last', item.id, null, callback);
		return false;
    	},
	onMove: function(item, callback) {
		var newStart = datetimeTonanoTimestamp(item.start);
		var newEnd = datetimeTonanoTimestamp(item.end);
		if (item.first_seen != newStart) {
			update_seen_attr(item.group+'s', 'first', item.id, newStart, callback);
		}
		if (item.last_seen != newEnd) {
			update_seen_attr(item.group+'s', 'last', item.id, newEnd, callback);
		}
	}
};

/* UTIL */
function build_attr_template(attr) {
	var span = $('<span>');
	if (!attr.seen_enabled) {
		span.addClass('timestamp-attr');
	}
	span.text(attr.content);
	span.data('seen_enabled', attr.seen_enabled);
	var html = span[0].outerHTML;
	return html;
}

function build_object_template(obj) {
	var table = $('<table>');
	table.data('seen_enabled', obj.seen_enabled);
	if (!obj.seen_enabled) {
		table.addClass('timestamp-obj');
	}
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

function update_seen_attr(itemType, seenType, item_id, nanoTimestamp, callback) {
	var fieldIdItemType = itemType.charAt(0).toUpperCase() + itemType.slice(1, -1); //  strip 's' and uppercase first char
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		},
		dataType:"html",
		cache: false,
		success: function (data, textStatus) {
			var form = $(data);
			$(container_timeline).append(form);
			//form.css({display: 'none'});
			var attr_id = item_id;
			var field = form.find("#"+fieldIdItemType+"_"+attr_id+"_"+seenType+"_seen_field");
			var the_time = nanoTimestamp;
			field.val(the_time);
			// submit the form
			$.ajax({
				data: form.serialize(),
				cache: false,
				success:function (data, textStatus) {
					console.log(data);
					form.remove()
				},
				error:function() {
					console.log('fail', 'Request failed for an unknown reason.');
				},
				type:"post",
				url:"/" + itemType + "/" + "editField" + "/" + attr_id
			});
		},
		complete: function () {
			$(".loading").hide();
		},
		url:"/" + itemType + "/fetchEditForm/" + item_id + "/" + seenType + "_seen",
	});

}

function nanoTimestampToDatetime(timestamp) {
	var factor = 0.000001; // 10^-6, fs and ls are expressed in 10^-9
	return new Date(timestamp*factor);
}
function timestampToDatetime(timestamp) {
	var factor = 1000;
	return new Date(timestamp*factor);
}
function datetimeTonanoTimestamp(d) {
	if (d === null || d === undefined) {
		return null;
	}
	var factor = 1000000;
	return d.getTime()*factor;
}
function datetimeToTimestamp(d) {
	if (d === null || d === undefined) {
		return null;
	}
	var factor = 0.001;
	return d.getTime()*factor;
}

function set_spanned_time(item) {
	var timestamp = item.timestamp;
    	var fs = item.first_seen;
    	var ls = item.last_seen;

	item.seen_enabled = true;
    	if (fs==null && ls==null) {
		item.start = timestampToDatetime(timestamp);
		item.seen_enabled = false;

    	} else if (fs==null && ls!=null) {
		item.start = timestampToDatetime(timestamp);
		item.end = nanoTimestampToDatetime(ls);
		item.seen_enabled = false;

    	} else if (ls==null && fs!=null) {
		item.start = nanoTimestampToDatetime(fs);
		item.end = new Date(); // now

    	} else { // fs and ls are defined
		item.start = nanoTimestampToDatetime(fs);
		item.end = nanoTimestampToDatetime(ls);
	}
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
				item.className = item.group;
				set_spanned_time(item);
			}
			var items_timeline = new vis.DataSet(data.items);
			eventTimeline = new vis.Timeline(container_timeline, items_timeline, options);
		},
		error: function( jqXhr, textStatus, errorThrown ){
			console.log( errorThrown );
		},
		complete: function() {
			$(".loadingTimeline").hide();
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
		options: ["First seen/Last seen", "MISP Timestamp"],
		default: "First seen/Last seen"
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
	menu_display_timeline.add_checkbox({
		id: 'checkbox_timeline_display_hide_not_seen_enabled',
		label: "Hide first seen not set",
		title: "Hide items that does not have first seen sets",
		event: function(value) {
			console.log(value);
		}
	});
}
