var eventTimeline;
var items_timeline;
var items_backup;
var user_manipulation = $('#event_timeline').data('user-manipulation');
var container_timeline = document.getElementById('event_timeline');
var default_editable = {
	add: false,         // add new items by double tapping
	updateTime: true,   // drag items horizontally
	remove: true
};
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
	minHeight: 400,
	multiselect: true,
	editable: user_manipulation ? default_editable : false,
	tooltipOnItemUpdateTime: true,
	onRemove: function(item, callback) { // clear timestamps
		update_seen(item.group+'s', 'first', item.id, null, callback);
		update_seen(item.group+'s', 'last', item.id, null, callback);
		eventTimeline.setSelection([]);
		$('.timelineSelectionTooltip').remove()
		return false;
    	},
	onMove: function(item, callback) {
		var newStart = datetimeTonanoTimestamp(item.start);
		var newEnd = datetimeTonanoTimestamp(item.end);
		if (item.first_seen != newStart) {
			update_seen(item.group+'s', 'first', item.id, newStart, callback);
		}
		if (item.last_seen != newEnd && item.seen_enabled) {
			update_seen(item.group+'s', 'last', item.id, newEnd, callback);
		}
	}
};

function generate_timeline_tooltip(itemID, target) {
	var item = items_timeline.get(itemID);
	var closest = $(target.closest(".vis-selected.vis-editable"));
	var btn_type = item.last_seen !== null ? 'collapse-btn' : 'expand-btn';
	var fct_type = item.last_seen !== null ? 'collapseItem' : 'expandItem';
	var btn = $('<div class="timelineSelectionTooltip vis-expand-action '+btn_type+'" data-itemid="'+item.id+'"></div>')
	if (item.last_seen !== null) {
		btn.click(collapseItem);
	} else {
		btn.click(expandItem);
	}
	closest.append(btn);
}

/* UTIL */
function collapseItem() {
	var itemID = $(this).data('itemid');
	var item = items_timeline.get(itemID);
	update_seen(item.group+'s', 'last', item.id, null, undefined);
}
function expandItem() {
	var itemID = $(this).data('itemid');
	var item = items_timeline.get(itemID);
	var next_step = get_next_step_nano(item.first_seen);
	var fs = parseInt(item.first_seen);
	var newEnd = fs+next_step;
	update_seen(item.group+'s', 'last', item.id, newEnd, undefined);
}

function get_next_step_nano() {
	var factor = 1000000; // to multiplie on milli to get nano;
	var hourmilli = 1000*3600;
	var scale = eventTimeline.timeAxis.step.scale;
	var step;
	switch(scale) {
		case 'millisecond':
			step = factor*1;
			break;
		case 'second':
			step = factor*1000;
			break;
		case 'minute':
			step = factor*1000*60;
			break;
		case 'hour':
			step = factor*hourmilli;
			break;
		case 'weekday':
			step = factor*hourmilli*24;
			break;
		case 'day':
			step = factor*hourmilli*24;
			break;
		case 'week':
			step = factor*hourmilli*24*7;
			break;
		case 'month':
			step = factor*hourmilli*24*7*30;
			break;
		case 'year':
			step = factor*hourmilli*24*7*30*365;
			break;
		default:
			step = factor*hourmilli*24;
			break;
	}
	return step;
}

function build_attr_template(attr) {
	var span = $('<span data-itemID="'+attr.id+'">');
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

function reflect_change(itemType, seenType, item_id) {
	quick_fetch_seen(itemType, seenType, item_id, function(data) {
		updated_item = items_timeline.get(item_id);
		if (seenType == 'first') {
			updated_item.first_seen = data;
		} else if (seenType == 'last') {
			updated_item.last_seen = data;
		}
		var redraw = set_spanned_time(updated_item);
		items_timeline.update(updated_item);
	});
}

function quick_fetch_seen(itemType, seenType, item_id, callback) {
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loadingTimeline").show();
		},
		dataType:"html",
		cache: false,
		success:function (data, textStatus) {
			seenTime = data.replace('&nbsp;', '');
			seenTime = seenTime == '' ? null : parseInt(seenTime);
			callback(seenTime);
		},
		complete: function () {
			$(".loadingTimeline").hide();
		},
		url:"/" + itemType + "/fetchViewValue/" + item_id + "/" + seenType + "_seen",
	});
}

function update_seen(itemType, seenType, item_id, nanoTimestamp, callback) {
	var fieldIdItemType = itemType.charAt(0).toUpperCase() + itemType.slice(1, -1); //  strip 's' and uppercase first char
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loadingTimeline").show();
		},
		dataType:"html",
		cache: false,
		success: function (data, textStatus) {
			var form = $(data);
			$(container_timeline).append(form);
			form.css({display: 'none'});
			var attr_id = item_id;
			var field = form.find("#"+fieldIdItemType+"_"+attr_id+"_"+seenType+"_seen_field");
			var the_time = nanoTimestamp;
			field.val(the_time);
			// submit the form
			$.ajax({
				data: form.serialize(),
				cache: false,
				success:function (data, textStatus) {
					reflect_change(itemType, seenType, item_id);
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
			$(".loadingTimeline").hide();
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

	item.seen_enabled = false;
    	if (fs===null && ls===null) {
		item.start = timestampToDatetime(timestamp);

    	} else if (fs===null && ls!==null) {
		item.start = timestampToDatetime(timestamp);
		item.end = nanoTimestampToDatetime(ls);

    	} else if (ls===null && fs!==null) {
		item.start = nanoTimestampToDatetime(fs);
		item.seen_enabled = true;
		item.end = null;

    	} else { // fs and ls are defined
		item.start = nanoTimestampToDatetime(fs);
		item.end = nanoTimestampToDatetime(ls);
		item.seen_enabled = true;
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
			for (var item of data.items) {
				item.className = item.group;
				set_spanned_time(item);
			}
			items_timeline = new vis.DataSet(data.items);
			eventTimeline = new vis.Timeline(container_timeline, items_timeline, options);
			
			eventTimeline.on('select', handle_selection);
			items_timeline.on('update', function(eventname, data) {
				handle_selection({
					event: { target: $('span[data-itemID="'+data.items[0]+'"]')},
					items: data.items
				});
			});
		},
		error: function( jqXhr, textStatus, errorThrown ){
			console.log( errorThrown );
		},
		complete: function() {
			$(".loadingTimeline").hide();
		}
	});
}

function handle_selection(data) {
	var event = data.event;
	var target = event.target;
	var items = data.items;

	if (items.length == 0) {
			$('.timelineSelectionTooltip').remove()
	} else {
		for (var itemID of items) {
			generate_timeline_tooltip(itemID, target);
		}
	}
}

function handle_not_seen_enabled(hide) {
	if (hide) {
		var hidden = items_timeline.get({
			filter: function(item) {
				return !item.seen_enabled;
			}
		});
		var hidden_ids = [];
		items_timeline.forEach(function(item) {
			hidden_ids.push(item.id);
		});
		items_timeline.remove(hidden)
		items_backup = hidden;
	} else {
		items_timeline.add(items_backup);
	}
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
	menu_display_timeline.add_checkbox({
		id: 'checkbox_timeline_display_hide_not_seen_enabled',
		label: "Hide first seen not set",
		title: "Hide items that does not have first seen sets",
		event: function(value) {
			handle_not_seen_enabled(value)
		}
	});
}
