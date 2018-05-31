var max_displayed_char_timeline = 64;
var eventTimeline;
var items_timeline;
var items_backup;
var mapping_text_to_id = new Map();
var user_manipulation = $('#event_timeline').data('user-manipulation');
var extended_text = $('#event_timeline').data('extended') == 1 ? "extended:1/" : "";
var container_timeline = document.getElementById('event_timeline');
var default_editable = {
	add: false,         // add new items by double tapping
	updateTime: true,   // drag items horizontally
	remove: true
};
var relationship_type_mapping = {
	'followed-by': 'after',
	'preceding-by': 'before',
}
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
var timeline_typeaheadDataSearch;
var timeline_typeaheadOption = {
	source: function (query, process) {
		if (timeline_typeaheadDataSearch === undefined) { // caching
			timeline_typeaheadDataSearch = Array.from(mapping_text_to_id.keys());
		}
		process(timeline_typeaheadDataSearch);
	},
	updater: function(value) {
		var id = mapping_text_to_id.get(value);
		eventTimeline.focus(id);
		$("#timeline-typeahead").blur();
	},
	autoSelect: true
}

function generate_timeline_tooltip(itemID, target) {
	var item = items_timeline.get(itemID);
	if (item.first_seen === undefined || item.first_seen === null) { // do not generate if first_seen not set
		return;
	}
	if (item.first_seen_overwritten !== undefined || item.last_seen_overwritten !== undefined) { // do not generate if start and end comes from object attribute
		return;
	}
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
	var bolt_html = obj.overwrite_enabled ? " <i class=\"fa fa-bolt\" style=\"color: yellow; font-size: large;\" title=\"Object is overwritten by its attributes\">" : "";
	table.append($('<tr class="timeline-objectName"><th>'+obj.content+bolt_html+'</th><th></th></tr>'));
	for (var attr of obj.Attribute) {
		var overwritten = attr.contentType == "first-seen" || attr.contentType == "last-seen" ? " <i class=\"fa fa-bolt\" style=\"color: yellow;\" title=\"Overwrite object "+attr.contentType+"\"></i>" : "";
		table.append(
			$('<tr>').append(
				$('<td class="timeline-objectAttrType">' + attr.contentType + '</td>'
				    +'<td class="timeline-objectAttrVal">' + attr.content+overwritten + '</td>'
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
		set_spanned_time(updated_item);
		items_timeline.remove(updated_item.id);
		items_timeline.add(updated_item);
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
	// determine whether the object's attribute should be updated instead of the first/last_seen value
	var item = items_timeline.get(item_id);
	var reflect = true;
	if (item[seenType+'_seen_overwritten'] !== undefined) {
		item_id = item[seenType+'_seen_overwritten']
		itemType = 'attributes'
		var compiled_url_form = "/" + itemType + "/fetchEditForm/" + item_id + "/" + "value";
		var compiled_field_form_id = "value_field";
		nanoTimestamp = nanoTimestampToDatetime(nanoTimestamp).toISOString();
		reflect = false;
	} else {
		var compiled_url_form = "/" + itemType + "/fetchEditForm/" + item_id + "/" + seenType + "_seen";
		var compiled_field_form_id = seenType+"_seen_field";
	}
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
			console.log(form);
			var field = form.find("#"+fieldIdItemType+"_"+attr_id+"_"+compiled_field_form_id);
			console.log(field);
			var the_time = nanoTimestamp;
			field.val(the_time);
			// submit the form
			$.ajax({
				data: form.serialize(),
				cache: false,
				success:function (data, textStatus) {
					if (reflect) {
						reflect_change(itemType, seenType, item_id);
					}
					form.remove()
				},
				error:function() {
					console.log('fail', 'Request failed for an unknown reason.');
				},
				complete: function () {
					$(".loadingTimeline").hide();
				},
				type:"post",
				url:"/" + itemType + "/" + "editField" + "/" + attr_id
			});
		},
		complete: function () {
			//$(".loadingTimeline").hide();
		},
		url: compiled_url_form,
	});

}

function nanoTimestampToDatetime(timestamp) {
	var factor = 0.000001; // 10^-6, fs and ls are expressed in 10^-9
	var d = new Date(timestamp*factor);
	if ($('#checkbox_timeline_display_gmt').prop('checked')) {
		return d;
	} else {
		return new Date(d.getTime() + (d.getTimezoneOffset() * 60 * 1000)); // adjust to GMT
	}
}
function timestampToDatetime(timestamp) {
	var factor = 1000;
	var d = new Date(timestamp*factor);
	if ($('#checkbox_timeline_display_gmt').prop('checked')) {
		return d;
	} else {
		return new Date(d.getTime() + (d.getTimezoneOffset() * 60 * 1000)); // adjust to GMT
	}
}
function datetimeTonanoTimestamp(d) {
	if (d === null || d === undefined) {
		return null;
	}
	var factor = 1000000;
	if (!$('#checkbox_timeline_display_gmt').prop('checked')) {
		d = new Date(d.getTime() + (d.getTimezoneOffset() * 60 * 1000)); // adjust to GMT
	}
	return d.getTime()*factor;
}
function datetimeToTimestamp(d) {
	if (d === null || d === undefined) {
		return null;
	}
	var factor = 0.001;
	if (!$('#checkbox_timeline_display_gmt').prop('checked')) {
		d = new Date(d.getTime() + (d.getTimezoneOffset() * 60 * 1000)); // adjust to GMT
	}
	return d.getTime()*factor;
}

function set_spanned_time(item) {
	var timestamp = item.timestamp;
    	var fs = item.first_seen;
    	var ls = item.last_seen;

	item.seen_enabled = false;
	item.overwrite_enabled = false;
    	if (fs===null && ls===null) {
		item.start = timestampToDatetime(timestamp);
		item.type = 'box';

    	} else if (fs===null && ls!==null) {
		item.start = timestampToDatetime(timestamp);
		// item.end = nanoTimestampToDatetime(ls);
		item.type = 'box';

    	} else if (ls===null && fs!==null) {
		item.start = nanoTimestampToDatetime(fs);
		item.seen_enabled = true;
		delete item.end;
		item.type = 'box';

    	} else { // fs and ls are defined
		item.start = nanoTimestampToDatetime(fs);
		item.end = nanoTimestampToDatetime(ls);
		item.seen_enabled = true;
		if (fs == ls) {
			item.type = 'box';
		} else {
			item.type = 'range';
		}
	}

	if (item.first_seen_overwritten !== undefined || item.last_seen_overwritten !== undefined) {
		var e = $.extend({}, default_editable);
		e.remove = false;
		item.editable = e;
		item.overwrite_enabled = true;
	}
}

function map_scope(val) {
	switch(val) {
		case 'First seen/Last seen':
			return 'seen';
		case 'Object relationship':
			return 'relationship';
		default:
			return 'seen';
	}
}

function timelinePopupCallback(state) {
	reload_timeline();
}

function adjust_text_length(elem) {
	var maxChar = $('#slider_timeline_display_max_char_num').val();
	elem.content = elem.content.substring(0, maxChar) + (elem.content.length < maxChar ? "" : "[...]");
}

function update_badge() {
	if ($('#checkbox_timeline_display_gmt').prop('checked')) {
		$("#timeline-display-badge").text("Timezone: " + ": " + new Date().toString().split(' ')[5]);
	} else {
		$("#timeline-display-badge").text("Timezone: " + ": GMT+0000");
	}
}

function reload_timeline() {
	update_badge();
	var payload = {scope: map_scope($('#select_timeline_scope').val())};
	$.ajax({
		url: "/events/"+"getEventTimeline"+"/"+scope_id+"/"+extended_text+"event.json",
		dataType: 'json',
		type: 'post',
		contentType: 'application/json',
		data: JSON.stringify( payload ),
		processData: false,
		beforeSend: function (XMLHttpRequest) {
			$(".loadingTimeline").show();
		},
		success: function( data, textStatus, jQxhr ){
			items_timeline.clear();
			for (var item of data.items) {
				item.className = item.group;
				set_spanned_time(item);
				if (item.group == 'object') {
					for (var attr of item.Attribute) {
						mapping_text_to_id.set(attr.contentType+': '+attr.content+' ('+item.id+')', item.id);
						adjust_text_length(attr);
					}
				} else {
					mapping_text_to_id.set(item.content+' ('+item.id+')', item.id);
					adjust_text_length(item);
				}
			}
			items_timeline.add(data.items);
		},
		error: function( jqXhr, textStatus, errorThrown ){
			console.log( errorThrown );
		},
		complete: function() {
			$(".loadingTimeline").hide();
		}
	});
}

function enable_timeline() {
	if (eventTimeline !== undefined) {
		return;
	}

	init_popover();
    
	$('#timeline-typeahead').typeahead(timeline_typeaheadOption);

	var payload = {scope: map_scope($('#select_timeline_scope').val())};
	$.ajax({
		url: "/events/"+"getEventTimeline"+"/"+scope_id+"/"+extended_text+"event.json",
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
				if (item.group == 'object') {
					for (var attr of item.Attribute) {
						mapping_text_to_id.set(attr.contentType+': '+attr.content+' ('+item.id+')', item.id);
						adjust_text_length(attr);
					}
				} else {
					mapping_text_to_id.set(item.content+' ('+item.id+')', item.id);
					adjust_text_length(item);
				}
			}
			items_timeline = new vis.DataSet(data.items);
			eventTimeline = new vis.Timeline(container_timeline, items_timeline, options);
			update_badge();
			
			eventTimeline.on('select', handle_selection);

			eventTimeline.on('doubleClick', handle_doubleClick);

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

function edit_item(id, callback) {
	var group = items_timeline.get(id).group;
	if (group == 'attribute') {
		simplePopup('/attributes/edit/'+id);
	} else if (group == 'object') {
		window.location = '/objects/edit/'+id;
	}
}

function handle_doubleClick(data) {
	edit_item(data.item);
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
			reload_timeline();
		},
		options: ["First seen/Last seen"],
		default: "First seen/Last seen"
	});

	var menu_display_timeline = new ContextualMenu({
		trigger_container: document.getElementById("timeline-display"),
		bootstrap_popover: true,
		style: "z-index: 1",
		container: document.getElementById("eventtimeline_div")
	});
	menu_display_timeline.add_slider({
		id: 'slider_timeline_display_max_char_num',
		label: "Charater to show",
		title: "Maximum number of charater to display in the label",
		min: 8,
		max: 2048,
		value: max_displayed_char_timeline,
		step: 8,
		applyButton: true,
		event: function(value) {
			$("#slider_timeline__display_max_char_num").parent().find("span").text(value);
		},
		eventApply: function(value) {
			reload_timeline();
		}
	});
	menu_display_timeline.add_checkbox({
		id: 'checkbox_timeline_display_hide_not_seen_enabled',
		label: "Hide first seen not set",
		title: "Hide items that does not have first seen sets",
		event: function(value) {
			handle_not_seen_enabled(value)
		}
	});
	menu_display_timeline.add_checkbox({
		id: 'checkbox_timeline_display_gmt',
		label: "Display with current timezone",
		title: "Set the dates relative to the browser timezone. Otherwise, keep dates in GMT",
		event: function(value) {
			reload_timeline()
		},
		checked: true
	});
}
