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
