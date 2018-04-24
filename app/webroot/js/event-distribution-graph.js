var scope_id = $('#eventdistri_graph').data('event-id');
var event_distribution = $('#eventdistri_graph').data('event-distribution');
var extended_text = $('#eventdistri_graph').data('extended') == 1 ? true : false;
var payload = {};
var distribution_chart;

var pb_colors_mapping = {
	0: "#00FF00", //Lime
	1: "#FFFF00", //yellow
	2: "#FFCC00", //gold
	3: "#FF6600", //red-orange
	4: "#FF0000", //red
};


function clickHandlerGraph(evt) {
	var firstPoint = distribution_chart.getElementAtEvent(evt)[0];
	var distribution_id;
	if (firstPoint) {
		var value = distribution_chart.data.datasets[firstPoint._datasetIndex].data[firstPoint._index];
		if (value == 0) {
			document.getElementById('attributesFilterField').value = "";
			filterAttributes('all', scope_id);
		} else {
			distribution_id = distribution_chart.data.labels[firstPoint._index][1];
			var value_to_set = String(distribution_id);
			value_to_set += distribution_id == event_distribution ? '|' + '5' : '';
			document.getElementById('attributesFilterField').value = value_to_set;
			filterAttributes('distribution', scope_id);
		}
	}
}

function clickHandlerPb(evt) {
	var distribution_id = evt.target.dataset.distribution;
	var value_to_set = String(distribution_id);
	value_to_set += distribution_id == event_distribution ? '|' + '5' : '';
	document.getElementById('attributesFilterField').value = value_to_set;
	filterAttributes('distribution', scope_id);
}


function get_maximum_distribution(array) {
	var org = array[0];
	var community = array[1];
	var connected = array[2];
	var all = array[3];
	var sharing = array[4];
	if (all != 0) {
		return 4;
	} else if (connected != 0) {
		return 3;
	} else if (sharing != 0) {
		return 2;
	} else if (community != 0) {
		return 1;
	} else {
		return 0;
	}
}


function add_level_to_pb(distribution, maxLevel) {
	var pb_container = document.getElementById('eventdistri_pb_container');
	var pb = document.getElementById('eventdistri_pb_background');
	var spanOffset = 15; // due to padding
	var pbStep = pb.clientWidth / 5.0;
	// we get 2:connected_comm, 3:all_comm, 4:sharing_group
	// we want 2:sharing_group, 3:connected_comm, 4:all_comm

	distribution = jQuery.extend({}, distribution); // deep clone distribution object
	distribution[0].num = 0;
	distribution[1].num = 1;
	var temp = distribution[2];
	distribution[2] = distribution[4];
	distribution[2].num = 4;
	distribution[4] = distribution[3];
	distribution[4].num = 3;
	distribution[3] = temp;
	distribution[3].num = 2;

	for (var d in distribution) {
		d = parseInt(d);
		// text
		var span = document.createElement('span');
		span.style.position = 'absolute';
		span.style.lineHeight = '12px';
		span.classList.add('useCursorPointer');
		span.onclick = clickHandlerPb;
		span.style.bottom = d % 2 == 0 ? '59px' : '7px';
		span.innerHTML = distribution[d].key;
		span.setAttribute('data-distribution', distribution[d].num);
		if (maxLevel == d+1) {
			span.style.fontSize = 'larger';
		} else {
			span.style.opacity = '0.5';
		}
		pb_container.appendChild(span);
		span.style.left = (pbStep*(d+1))+spanOffset-span.clientWidth/2 + 'px';
		// tick
		var span = document.createElement('span');
		span.style.position = 'absolute';
		spanOffset += (pbStep*(d+1))+spanOffset > pb_container.clientWidth ? -3 : 0; // avoid the tick width to go further than the pb
		span.style.left = (pbStep*(d+1))+spanOffset + 'px';
		span.style.bottom = d % 2 == 0 ? '32px' : '25px';
		span.style.width = '3px';
		span.style.height = '23px';
		span.style.zIndex = '-1';
		span.style.background = 'black';
		span.style.borderRadius = '4px';
		if (maxLevel == d+1) {
			span.style.opacity = '0.6';
		} else {
			span.style.opacity = '0.2';
		}
		pb_container.appendChild(span);
	}
	
}
$(document).ready(function() {
	$('.distribution_graph').popover({
		"title": "Atomic event distribution graph",
		"html": true,
		"content": function() { return $('#distribution_graph_container').html(); },
		"template" : '<div class="popover" role="tooltip" style="z-index: 1;"><div class="arrow"></div><h3 class="popover-title"></h3><div class="popover-content" style="padding-left: 15px; padding-right: 30px;"></div></div>'
	});

	$('.distribution_graph').click(function() {
		$.ajax({
			url: "/events/"+"getDistributionGraph"+"/"+scope_id+"/event.json",
			dataType: 'json',
			type: 'post',
			contentType: 'application/json',
			data: JSON.stringify( payload ),
			processData: false,
			success: function( data, textStatus, jQxhr ){
				$('#eventdistri_pb_invalid').tooltip();
				$('#eventdistri_pb').tooltip();

				// pb
				var max_distri = get_maximum_distribution(data.event)+1;
				var event_dist = event_distribution+1;
				add_level_to_pb(data.distributionInfo, event_dist);
				$('#eventdistri_pb').width(event_dist*20+'%');
				$('#eventdistri_pb').attr('aria-valuenow', event_dist*20);
				$('#eventdistri_pb').css("transition", "width 0.5s");
				//$('#eventdistri_pb').css("background", pb_colors_mapping[max_distri-1]);
				$('#eventdistri_pb').css("background", "#28a745");

				$('#eventdistri_pb_invalid').width((max_distri-event_dist)*20+'%');
				$('#eventdistri_pb_invalid').attr('aria-valuenow', (max_distri-event_dist)*20);
				$('#eventdistri_pb_invalid').css("transition", "width 0.5s");
				$('#eventdistri_pb_invalid').css("background", "#dc3545");
				// radar
				var ctx = document.getElementById("distribution_graph_canvas");
				ctx.onclick = function(evt) { clickHandlerGraph(evt); };
				distribution_chart = new Chart(ctx, {
					type: 'radar',
					data: {
						labels: data.distributionInfo.map(function(elem, index) { return [elem.key, index]; }),
						datasets: [
							{
								label: "Attributes",
								data: data.attribute,
								backgroundColor: "rgba(255, 0, 0, 0.1)",
								borderColor: "rgba(255, 0, 0, 0.6)",
								pointBackgroundColor: "rgba(255, 0, 0, 1)",
							},
							{
								label: "Object attributes",
								data: data.obj_attr,
								backgroundColor: "rgba(0, 0, 255, 0.1)",
								borderColor: "rgba(0, 0, 255, 0.6)",
								pointBackgroundColor: "rgba(0, 0, 255, 1)",
							},
						
						],
					},
					options: {
						title: {
							display: false,
							text: 'Distribution'
						},
						scale: {
							ticks: {
								beginAtZero: true,
								maxTicksLimit: 4
							}
						},
						label: {
							onclick: function() {console.log('wddw');}
						}
					}
				});
			},
			error: function( jqXhr, textStatus, errorThrown ){
				console.log( errorThrown );
			}
		});
	});
});
