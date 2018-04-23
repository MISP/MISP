var url = "getDistributionGraph";
var scope_id = $('#eventdistri_graph').data('event-id');
var extended_text = $('#eventdistri_graph').data('extended') == 1 ? true : false;
var payload = {};
var chartColors = window.chartColors;
var color = Chart.helpers.color;
var distribution_chart;
var reverse_distribution
function clickHandler(evt) {
	var firstPoint = distribution_chart.getElementAtEvent(evt)[0];
	var distribution_id;
	if (firstPoint) {
		distribution_id = distribution_chart.data.labels[firstPoint._index][1];
		document.getElementById('attributesFilterField').value = distribution_id;
		filterAttributes('distribution', '17');
	}
}
$.ajax({
	url: "/events/"+url+"/"+scope_id+"/event.json",
	dataType: 'json',
	type: 'post',
	contentType: 'application/json',
	data: JSON.stringify( payload ),
	processData: false,
	success: function( data, textStatus, jQxhr ){
		console.log(data);
		var ctx = document.getElementById("distribution_graph_canvas");
		ctx.onclick = function(evt) { clickHandler(evt); };
		distribution_chart = new Chart(ctx, {
			type: 'radar',
			data: {
				labels: data.distributionInfo.map(function(elem, index) { return [elem.key, index]; }),
				datasets: [
					//{
					//	label: "Event",
					//	data: data.event,
					//	backgroundColor: "rgba(255, 0, 0, 0.0)",
					//	borderColor: "rgba(255, 0, 0, 0.6)",
					//	pointBackgroundColor: "rgba(255, 0, 0, 0.8)",
					//},
					{
						label: "Attributes",
						data: data.attribute,
						backgroundColor: "rgba(255, 0, 0, 0.1)",
						borderColor: "rgba(255, 0, 0, 0.6)",
						pointBackgroundColor: "rgba(255, 0, 0, 1)",
					},
					{
						label: "Objects",
						data: data.object,
						backgroundColor: "rgba(0, 0, 255, 0.1)",
						borderColor: "rgba(0, 0, 255, 0.6)",
						pointBackgroundColor: "rgba(0, 0, 255, 1)",
					},
					{
						label: "Object attributes",
						data: data.obj_attr,
						backgroundColor: "rgba(0, 255, 0, 0.1)",
						borderColor: "rgba(0, 255, 0, 0.6)",
						pointBackgroundColor: "rgba(0, 255, 0, 1)",
					},
				
				],
			},
			options: {
				title: {
					display: true,
					text: 'Distribution'
				},
				scale: {
					ticks: {
						//beginAtZero: true,
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
