var url = "getDistributionGraph";
var scope_id = $('#eventdistri_graph').data('event-id');
var extended_text = $('#eventdistri_graph').data('extended') == 1 ? true : false;
var payload = {};
var chartColors = window.chartColors;
var color = Chart.helpers.color;
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
		var myChart = new Chart(ctx, {
			type: 'radar',
			data: {
				labels: data.distributionInfo.map(function(elem, index) { return elem.key; }),
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
				}
			}
		});
	},
	error: function( jqXhr, textStatus, errorThrown ){
		console.log( errorThrown );
	}
});
