var margin = {top: 0, right: 0, bottom: 0, left: 0},
	width = 960 - margin.left - margin.right,
	height = 500 - margin.top - margin.bottom;

var color = d3.scale.category20c();

var treemap = d3.layout.treemap()
	.size([width, height])
	.sticky(true)
	.value(function(d) { return d.size; });

var div = d3.select("#treemapGraph").append("div")
	.style("position", "relative")
	.style("width", (width + margin.left + margin.right) + "px")
	.style("height", (height + margin.top + margin.bottom) + "px")
	.style("left", margin.left + "px")
	.style("top", margin.top + "px");

var node = div.datum(root).selectAll(".node")
	.data(treemap.nodes)
	.enter().append("div")
	.attr("class", "node")
	.attr("title", function(d) {return d.name + ': ' + d.size})
	.attr("id", function(d) { return d.name + '-node'})
	.call(position)
	.style("background", function(d) { return d.children ? color(d.name) : null; })
	.text(function(d) { return d.children ? null : d.name; });

taxonomies.forEach(function(taxonomy) {
	$("#" + taxonomy + "-colour").css("background-color", $("#" + taxonomy + "-node").css('background-color'));
});
	
d3.selectAll("input").on("change", function change() {
	var value = this.value === "count" ? function() { return 1; } : function(d) { return d.size; };
	node
		.data(treemap.value(value).nodes)
		.transition()
		.duration(1500)
		.call(position);
});

function position() {
  this.style("left", function(d) { return d.x + "px"; })
      .style("top", function(d) { return d.y + "px"; })
      .style("width", function(d) { return Math.max(0, d.dx - 1) + "px"; })
      .style("height", function(d) { return Math.max(0, d.dy - 1) + "px"; });
}

function updateTaxonomies() {
	var value = function(d) {
			tagTaxonomy = d.name.split(':')[0];
			if (taxonomies.indexOf(tagTaxonomy) == -1) {
				tagTaxonomy = 'custom';
			}
			if ($.inArray(tagTaxonomy, hiddenTaxonomies) > -1) {
				return 0;
			} else {
				return flatData[tagTaxonomy][d.name]['size'];
			}
		};
		node
			.data(treemap.value(value).nodes)
			.transition()
			.duration(1500)
			.call(position);
}

$('.treemap-selector').click(function() {
	var taxonomy = $( this ).data("treemap-selector");
	var index = hiddenTaxonomies.indexOf(taxonomy);
	if ($( this ).hasClass("bold")) {
		$( this ).removeClass("bold");
		if (index < 0) {
			hiddenTaxonomies.push(taxonomy);
		}
	} else {
		$( this ).addClass("bold");
		if (index > -1) {
			hiddenTaxonomies.splice(index, 1);
		}
	}
	updateTaxonomies();
});