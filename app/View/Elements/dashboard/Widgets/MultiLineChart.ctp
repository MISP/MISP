<?php
    echo $this->Html->script('d3');
    echo $this->Html->css('multi-line-chart');
    $seed = rand();
    if (!empty($data['formula'])) {
        echo sprintf(
            '<div style="width:100%%;text-align:center;" class="blue bold">%s</div>',
            h($data['formula'])
        );
    }
?>
<svg id="svg-<?= $seed ?>" width="960" height="500"></svg>
<script>

var margin = {top: 20, right: 80, bottom: 30, left: 50},
    width = 960 - margin.left - margin.right,
    height = 500 - margin.top - margin.bottom;

var parseDate = d3.time.format("%Y-%m-%d").parse;

var x = d3.time.scale()
    .range([0, width]);

var y = d3.scale.linear()
    .range([height, 0]);

var color = d3.scale.category10();

var xAxis = d3.svg.axis()
    .scale(x)
    .orient("bottom");

var yAxis = d3.svg.axis()
    .scale(y)
    .orient("left");

var line = d3.svg.line()
    .interpolate("basis")
    .x(function(d) { return x(d.date); })
    .y(function(d) { return y(d.count); });

var svg = d3.select('#svg-<?= $seed ?>')
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
  .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

var data = <?= json_encode($data['data']) ?>;
var insight = "<?= h($data['insight']) ?>";

  color.domain(d3.keys(data[0]).filter(function(key) { return key !== "date"; }));

  data.forEach(function(d) {
    d.date = parseDate(d.date);
  });

  var data_nodes = color.domain().map(function(name) {
    return {
      name: name,
      values: data.map(function(d) {
        return {
            date: d.date, count: +d[name]
        };
      })
    };
  });
  x.domain(d3.extent(data, function(d) { return d.date; }));

  y.domain([
    d3.min(data_nodes, function(c) { return d3.min(c.values, function(v) { return v.count; }); }),
    d3.max(data_nodes, function(c) { return d3.max(c.values, function(v) { return v.count; }); })
  ]);

  svg.append("g")
      .attr("class", "x axis")
      .attr("transform", "translate(0," + height + ")")
      .call(xAxis);

  svg.append("g")
      .attr("class", "y axis")
      .call(yAxis)

  var data_node = svg.selectAll(".data-node-<?= $seed ?>")
      .data(data_nodes)
    .enter().append("g")
      .attr("class", "data-node-<?= $seed ?>");

  data_node.append("path")
      .attr("class", "line")
      .attr("d", function(d) { return line(d.values); })
      .style("stroke", function(d) { return color(d.name); });

  data_node.append("text")
      .datum(function(d) { return {name: d.name, value: d.values[d.values.length - 1]}; })
      .attr("transform", function(d) { return "translate(" + x(d.value.date) + "," + y(d.value.count) + ")"; })
      .attr("x", 3)
      .attr("dy", ".35em")
      .text(function(d) { return d.name; });

</script>
