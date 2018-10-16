<?php
    echo $this->Html->script('d3');
    echo $this->Html->css('sightingstyle');
?>
<div id="graphContent" class="graphContent"></div>
<script>
    var myData = "<?php echo $tsv; ?>";

    var colours = {
        'Sighting': 'blue',
        'False-positive': 'red'
    }

    var margin = {
            top: 20,
            right: 60,
            bottom: 30,
            left: 25
        },
        width = 980 - margin.left - margin.right,
        height = 300 - margin.top - margin.bottom;

    var parseDate = d3.time.format("%Y%m%d").parse;

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
        .interpolate("linear")
        .x(function(d) {
            return x(d.date);
        })
        .y(function(d) {
            return y(d.count);
        });

    var svg = d3.select("#graphContent").append("svg")
        .attr("width", width + margin.left + margin.right)
        .attr("height", height + margin.top + margin.bottom)
        .append("g")
        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

    var data = d3.tsv.parse(myData);

    color.domain(d3.keys(data[0]).filter(function(key) {
        return key !== "date";
    }));

    data.forEach(function(d) {
        d.date = parseDate(d.date);
    });

    var sightings = color.domain().map(function(name) {
        return {
            name: name,
            values: data.map(function(d) {
                return {
                    date: d.date,
                    count: +d[name]
                };
            })
        };
    });

    x.domain(d3.extent(data, function(d) {
        return d.date;
    }));

    y.domain([
        d3.min(sightings, function(c) {
            return d3.min(c.values, function(v) {
                return v.count;
            });
        }),
        d3.max(sightings, function(c) {
            return d3.max(c.values, function(v) {
                return v.count;
            });
        })
    ]);

    var legend = svg.selectAll('g')
        .data(sightings)
        .enter()
        .append('g')
        .attr('class', 'sightingsLegend');

    legend.append('rect')
        .attr('x', width - 20)
        .attr('y', function(d, i) {
            return i * 20;
        })
        .attr('width', 10)
        .attr('height', 10)
        .style('fill', function(d) {
            return colours[d.name];
        });

    legend.append('text')
        .attr('x', width - 8)
        .attr('y', function(d, i) {
            return (i * 20) + 9;
        })
        .text(function(d) {
            return d.name;
        });

    svg.append("g")
        .attr("class", "x axis")
        .attr("transform", "translate(0," + height + ")")
        .call(xAxis);

    svg.append("g")
        .attr("class", "y axis")
        .call(yAxis)
        .append("text")
        .attr("transform", "rotate(-90)")
        .attr("y", 6)
        .attr("dy", ".71em")
        .style("text-anchor", "end")
        .text("Count");

    var sightings = svg.selectAll(".sightings")
        .data(sightings)
        .enter().append("g")
        .attr("class", "sightings");

    sightings.append("path")
        .attr("class", "line")
        .attr("d", function(d) {
            return line(d.values);
        })
        .style("stroke", function(d) {
            return colours[d.name];
        });

</script>
