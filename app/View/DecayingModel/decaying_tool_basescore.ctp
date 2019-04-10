<div class="row">
    <div class="span8">
        <table>
            <thead>
                <tr>
                    <th><?php echo __('Taxonomies') ?></th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($taxonomies as $taxonomy): ?>
                    <tr>
                        <td>
                            <?php echo h($taxonomy['name']) ?>
                        </td>
                        <td>
                            <input type="range" min=0 max=100 step=1 value=<?php echo h($taxonomy['value']) ?>></input>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <div class="span8">
        <div id="treemapGraph"></div>
    </div>
</div>

<script>
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
</script>
