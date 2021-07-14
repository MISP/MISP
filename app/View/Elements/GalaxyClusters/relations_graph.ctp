<div style="margin-bottom: 10px; position: relative">
    <label>
        <input type="checkbox" id="checkbox-include-inbound" <?= !empty($includeInbound) ? "checked=\"checked\"" : "" ?>></input>
        <?= __('Include inbound relations from other galaxies') ?>
    </label>
    <div id="graphContainer" style="height: 70vh; border: 1px solid #ddd; "></div>
    <div id="tooltipContainer" style="max-height: 450px; min-width: 200px; max-width:300px; position: absolute; top: 10px; right: 10px; border: 1px solid #999; border-radius: 3px; background-color: #f5f5f5ee; overflow: auto;"></div>
</div>

<?php
echo $this->element('genericElements/assetLoader', array(
    'js' => array('d3')
));
?>

<script>
(function(){
var distributionLevels = <?= json_encode($distributionLevels) ?>;
var hexagonPoints = '30,15 22.5,28 7.5,28 0,15 7.5,2.0 22.5,2'
var hexagonPointsSmaller = '21,10.5 15.75,19.6 5.25,19.6 0,10.5 5.25,1.4 15.75,1.4'
var hexagonTranslate = -10.5;
var graph = <?= json_encode($relations) ?>;
var store;
var nodes, links, edgepaths, edgelabels, edgetags;
var width, height, margin;
var vis, svg, plotting_area, force, container, zoom;
var legendLabels, labels;
var graphElementScale = 1;
var graphElementTranslate = [0, 0];
var nodeHeight = 20;
var nodeWidth = 120;
var colors = d3.scale.category10();

$(document).ready( function() {
    margin = {top: 5, right: 5, bottom: 5, left: 5},
    width = $('#graphContainer').width() - margin.left - margin.right,
    height = $('#graphContainer').height() - margin.top - margin.bottom;
    $('#tooltipContainer').hide();
    if (graph.nodes.length > 0) {
        initGraph();
    } else {
        $('#graphContainer')
            .css({
                'text-align': 'center',
                'height': 'unset'
            })
            .append(
                $('<p></p>')
                    .text("<?= __('This galaxy does not have any relationships.') ?>")
            );
    }
    $('#checkbox-include-inbound').click(function() {
        var $container = $(this).parent().parent().parent();
        var checked = $(this).prop('checked');
        reloadGraph(checked);
    })
});

function reloadGraph(checked) {
    var uri = '<?= $baseurl ?>/galaxies/relationsGraph/<?= h($galaxy['Galaxy']['id']) ?>/' + (checked ? '1' : '0')
    $.get(uri, function(data) {
        $("#clusters_content").html(data);
    })
}

function initGraph() {
    var groupDomain = {};
    graph.links.forEach(function(link) {
        var tmpNode = graph.nodes.filter(function(node) {
            return node.uuid == link.source;
        })
        link.source = tmpNode[0]
        tmpNode = graph.nodes.filter(function(node) {
            return node.uuid == link.target;
        })
        link.target = tmpNode[0];
        groupDomain[link.source.group] = 1;
        groupDomain[link.target.group] = 1;
        link.id = link.source.uuid + ':' + link.target.uuid + ':' + link.type;
    })
    store = $.extend(true, {}, graph);
    groupDomain = Object.keys(groupDomain);
    colors.domain(groupDomain);
    force = d3.layout.force()
        .size([width, height])
        .charge(-3000)
        .friction(0.3)
        .theta(0.3)
        // .theta(0.9)
        .linkDistance(130)
        // .linkStrength(0.7)
        .on("tick", tick)

    vis = d3.select("#graphContainer");

    svg = vis.append("svg")
        .attr("id", "relationGraphSVG")
        .attr("width", width)
        .attr("height", height)
    container = svg.append("g").attr("class", "zoomContainer");
    svg.on('click', clickHandlerSvg);
    zoom = d3.behavior.zoom()
        .on("zoom", zoomHandler);
    svg.call(zoom);

    defs = svg.append("defs")
    defs.append("marker")
        .attr({
            "id":"arrowEnd",
            "viewBox":"0 -5 10 10",
            "refX": 10+5,
            "refY": 0,
            "markerWidth": 8,
            "markerHeight": 8,
            "markerUnits": "userSpaceOnUse",
            "orient":"auto"
        })
        .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .attr("class","arrowHead");
    
    defs.append("marker")
        .attr({
            "id":"arrowEndForHexa",
            "viewBox":"0 -5 10 10",
            "refX": 10+15,
            "refY": 0,
            "markerWidth": 8,
            "markerHeight": 8,
            "markerUnits": "userSpaceOnUse",
            "orient":"auto"
        })
        .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .attr("class","arrowHead");

    container.append("g")
        .attr("class", "links")
    container.append("g")
        .attr("class", "edgepaths")
    container.append("g")
        .attr("class", "edgelabels")
    container.append("g")
        .attr("class", "edgetags")
    container.append("g")
        .attr("class", "nodes")

    svg.append('g')
        .classed('legendContainer', true)
        .append('g')
        .classed('legend', true);
    legendLabels = groupDomain.map(function(domain) {
        return {
            text: domain,
            color: colors(domain),
            disabled: false
        }
    })
    drawLabels();
    update();
}

function zoomHandler() {
    container.attr("transform",
        "translate(" + d3.event.translate + ")"
        + " scale(" + d3.event.scale + ")");
    graphElementScale = d3.event.scale;
    graphElementTranslate = d3.event.translate;
}

function update() {
    force
        .nodes(graph.nodes)
        .links(graph.links)

    links = container.select('.links')
        .selectAll("line")
        .data(graph.links, function(d) { return d.id;});
    links.exit().remove();

    var linkEnter = links.enter()
        .append("line")
        .attr("id",function(d,i) { return "linkId_" + d.id; })
        .attr("class", "link useCursorPointer")
        .on('click', clickHandlerLink)
        .attr("marker-end", function(d) { return d.target.isRoot ? "url(#arrowEndForHexa)" : "url(#arrowEnd)"; })
        .attr("stroke", "#999")
        .attr("stroke-width", function(d) {
            var linkWidth = 1;
            var linkMaxWidth = 5;
            if (d.tag !== undefined) {
                var avg = getAverageNumericalValue(d.tag);
                d.numerical_avg = avg;
                linkWidth = avg / 100 * linkMaxWidth;
            }
            linkWidth = Math.max(linkWidth, 1);
            return linkWidth + 'px';
        })
        .attr("stroke-opacity", function(d) {
            var opacity = 0.6;
            if (d.tag !== undefined) {
                var avg = d.numerical_avg;
                opacity = Math.min(0.8, Math.max(0.2, d.numerical_avg / 100));
            }
            return opacity;
        })

        edgepaths = container.select(".edgepaths")
            .selectAll(".edgepath") //make path go along with the link provide position for link labels
            .data(graph.links, function(d) { return d.id;});
        edgepaths.exit().remove();
        edgepaths.enter()
            .append('path')
            .attr('class', 'edgepath')
            .attr('fill-opacity', 0)
            .attr('stroke-opacity', 0)
            .attr('id', function (d) { return "edgepathId_" + d.id; })
            .style("pointer-events", "none");

        edgelabels = container.select(".edgelabels")
            .selectAll(".edgelabel")
            .data(graph.links, function(d) { return d.id;});
        
        edgelabels.exit().remove();
        edgelabels.enter()
            .append('text')
            .attr('class', 'edgelabel')
            .attr('dy', '-3')
            .attr('id', function (d) {return 'edgelabelId_' + d.id})
            .attr('font-size', 10)
            .attr('fill', '#aaa')
            .append('textPath') //To render text along the shape of a <path>, enclose the text in a <textPath> element that has an href attribute with a reference to the <path> element.
            .attr('xlink:href', function (d) {return '#edgepathId_' + d.id})
            .style("text-anchor", "middle")
            .attr("startOffset", "50%")
            .attr('class', 'useCursorPointer')
            .on('click', clickHandlerLink)
            .text(function(d) { return d.type});

        edgetags = container.select(".edgetags")
            .selectAll(".edgetagContainer")
            .data(graph.links, function(d) { return d.id;});
        edgetags.exit().remove();
        edgetags.enter()
            .append('g')
            .attr('id', function (d) {return 'edgetagId_' + d.id})
            .attr('class', 'edgetagContainer useCursorPointer')
            .on('click', clickHandlerLink)
            .each(function(d) {
                var tagContainer = d3.select(this);
                var width = 7;
                var margin = 1;
                var offset = width/2 + margin;
                if (d.tag !== undefined) {
                    var centeredOffset = [];
                    if (d.tag.length == 0) {
                        centeredOffset.push(0);
                    } else {
                        for (var i = -offset*(d.tag.length-1); i <= offset*(d.tag.length-1); i += 2*offset) {
                            centeredOffset.push(i);
                        }
                    }
                    d.tag.forEach(function(tag, i) {
                        tagContainer
                            .append("rect")
                            .attr("x", centeredOffset[i])
                            .attr("y", "3")
                            .attr("width", width)
                            .attr("height", "12")
                            .attr("rx", "2")
                            .attr('title', tag.name)
                            .attr("fill", tag.colour)
                            .attr("color", getTextColour(tag.colour));
                    });
                }
            });

    nodes = container.select(".nodes")
        .selectAll(".node")
        .data(graph.nodes, function(d) { return d.uuid;});
    nodes.exit().remove();
    var nodesEnter = nodes.enter()
        .append('g')
        .classed('useCursorPointer node', true)
        .call(drag(force))
        .on('click', clickHandlerNode);

    nodesEnter.filter(function(node) { return !node.isRoot }).append("circle")
        .attr("r", 5)
        .style("fill", function(d) { return colors(d.group); })
        .style("stroke", "black")
        .style("stroke-width", "1px");
    nodesEnter.filter(function(node) { return node.isRoot }).append('polygon')
        .attr('points', hexagonPointsSmaller)
        .attr("transform", 'translate(' + hexagonTranslate + ', ' + hexagonTranslate + ')')
        .style("fill", function(d) { return colors(d.group); })
        .style("stroke", "black")
        .style("stroke-width", "2px");
    nodesEnter.append("text")
        .attr("dy", "25px")
        .attr("dx", "")
        .attr("x", "")
        .attr("y", "")
        .attr("text-anchor", "middle")
        .style("fill-opacity", 1)
        .text(function(d) { return d.value });

    force.start();
}

function tick() {
    links.attr("x1", function(d) { return d.source.x; })
        .attr("y1", function(d) { return d.source.y; })
        .attr("x2", function(d) { return d.target.x; })
        .attr("y2", function(d) { return d.target.y; });

    nodes.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
    edgepaths.attr('d', function(d) { return 'M ' + d.source.x + ' ' + d.source.y + ' L ' + d.target.x + ' ' + d.target.y});

    edgetags.attr("transform", function(d) {
        var bbox = this.getBBox();
        var rx = bbox.width/2;
        var ry = bbox.y+bbox.height/2;
        var angle = Math.atan((d.source.y - d.target.y) / (d.source.x - d.target.x)) * 180 / Math.PI;
        var angle2 = 0;
        if (d.target.x > d.source.x && d.target.y < d.source.y) { // quad 1
            angle2 = Math.abs(Math.atan((d.source.y - d.target.y) / (d.source.x - d.target.x)) * 180 / Math.PI);
        } else if (d.target.x < d.source.x && d.target.y < d.source.y) { // quad 2
            angle2 = 90 + Math.atan((d.source.x - d.target.x) / (d.source.y - d.target.y)) * 180 / Math.PI;
        } else if (d.target.x < d.source.x && d.target.y > d.source.y) { // quad 3
            angle2 = 180 - Math.atan((d.source.y - d.target.y) / (d.source.x - d.target.x)) * 180 / Math.PI;
        } else { // quad 4
            angle2 = 360 - Math.atan((d.source.y - d.target.y) / (d.source.x - d.target.x)) * 180 / Math.PI;
        }
        var angle2Rad = angle2/180 * Math.PI;
        var sinX = Math.sin(angle2Rad);
        var cosY = Math.cos(angle2Rad);
        var dx = sinX * (bbox.height/2);
        var dy = cosY * bbox.height/2;
        if (sinX > 0.5 || sinX < -0.5) { // increase distance. #magic
            dx *= 1.4;
        }
        if (cosY < 0) {
            dy *= 1.7;
        }
        var newX = (d.source.x + d.target.x) / 2 - bbox.width/2 + dx;
        var newY = (d.source.y + d.target.y) / 2 - bbox.height/2 + dy;
        return 'translate(' + [newX, newY] + ') rotate(' + angle + ' ' + rx + ' ' + ry + ')';
    });

    edgelabels.attr("transform", function(d) {
        if (d.target.x < d.source.x){
            var bbox = this.getBBox();
            var rx = bbox.x+bbox.width/2;
            var ry = bbox.y+bbox.height/2;
            return 'rotate(180 '+rx+' '+ry+')';
        } else {
            return 'rotate(0)';
        }
    });
}

function drag(force) {
    function dragstart(d, i) {
        force.stop();
        d3.event.sourceEvent.stopPropagation();
        // if (!d3.event.active) {
        //     force.resume()
        // }

    }

    function dragmove(d, i) {
        d.px += d3.event.dx;
        d.py += d3.event.dy;
        d.x += d3.event.dx;
        d.y += d3.event.dy;
        tick();
    }

    function dragend(d, i) {
        d.fixed = true;
        // tick();
        force.resume();
    }
    
    return d3.behavior.drag()
        // .filter(dragfilter)
        .on("dragstart", dragstart)
        .on("drag", dragmove)
        .on("dragend", dragend)
}

function unselectAll() {
    $('#graphContainer g.nodes > g.node').removeClass('selected');
    $('#graphContainer g.links > line.link').removeClass('selected');
    $('#graphContainer g.edgelabels > text').removeClass('selected');
}

function clickHandlerSvg(e) {
    // if (d3.event.target.id == 'relationGraphSVG') {
    //     generateTooltip(null, 'hide');
    // }
}

function clickHandlerNode(d) {
    var $d3Element = $(this);
    unselectAll();
    $d3Element.addClass('selected');
    generateTooltip(d, 'node');
}

function clickHandlerLink(d, i) {
    unselectAll();
    $('#graphContainer g.links #linkId_'+i).addClass('selected');
    $('#graphContainer g.edgelabels #edgelabelId_'+i).addClass('selected');
    generateTooltip(d, 'link');
}

function getAverageNumericalValue(tags) {
    var total = 0;
    var validTagCount = 0;
    tags.forEach(function(tag) {
        if (tag.numerical_value !== undefined) {
            total += parseInt(tag.numerical_value);
            validTagCount++;
        }
    });
    return validTagCount > 0 ? total / validTagCount : 0;
}

function generateTooltip(d, type) {
    $div =  $('#tooltipContainer');
    $div.empty();
    tableArray = [];
    title = '';
    $div.show();
    if (type === 'node') {
        title = d.value;
        tableArray = [
            {label: '<?= __('Name') ?>', value: d.value, url: {path: '<?= sprintf('%s/galaxy_clusters/view/', $baseurl) ?>', id: d.id}},
            {label: '<?= __('Galaxy') ?>', value: d.type, url: {path: '<?= sprintf('%s/galaxies/view/', $baseurl) ?>', id: d.galaxy_id}},
            {label: '<?= __('Description') ?>', value: d.description},
            {label: '<?= __('Default') ?>', value: d.default},
            {label: '<?= __('Distribution') ?>', value: getReadableDistribution(d), url: {path: d.distribution == 4 ? '<?= sprintf('%s/sharing_groups/view/', $baseurl) ?>' : undefined, id: d.distribution == 4 ? d.SharingGroup.id : ''}},
            (d.Org.id == 0 ?
                {label: '<?= __('Owner Org.') ?>', value: d.Org.name} :
                {label: '<?= __('Owner Org.') ?>', value: d.Org.name, url: {path: '<?= sprintf('%s/organisations/view/', $baseurl) ?>', id: d.Org.id}}
            ),
            (d.Orgc.id == 0 ?
                {label: '<?= __('Creator Org.') ?>', value: d.Org.name} :
                {label: '<?= __('Creator Org.') ?>', value: d.Orgc.name, url: {path: '<?= sprintf('%s/organisations/view/', $baseurl) ?>', id: d.Orgc.id}}
            ),
            {label: '<?= __('Tag name') ?>', value: d.tag_name},
            {label: '<?= __('Version') ?>', value: d.version},
            {label: '<?= __('UUID') ?>', value: d.uuid}
        ]
    } else if (type === 'link') {
        title = d.type;
        tableArray = [
            {label: '<?= __('Source') ?>', value: d.source.value},
            {label: '<?= __('Target') ?>', value: d.target.value},
            {label: '<?= __('Type') ?>', value: d.type},
        ]
        if (d.tag !== undefined) {
            var row = {label: '<?= __('Tags') ?>', htmlEnabled: true, html: '- none -'};
            if (d.tag.length > 0) {
                row['html'] = '';
            }
            var $tagDiv = $('<div></div>');
            d.tag.forEach(function(tag) {
                $tagDiv.append(
                    $('<span></span>')
                        .addClass('tag')
                        .text(tag.name)
                        .attr('title', '<?= __('Numerical value: ') ?>' + (tag.numerical_value !== undefined ? tag.numerical_value : '- none -'))
                        .css({
                            'white-space': 'nowrap',
                            'background-color': tag.colour,
                            'color': getTextColour(tag.colour)
                        })
                );
            });
            row['html'] += $tagDiv[0].outerHTML;
            tableArray.push(row);
            tableArray.push( {label: '<?= __('Average value') ?>', value: d.numerical_avg});
        }
    } else if (type == 'hide') {
        $div.hide();
        unselectAll();
        return;
    }
    $div.append($('<button></button>').css({'margin-right': '2px'}).addClass('close').text('×').click(function() { generateTooltip(null, 'hide') }));
    $div.append($('<h6></h6>').css({'text-align': 'center'}).text(title));
    if (tableArray.length > 0) {
        var $table = $('<table class="table table-condensed"></table>');
        $body = $('<tbody></tbody>');
        tableArray.forEach(function(row) {
            var $cell1 = $('<td></td>').text(row.label);
            var $cell2 = $('<td></td>');
            if (row.url !== undefined && row.url.path !== undefined) {
                var completeUrl = row.url.path + (row.url.id !== undefined ? row.url.id : '');
                $cell2.append($('<a></a>').attr('href', completeUrl).attr('target', '_blank').text(row.value));
            } else if (row.htmlEnabled) {
                $cell2.html(row.html)
            } else {
                $cell2.text(row.value);
            }
            $body.append(
                $('<tr></tr>').append(
                    $cell1,
                    $cell2
                )
            );
        })
        $table.append($body);
        $div.append(
            $table
        );
    }
}

function drawLabels() {
    labels = svg.select('.legend')
        .selectAll('.labels')
        .data(legendLabels);
    var label = labels.enter()
        .append('g')
        .attr('class', 'labels useCursorPointer')
    label.append('circle')
    label.append('text')

    labels.selectAll('circle')
        .style('fill', function(d, i){ return d.color })
        .style('stroke', function(d, i){ return d.color })
        .attr('r', 5);
    labels.selectAll('text')
        .text(function(d) { return d.text })
        .style('font-size', '16px')
        .style('text-decoration', function(d) { return d.disabled ? 'line-through' : '' })
        .attr('fill', function(d) { return d.disabled ? 'gray' : '' })
        .attr('text', 'start')
        .attr('dy', '.32em')
        .attr('dx', '8');
    labels.exit().remove();
    var ypos = 10, newxpos = 20, xpos;
    label
        .attr('transform', function(d, i) {
            var length = d3.select(this).select('text').node().getComputedTextLength() + 28;
            var xpos = newxpos;

            if (width < (margin.left) + margin.right + xpos + length) {
                newxpos = xpos = 20;
                ypos += 20;
            }

            newxpos += length;

            return 'translate(' + xpos + ',' + ypos + ')';
        })
        .on('click', function(d, i) { 
            var label_text = d.text;
            if (d3.event.ctrlKey) { // hide all others
                d.disabled = false;
                legendLabels.filter(function(fd) { return fd.text !== label_text}).forEach(function(label_data) {
                    label_data.disabled = true;
                })
            } else { // hide it
                d.disabled = !d.disabled;
            }
            filterGraph();
            drawLabels();
            update();
        });
    var legendBB = svg.select('.legend').node().getBBox();
    var pad = 3;
    svg.select('.legendContainer').insert('rect', ':first-child')
        .style('fill', '#fff')
        .attr('x', legendBB.x - pad)
        .attr('y', legendBB.y - pad)
        .attr('width', legendBB.width + pad)
        .attr('height', legendBB.height + pad)
        .style('stroke', '#eee');
}

function filterGraph() {
    var visibleLabels = legendLabels.filter(function(label) {
        return !label.disabled
    }).map(function(label) {
        return label.text;
    });
    var visibleLabels = {}
    legendLabels.forEach(function(label) {
        visibleLabels[label.text] = !label.disabled;
    });

    store.nodes.forEach(function(node) {
        if (node.isFiltered === undefined) {
            node.isFiltered = false;
        }
        if(visibleLabels[(node.group)] && node.isFiltered) {
            node.isFiltered = false;
            graph.nodes.push($.extend(true, {}, node));
        } else if (!visibleLabels[(node.group)] && !node.isFiltered) {
            node.isFiltered = true;
            graph.nodes.forEach(function(d, i) {
                if (node.id === d.id) {
                    graph.nodes.splice(i, 1);
                }
            });
        }
    });

    store.links.forEach(function(link) {
        if (link.isFiltered === undefined) {
            link.isFiltered = false;
        }
        if((visibleLabels[(link.source.group)] && visibleLabels[(link.target.group)]) && link.isFiltered) {
            link.isFiltered = false;

            /* No clue with d3 force doesn't keep the correct reference */
            var newLink = $.extend(true, {}, link);
            var tmpNode = graph.nodes.filter(function(node) {
                return node.uuid == newLink.source.uuid;
            })
            newLink.source = tmpNode[0]
            tmpNode = graph.nodes.filter(function(node) {
                return node.uuid == newLink.target.uuid;
            })
            newLink.target = tmpNode[0];
            newLink.id = link.source.uuid + ':' + link.target.uuid + ':' + link.type;
            /* Hopefully it will be fixed whener we bump d3.js */

            graph.links.push(newLink);
        } else if (!(visibleLabels[(link.source.group)] && visibleLabels[(link.target.group)]) && !link.isFiltered) {
            link.isFiltered = true;
            graph.links.forEach(function(d, i) {
                if (link.id === d.id) {
                    graph.links.splice(i, 1);
                }
            });
        }
    });
}

function getReadableDistribution(d) {
    if (d.distribution != 4) {
        return distributionLevels[d.distribution];
    } else {
        return d.SharingGroup.name;
    }
}
}());
</script>

<style>
#graphContainer g.node.selected > circle {
    r: 7;
    stroke-width: 2px !important;
}

#graphContainer g.node.selected > text {
    font-weight: bold;
}

#graphContainer line.link.selected {
    stroke: steelblue;
    stroke-opacity: 1;
}

#graphContainer g.edgelabels text.selected {
    fill: steelblue;
    font-weight: bold;
}
</style>