<?php
echo $this->element('genericElements/assetLoader', array(
    'js' => array('d3')
));
?>

<div>
    <div style="padding: 5px; background-color: #f6f6f6; border-bottom: 1px solid #ccc; ">
        <div id="relationsQuickAddForm">
            <div class="input">
                <label for="RelationshipSource"><?= __('Source UUID') ?></label>
                <input id="RelationshipSource" type="text" value="<?= h($cluster['GalaxyCluster']['uuid']) ?>" disabled></input>
            </div>
            <div class="input">
                <label for="RelationshipType"><?= __('Relationship type') ?></label>
                <select id="RelationshipType">
                    <?php foreach ($existingRelations as $relation): ?>
                        <option value="<?= h($relation) ?>"><?= h($relation) ?></option>
                    <?php endforeach; ?>
                    <option value="<?= __('custom') ?>"><?= __('Custom relationship') ?></option>
                    <input id="RelationshipTypeFreetext" type="text"></input>
                </select>
            </div>
            <div class="input">
                <label for="RelationshipTarget"><?= __('Target UUID') ?></label>
                <input id="RelationshipTarget" type="text"></input>
            </div>
            <div class="input">
                <label for="RelationshipTags"><?= __('Tags') ?></label>
                <input id="RelationshipTags" type="text"></input>
            </div>
            <div class="clear"></div>
            <button id="buttonAddRelationship" type="button" class="btn btn-primary" style="">
                <i class="fas fa-plus"></i>
                Add relationship
            </button>
        </div>
    </div>
</div>

<div style="padding: 5px; min-height: 600px;">
    <svg id="treeSVG" style="width: 100%; height: 100%; min-height: 500px;"></svg>
</div>

<script>
    var treeData = <?= json_encode($tree) ?>;
    var margin = {top: 10, right: 10, bottom: 10, left: 20};
    var treeWidth, treeHeight;
    var colors = d3.scale.category10();
    $(document).ready(function() {
        // $('#relationsQuickAddForm select').chosen();
        $('#relationsQuickAddForm #RelationshipType').change(function() {
            if (this.value === 'custom') {
                $('#relationsQuickAddForm #RelationshipTypeFreetext').show();
            } else {
                $('#relationsQuickAddForm #RelationshipTypeFreetext').hide();
            }
        });
        $('#relationsQuickAddForm #RelationshipTypeFreetext').hide();
    })
    $('#buttonAddRelationship').click(function() {
        submitRelationshipForm();
    })

    function submitRelationshipForm() {
        var url = "<?= $baseurl ?>/galaxy_clusters/addRelations/";
        $.ajax({
            beforeSend: function (XMLHttpRequest) {
                toggleLoadingButton(true);
            },
            data: $('#relationsQuickAddForm').serialize(),
            success: function (data, textStatus) {
                $('#top').html(data);
                showMessage("success", "Relation added");
            },
            error: function (jqXHR, textStatus, errorThrown) {
                showMessage('fail', textStatus + ": " + errorThrown);
            },
            complete: function() {
                toggleLoadingButton(false);
            },
            type:"post",
            cache: false,
            url: url,
        });
    }

    function toggleLoadingButton(loading) {

    }

    function buildTree() {
        var $tree = $('#treeSVG');
        treeWidth = $tree.width() - margin.right - margin.left;
        treeHeight = $tree.height() - margin.top - margin.bottom;

        var tree = d3.layout.tree(treeData)
            .size([treeHeight, treeWidth]);
        
        var diagonal = function link(d) {
            return "M" + d.source.y + "," + d.source.x
                + "C" + (d.source.y + d.target.y) / 2 + "," + d.source.x
                + " " + (d.source.y + d.target.y) / 2 + "," + d.target.x
                + " " + d.target.y + "," + d.target.x;
        };
        
        var svg = d3.select("#treeSVG")
            .attr("width", treeWidth + margin.right + margin.left)
            .attr("height", treeHeight + margin.top + margin.bottom)
            .append("g")
                .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

        var root = treeData[0];
        root.isRoot = true;
        root.x0 = treeHeight / 2;
        root.y0 = 0;
        var nodes = tree.nodes(root).reverse();
        var links = tree.links(nodes);
        var maxDepth = 0;
        var leftMaxTextLength = 0;
        nodes.forEach(function(d) {
            maxDepth = maxDepth > d.depth ? maxDepth : d.depth;
            if (d.GalaxyCluster !== undefined) {
                var clusterLength = d.GalaxyCluster.type.length > d.GalaxyCluster.value.length ? d.GalaxyCluster.type.length : d.GalaxyCluster.value.length;
                leftMaxTextLength = leftMaxTextLength > clusterLength ? leftMaxTextLength : clusterLength;
            } else if (d.Relation !== undefined) {
                var tagLength = 0;
                if (d.Relation.Tag !== undefined) {
                    tagLength = d.Relation.Tag.name / 2;
                }
                var relationLength = tagLength > d.Relation.referenced_galaxy_cluster_type.length ? tagLength : d.Relation.referenced_galaxy_cluster_type.length;
                leftMaxTextLength = leftMaxTextLength > relationLength ? leftMaxTextLength : relationLength;
            }
        })
        var offsetLeafLength = leftMaxTextLength * 6.7; // font-size of body is 12px
        var ratioFactor = (treeWidth - offsetLeafLength) / maxDepth;
        nodes.forEach(function(d) { d.y = d.depth * ratioFactor; });

        var node = svg.selectAll("g.node")
            .data(nodes, function(d) { return getId(d, true) });

        var nodeEnter = node.enter().append("g")
            .attr("class", "node")
            .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; })
            .on("mouseover", nodeHover)
            .on("dblclick", nodeDbclick);

        var gEnter = nodeEnter.append('g');
        drawEntities(gEnter);

        var link = svg.selectAll("path.link")
            .data(links, function(d) { return getId(d.target); });

        link.enter().insert("path", "g")
            .attr("class", "link")
            .style("fill", "none")
            .style("stroke", "#ccc")
            .style("stroke-width", function(d) {
                var linkWidth = 2;
                var linkMaxWidth = 4;
                if (d.source.Relation !== undefined && d.source.Relation.Tag !== undefined) {
                    linkWidth = d.source.Relation.Tag.numerical_value / 100 * linkMaxWidth;
                } else if (d.target.Relation !== undefined && d.target.Relation.Tag !== undefined) {
                    linkWidth = d.target.Relation.Tag.numerical_value / 100 * linkMaxWidth;
                }
                return linkWidth + 'px';
            })
            .attr("d", function(d) {
                return diagonal(d);
            });
    }

    function drawEntities(gEnter) {
        gEnter.filter(function(d) { return d.GalaxyCluster !== undefined }).call(drawCluster);
        gEnter.filter(function(d) { return d.Relation !== undefined }).call(drawRelation);
    }

    function drawCluster(gEnter) {
        gEnter.append("circle")
            .attr("r", 5)
            .style("fill", function(d) { return colors(d.GalaxyCluster.type); })
            .style("stroke", "#000")
            .style("stroke-width", "2px");

        drawLabel(gEnter, {
            text: [function(d) { return d.GalaxyCluster.value }, function(d) { return d.GalaxyCluster.type }],
            x: function(d) { return d.children ? "0em" : "1.5em"; },
            y: function(d) { return d.children ? "2em" : ""; },
            textAnchor: 'start',
            fontWeight: 'bold'
        });
    }

    function drawRelation(gEnter) {
        var paddingX = 9;
        gEnter.append("foreignObject")
        .attr("height", 40)
            .attr("y", -20)
            .attr("width", function(d) { return getTextWidth(d.Relation.referenced_galaxy_cluster_type) + 2*paddingX + 'px'; })
            .append("xhtml:div")
            .append("div")
            .attr("class", "well well-small")
            // .attr("title", function(d) { return d.children ? "Version" : "<?= __('Latest version of the parent cluster') ?>" })
            .html(function(d) { return d.Relation.referenced_galaxy_cluster_type; })
            
        paddingX = 6;
        gEnter.append("foreignObject")
            .attr("height", 18)
            .attr("y", 20)
            .attr("x", function(d) { return  -(d.Relation.Tag !== undefined ? getTextWidth(d.Relation.Tag.name, {'white-space': 'nowrap', 'font-weight': 'bold'}) - 2*paddingX : 0)/2 + 'px'; })
            .attr("width", function(d) { return  (d.Relation.Tag !== undefined ? getTextWidth(d.Relation.Tag.name, {'white-space': 'nowrap', 'font-weight': 'bold'}) + 2*paddingX : 0) + 'px'; })
            .append("xhtml:div")
            .append("span")
            .attr("class", "tag")
            .style('white-space', 'nowrap')
            .style('background-color', function(d) {return d.Relation.Tag !== undefined ? d.Relation.Tag.colour : '';})
            .style('color', function(d) {return d.Relation.Tag !== undefined ? getTextColour(d.Relation.Tag.colour) : 'white';})
            // .attr("title", function(d) { return d.children ? "Version" : "<?= __('Latest version of the parent cluster') ?>" })
            .html(function(d) { return d.Relation.Tag !== undefined ? d.Relation.Tag.name : ''; })
    }

    function drawLabel(gEnter, options) {
        var defaultOptions = {
            text: '',
            x: '',
            dx: '',
            y: '',
            dy: '',
            textAnchor: 'start',
            fontWeight: ''
        }
        options = $.extend(defaultOptions, options);
        var svgText = gEnter.append("text")
            .attr("dy", options.dy)
            .attr("dx", options.dx)
            .attr("x", options.x)
            .attr("y", options.y)
            .attr("text-anchor", options.textAnchor)
        if (Array.isArray(options.text)) {
            options.text.forEach(function(text, i) {
                svgText.append('tspan')
                    .attr('font-weight', i == 0 ? 'bold' : '')
                    .attr('font-style', i != 0 ? 'italic' : '')
                    .attr('x', options.x)
                    .attr('dy', i != 0 ? 16 : 0)
                    .text(text);
            })
        } else {
            svgText
                .attr("font-weight", options.fontWeight)
                .text(options.text);
        }
    }

    function getTextWidth(text, additionalStyle) {
        var style = {visibility: 'hidden'};
        if (additionalStyle !== undefined) {
            style = $.extend(style, additionalStyle);
        }
        var tmp = $('<span></span>').text(text).css(style)
        $('body').append(tmp);
        var bcr = tmp[0].getBoundingClientRect()
        tmp.remove();
        return bcr.width;
    }

    function nodeDbclick(d) {
    }

    function nodeHover(d) {
    }

    function getId(d) {
        var id = "";
        if (d.GalaxyCluster !== undefined) {
            id = d.GalaxyCluster.id;
        } else if (d.Relation !== undefined) {
            id = d.Relation.id;
        }
        return id;
    }
</script>