<?php
echo $this->element('genericElements/assetLoader', array(
    'js' => array('d3')
));
?>

<div>
    <div style="padding: 5px; background-color: #f6f6f6; border-bottom: 1px solid #ccc; ">
        <form id="relationsQuickAddForm">
            <div class="input">
                <label for="RelationshipSource"><?= __('Source UUID') ?></label>
                <input id="RelationshipSource" name="source_id" type="text" value="<?= h($cluster['GalaxyCluster']['uuid']) ?>" disabled></input>
            </div>
            <div class="input">
                <label for="RelationshipType"><?= __('Relationship type') ?></label>
                <select id="RelationshipType" name="referenced_galaxy_cluster_type">
                    <?php foreach ($existingRelations as $relation): ?>
                        <option value="<?= h($relation) ?>"><?= h($relation) ?></option>
                    <?php endforeach; ?>
                    <option value="<?= __('custom') ?>"><?= __('Custom relationship') ?></option>
                    <input id="RelationshipTypeFreetext" type="text"></input>
                </select>
            </div>
            <div class="input">
                <label for="RelationshipTarget"><?= __('Target UUID') ?></label>
                <input id="RelationshipTarget" name="target_id" type="text"></input>
            </div>
            <div class="input">
                <label for="RelationshipDistribution"><?= __('Distribution') ?></label>
                <select id="RelationshipDistribution" name="distribution">
                    <?php foreach ($distributionLevels as $k => $distribution): ?>
                        <option value="<?= h($k) ?>"><?= h($distribution) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="input">
                <label for="RelationshipTags"><?= __('Tags') ?></label>
                <input id="RelationshipTags" name="tags" type="text"></input>
            </div>
            <div class="clear"></div>
            <button id="buttonAddRelationship" type="button" class="btn btn-primary" style="">
                <i class="fas fa-plus"></i>
                Add relationship
            </button>
        </form>
    </div>
</div>

<div style="padding: 5px; min-height: 600px;">
    <svg id="treeSVG" style="width: 100%; height: 100%; min-height: 500px;"></svg>
</div>

<script>
    var hexagonPoints = '21,10.5 15.75,19.6 5.25,19.6 0,10.5 5.25,1.4 15.75,1.4'
    var hexagonTranslate = -10.5;
    var treeData = <?= json_encode($tree) ?>;
    var margin = {top: 10, right: 10, bottom: 10, left: 20};
    var treeWidth, treeHeight;
    var colors = d3.scale.category10();
    var hasBeenBuilt = false;
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
        var url = "<?= $baseurl ?>/galaxy_cluster_relations/add/";
        var data = {
            source_id: $('#RelationshipSource').val(),
            target_id: $('#RelationshipTarget').val(),
            type: $('#RelationshipType').val(),
            tags: $('#RelationshipTags').val(),
            distribution: $('#RelationshipDistribution').val(),
            tags: $('#RelationshipTags').val(),
            freetext_relation: $('#RelationshipTypeFreetext').val(),
        };
        if (data.type === 'custom') {
            data.type = data.freetext_relation;
        }
        toggleLoadingButton(true);
        fetchFormDataAjax(url,
            function(formData) {
                $('body').append($('<div id="temp"/>').html(formData));
                $('#temp #GalaxyClusterRelationSourceId').val(data.source_id);
                $('#temp #GalaxyClusterRelationTargetId').val(data.target_id);
                $('#temp #GalaxyClusterRelationReferencedGalaxyClusterType').val(data.type);
                $('#temp #GalaxyClusterRelationDistribution').val(data.distribution);
                $('#temp #GalaxyClusterRelationTags').val(data.tags);
                $.ajax({
                    data: $('#GalaxyClusterRelationAddForm').serialize(),
                    success:function (data) {
                        $.get("/galaxy_clusters/viewRelations/<?php echo $cluster['GalaxyCluster']['id']; ?>", function(data) {
                            $("#relations_container").html(data);
                        });
                    },
                    error:function(jqXHR, textStatus, errorThrown) {
                        showMessage('fail', textStatus + ": " + errorThrown);
                    },
                    complete:function() {
                        toggleLoadingButton(false);
                        $('#temp').remove();
                    },
                    type:"post",
                    url: $('#GalaxyClusterRelationAddForm').attr('action')
                });
            },
            function() {
                toggleLoadingButton(false);
            }
        )
    }

    function toggleLoadingButton(loading) {
        if (loading) {
            $('#buttonAddRelationship > i').removeClass('fa-plus').addClass('fa-spinner fa-spin');
        } else {
            $('#buttonAddRelationship > i').removeClass('fa-spinner fa-spin').addClass('fa-plus');
        }
    }

    function buildTree() {
        if (hasBeenBuilt) {
            return;
        }
        hasBeenBuilt = true;
        var $tree = $('#treeSVG');
        treeWidth = $tree.width() - margin.right - margin.left;
        treeHeight = $tree.height() - margin.top - margin.bottom;
        var leftShift;
        var childrenBothSides, side;

        var finalData = treeData.right;
        if (treeData.left[0].children === undefined || treeData.left[0].children.length == 0) {
            leftShift = 0;
            childrenBothSides = false;
            side = 'right';
        } else {
            if (treeData.right[0].children === undefined || treeData.right[0].children.length == 0) {
                leftShift = treeWidth;
                childrenBothSides = false;
                side = 'left';
            } else {
                leftShift = treeWidth/2;
                childrenBothSides = true;
                side = 'both';
            }
        }
        var data = genHierarchy(treeData, leftShift, childrenBothSides, side);
        drawTree(data, leftShift, childrenBothSides);
    }

    function genHierarchy(data, leftShift, childrenBothSides, side) {
        var rightOffset = 0;
        if (side !== 'left') {
            var treeRight = d3.layout.tree(data.right)
                .size([treeHeight, (childrenBothSides ? treeWidth/2 : treeWidth)]);
            var rootRight = data.right[0];
            rootRight.isRoot = true;
            rootRight.x0 = treeHeight / 2;
            rootRight.y0 = 0;
            var nodesRight = treeRight.nodes(rootRight).reverse();
            var linksRight = treeRight.links(nodesRight);
            var maxDepthRight = 0;
            var leftMaxTextLengthRight = 0;
            nodesRight.forEach(function(d) {
                maxDepthRight = maxDepthRight > d.depth ? maxDepthRight : d.depth;
                if (d.GalaxyCluster !== undefined) {
                    var clusterLength = d.GalaxyCluster.type.length > d.GalaxyCluster.value.length ? d.GalaxyCluster.type.length : d.GalaxyCluster.value.length;
                    leftMaxTextLengthRight = leftMaxTextLengthRight > clusterLength ? leftMaxTextLengthRight : clusterLength;
                } else if (d.Relation !== undefined) {
                    var tagLength = 0;
                    if (d.Relation.Tag !== undefined) {
                        tagLength = d.Relation.Tag.name / 2;
                    }
                    var relationLength = tagLength > d.Relation.referenced_galaxy_cluster_type.length ? tagLength : d.Relation.referenced_galaxy_cluster_type.length;
                    leftMaxTextLengthRight = leftMaxTextLengthRight > relationLength ? leftMaxTextLengthRight : relationLength;
                }
            })
            var offsetLeafLengthRight = leftMaxTextLengthRight * 6.7; // font-size of body is 12px
            var ratioFactor = (treeWidth - offsetLeafLengthRight) / (maxDepthRight * (childrenBothSides ? 2 : 1));
            nodesRight.forEach(function(d) { d.y = d.depth * ratioFactor; });
            rightOffset = side === 'right' ? -leftMaxTextLengthRight : 0;
        }

        if (side !== 'right') {
            var treeLeft = d3.layout.tree(data.left)
                .size([treeHeight, (childrenBothSides ? treeWidth/2 : treeWidth)]);
            var rootLeft = data.left[0];
            rootLeft.isRoot = true;
            rootLeft.x0 = treeHeight / 2;
            rootLeft.y0 = 0;
            var nodesLeft = treeLeft.nodes(rootLeft).reverse();
            var linksLeft = treeLeft.links(nodesLeft);
            var maxDepthLeft = 0;
            var leftMaxTextLengthLeft = 0;
            nodesLeft.forEach(function(d) {
                maxDepthLeft = maxDepthLeft > d.depth ? maxDepthLeft : d.depth;
                if (d.GalaxyCluster !== undefined) {
                    var clusterLength = d.GalaxyCluster.type.length > d.GalaxyCluster.value.length ? d.GalaxyCluster.type.length : d.GalaxyCluster.value.length;
                    leftMaxTextLengthLeft = leftMaxTextLengthLeft > clusterLength ? leftMaxTextLengthLeft : clusterLength;
                } else if (d.Relation !== undefined) {
                    var tagLength = 0;
                    if (d.Relation.Tag !== undefined) {
                        tagLength = d.Relation.Tag.name / 2;
                    }
                    var relationLength = tagLength > d.Relation.referenced_galaxy_cluster_type.length ? tagLength : d.Relation.referenced_galaxy_cluster_type.length;
                    leftMaxTextLengthLeft = leftMaxTextLengthLeft > relationLength ? leftMaxTextLengthLeft : relationLength;
                }
            })
            var offsetLeafLengthLeft = leftMaxTextLengthLeft * 6.7; // font-size of body is 12px
            var ratioFactor = (treeWidth - offsetLeafLengthLeft) / (maxDepthLeft  * (childrenBothSides ? 2 : 1));
            nodesLeft.forEach(function(d) { d.y = -d.depth * ratioFactor; });
            rightOffset = side === 'left' ? leftMaxTextLengthLeft : 0;
        }

        var nodes, links;
        if (side === 'both') {
            nodesLeft = nodesLeft.filter(function(d) { return d.depth !== 0}); // filter out duplicate root
            nodes = nodesRight.concat(nodesLeft);
            links = linksRight.concat(linksLeft);
        } else if (side === 'right') {
            nodes = nodesRight;
            links = linksRight;
        } else {
            nodes = nodesLeft;
            links = linksLeft;
        }
        return {
            rightOffset: rightOffset,
            nodes: nodes,
            links: links
        };
    }
    
    function drawTree(data, leftShift, childrenBothSides) {    
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
                .attr("transform", "translate(" + (leftShift + margin.left - 2*data.rightOffset) + "," + margin.top + ")");

        defs = svg.append("defs")
        defs.append("marker")
            .attr({
                "id":"arrowEnd",
                "viewBox":"0 -5 10 10",
                "refX": 10+7,
                "refY": 0,
                "markerWidth": 10,
                "markerHeight": 10,
                "markerUnits": "userSpaceOnUse",
                "orient":"auto"
            })
            .append("path")
                .attr("d", "M0,-5L10,0L0,5")
                .attr("class","arrowHead");
        defs.append("marker")
            .attr({
                "id":"arrowStart",
                "viewBox":"0 -5 10 10",
                "refX": 10+7,
                "refY": 0,
                "markerWidth": 10,
                "markerHeight": 10,
                "markerUnits": "userSpaceOnUse",
                "orient": 0
            })
            .append("path")
                .attr("d", "M0,-5L10,0L0,5")
                .attr("class","arrowHead");
        var nodes = data.nodes;
        var links = data.links;

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
            .attr("id",function(d,i) { return "linkId_" + i; })
            .attr("class", "link")
            .attr("marker-end", function(d) {
                if ((d.target.children === undefined || d.target.children.length === 0) && d.target.y > 0) {
                    return "url(#arrowEnd)"
                } else {
                    return ""
                }
            })
            .attr("marker-start", function(d) {
                if (d.source.isRoot && d.target.y < 0) {
                    return "url(#arrowStart)"
                } else {
                    return ""
                }
            })
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
        gEnter
        .classed('useCursorPointer', true)
        .on('dblclick', function(d) {
            if (d.isRoot) {
                return;
            }
            var url = "<?= sprintf('%s/galaxy_clusters/view/', $baseurl) ?>"
            window.open(url + d.GalaxyCluster.id, '_blank');
        })
        gEnter.filter(function(node) {return !node.isRoot; }).append("circle")
            .attr("r", function(d) { return d.isRoot ? 10 : 5; })
            .style("fill", function(d) { return colors(d.GalaxyCluster.type); })
            .style("stroke", "#000")
            .style("stroke-width", "2px");
        gEnter.filter(function(node) {return node.isRoot; }).append('polygon')
            .attr('points', hexagonPoints)
            .attr("transform", 'translate(' + hexagonTranslate + ', ' + hexagonTranslate + ')')
            .style("fill", function(d) { return colors(d.GalaxyCluster.type); })
            .style("stroke", "#000")
            .style("stroke-width", "2px");

        drawLabel(gEnter, {
            text: [function(d) { return d.GalaxyCluster.value }, function(d) { return d.GalaxyCluster.type }],
            x: function(d) { return getLabelPlacement(d, 'x'); },
            y: function(d) { return getLabelPlacement(d, 'y'); },
            textAnchor: 'middle',
            fontWeight: 'bold'
        });
    }

    function drawRelation(gEnter) {
        var paddingX = 9;
        gEnter.append("foreignObject")
            .attr("height", 40)
            .attr("y", -15)
            .attr("x", function(d) { return  -(getTextWidth(d.Relation.referenced_galaxy_cluster_type) + 2*paddingX/2)/2 + 'px'; })
            .attr("width", function(d) { return getTextWidth(d.Relation.referenced_galaxy_cluster_type) + 2*paddingX + 'px'; })
            .append("xhtml:div")
            .append("div")
            .attr("class", "well well-small")
            .style('padding', '4px 9px')
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

    function getLabelPlacement(d, axis) {
        if (axis === 'x') {
            return "0em";
            // if (reversed) {
                //     return d.children ? "1.5em" : "0em";
                // } else {
                    //     return d.children ? "0em" : "1.5em";
                    // }
        } else {
            return "2em";
            // if (reversed) {
            //     return d.children ? "0em" : "2em";
            // } else {
            //     return d.children ? "2em" : "";
            // }
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