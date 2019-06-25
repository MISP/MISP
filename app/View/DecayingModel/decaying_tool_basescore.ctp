<div class="row" style="padding: 15px;">
    <div class="span8" style="height: calc(90vh); overflow-y: scroll; border: 1px solid #ddd;">
        <input id="table_taxonomy_search" class="input" style="width: 250px; margin: 0px;" type="text" placeholder="<?php echo _('Search Taxonomy'); ?>"></input>
        <it class="fa fa-times useCursorPointer" title="<?php echo __('Clear search field'); ?>" onclick="$('#table_taxonomy_search').val('').trigger('input');"></it>
        <span style="float: right;"><b><?php echo h($taxonomies_not_having_numerical_value); ?></b><?php echo __(' not having numerical value'); ?></span>
        <table id="tableTaxonomy" class="table table-striped table-bordered table-condensed">
            <thead>
                <tr>
                    <th><?php echo __('Taxonomies') ?></th>
                    <th><?php echo __('Weight') ?></th>
                </tr>
            </thead>
            <tbody id="body_taxonomies">
                <?php foreach ($taxonomies as $name => $taxonomy): ?>
                    <tr>
                        <td>
                            <?php echo h($name) ?>
                        </td>
                        <td>
                            <input id="slider_<?php echo h($name) ?>" data-taxonomyname="<?php echo h($name) ?>" type="range" min=0 max=100 step=1 value="<?php echo isset($taxonomy['value']) ? h($taxonomy['value']) : 0 ?>" onchange="sliderChanged(this);" oninput="sliderChanged(this);"></input>
                            <input type="number" min=0 max=100 step=1 value="<?php echo isset($taxonomy['value']) ? h($taxonomy['value']) : 0 ?>" style="display: inline-block; margin-left: 5px; margin: 0px; width: 40px;" data-taxonomyname="<?php echo h($name) ?>" onchange="inputChanged(this);" oninput="inputChanged(this);"></input>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <div class="span8">
        <div style="margin-bottom: 5px;">
            <div id="treemapGraphTax" style="border: 1px solid #dddddd; border-radius: 4px; text-align: center;"></div>
        </div>
        <div style="margin-bottom: 5px; border: 1px solid #dddddd; border-radius: 4px; text-align: center; background-color: white;">
            <?php echo __('Placeholder for `Organisation source confidence`') ?>
        </div>
        <div>
            <h3><?php echo __('Example') ?><it class="fa fa-sync useCursorPointer" style="margin-left: 5px; font-size: small;" onclick="refreshExamples()"></it></h3>
            <table id="tableTaxonomy" class="table table-striped table-bordered table-condensed">
                <thead>
                    <tr>
                        <th>Attribute</th>
                        <th>Tags</th>
                        <th>Base score</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>
                            Tag your attribute
                        </td>
                        <td>
                            <div style="width:100%;display:inline-block;" data-original-title="" title="">
                                <div style="float:left" data-original-title="" title="">
                                    <button id="basescore-example-score-addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" title="Add tag" onclick="popoverPopup(this, '0', 'tags', 'selectTaxonomy');">+</button>
                                </div>
                            </div>
                        </td>
                        <td id="basescore-example-score-custom">
                        </td>
                    </tr>
                    <tr>
                        <td>Attribute 1</td>
                        <td id="basescore-example-tag-1"><?php echo __('Pick a Taxonomy'); ?></td>
                        <td id="basescore-example-score-1"></td>
                    </tr>
                    <tr>
                        <td>Attribute 2</td>
                        <td id="basescore-example-tag-2"><?php echo __('Pick a Taxonomy'); ?></td>
                        <td id="basescore-example-score-2"></td>
                    </tr>
                    <tr>
                        <td>Attribute 3</td>
                        <td id="basescore-example-tag-3"><?php echo __('Pick a Taxonomy'); ?></td>
                        <td id="basescore-example-score-3"></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php
echo $this->element('genericElements/assetLoader', array(
    'css' => array(
        'treemap',
    )
));
?>

<script>
var taxonomies_with_num_value = <?php echo json_encode($taxonomies); ?>;

function getRandomInt(max) {
    return Math.floor(Math.random() * Math.floor(max));
}

function pickRandomTags() {
    var matching_inputs = $('#body_taxonomies > tr')
    .find('input[type="number"]')
    .filter(function() {
        return $(this).val() > 0;
    });
    var taxonomies_name = [];
    matching_inputs.each(function() {
        taxonomies_name.push($(this).data('taxonomyname'));
    });
    var tags = [];

    if (taxonomies_name.length == 0) {
        return [];
    }

    var temp_taxonomies_name = taxonomies_name.slice();
    var max_tag_num = taxonomies_name.length > 3 ? 3 : taxonomies_name.length;
    var picked_tag_number = getRandomInt(max_tag_num) + 1;
    for (var i = 0; i < picked_tag_number; i++) { // number of tags
        // pick a taxonomy
        var picked_number_taxonomy = getRandomInt(temp_taxonomies_name.length);
        var picked_taxonomy_name = temp_taxonomies_name[picked_number_taxonomy];
        var picked_taxonomy = taxonomies_with_num_value[picked_taxonomy_name];
        // pick a random predicate
        var picked_number_predicate = getRandomInt(picked_taxonomy['TaxonomyPredicate'].length);
        var picked_predicate = picked_taxonomy['TaxonomyPredicate'][picked_number_predicate];
        // pick a random entry -> tag
        var picked_number_entry = getRandomInt(picked_predicate['TaxonomyEntry'].length);
        var picked_entry = picked_predicate['TaxonomyEntry'][picked_number_entry];
        tags.push(picked_entry['Tag']);
        // delete temp_taxonomies_name[picked_number_taxonomy];
        temp_taxonomies_name.splice(picked_number_taxonomy, 1);
    }
    return tags;
}

function refreshExamples() {
    for (var i = 1; i <= 3; i++) {
        var numerical_values = [];
        tags = pickRandomTags();
        tags_html = '';
        tags.forEach(function(tag) {
            numerical_values.push({name: tag.name.split(':')[0], value: tag['numerical_value']})
            var text_color = getTextColour(tag.colour);
            tags_html += '<span class="tag decayingExampleTags" style="background-color: ' + tag.colour + ';color:' + text_color + '" '
                + 'title="numerical_value=' + tag['numerical_value'] + '" '
                + 'data-placement="right">' + tag.name + '</span>&nbsp;';
        });

        var base_score = compute_base_score(numerical_values);
        $('#basescore-example-tag-'+i).empty().append(tags_html);
        $('#basescore-example-score-'+i).text(base_score);
        $('span.decayingExampleTags').tooltip();
    }
}

function compute_base_score(numerical_values) {
    return 0;
}

function filterTableTaxonomy(searchString) {
    var $table = $('#tableTaxonomy');
    var $body = $table.find('tbody');
    if (searchString === '') {
        $body.find('tr').forceClass('hidden', false);
    } else {
        $body.find('tr').forceClass('hidden', true);
        // show only matching elements
        var $cells = $body.find('tr > td:nth-child(1)');
        $cells.each(function() {
            if ($(this).text().trim().toUpperCase().indexOf(searchString.toUpperCase()) != -1) {
                $(this).parent().forceClass('hidden', false);
            }
        });
    }
}

$('#table_taxonomy_search').on('input', function() {
    filterTableTaxonomy(this.value);
});

function sliderChanged(changed) {
    $(changed).parent().find('input[type="number"]').val(changed.value);
    var new_data = genTreeData();
    updateTree(new_data);
}
function inputChanged(changed) {
    $(changed).parent().find('input[type="range"]').val(changed.value);
    var new_data = genTreeData();
    updateTree(new_data);
}

function updateTree(new_data) {
    var treemap = d3.layout.treemap()
        .size([width, height])
        .sticky(true)
        .value(function(d) { return d.size; });
    var nodes = div.datum(new_data).selectAll(".node")
        .data(treemap.nodes);

    nodes.enter()
        .append("div")
        .attr("class", "node useCursorPointer")
        .style("background", function(d) {
            if (d.depth == 0) {
                return 'white';
            } else if (!d.children) {
                return color(d.name);
            } else {
                return null;
            }
        })
        .attr("id", function(d) { return d.name + '-node'})
        .on('click', function() { $('#table_taxonomy_search').val(d3.select(this).data()[0].name).trigger('input');})
    nodes.transition().duration(100)
        .call(position)
        .attr("title", function(d) { return d.name + ': ' + d.size})
        .text(function(d) {
            if (d.children) {
                return '';
            } else if (d.name !== '' && !isNaN(d.ratio) ) {
                return d.name + ' ('+parseInt(d.ratio*100)+'%)';
            } else {
                return '';
            }
        });

    nodes.exit()
        .remove();
}

function genTreeData() {
    var root = {
        name: '',
        children: []
    };
    var sum = 0;
    var $sliders = $('#body_taxonomies').find('input[type="range"]');
    $sliders.each(function(){
        sum += parseInt($(this).val());
    });
    $sliders.each(function(){
        var val = parseInt($(this).val());
        if (val > 0) {
            var tmp = {
                name: $(this).data('taxonomyname'),
                size: val,
                ratio: val/sum
            };
            root.children.push(tmp);
        }
    });
    return root;
}

    var root = genTreeData();
    var margin = {top: 0, right: 0, bottom: 0, left: 0},
    	width = 620 - margin.left - margin.right,
    	height = 500 - margin.top - margin.bottom;

    var color = d3.scale.category20c();

    var treemap = d3.layout.treemap()
        .size([width, height])
        .sticky(true)
        .value(function(d) { return d.size; });

    var div = d3.select("#treemapGraphTax").append("div").text('No taxonomy')
    	.style("position", "relative")
    	.style("width", (width + margin.left + margin.right) + "px")
    	.style("height", (height + margin.top + margin.bottom) + "px")
    	.style("left", margin.left + "px")
    	.style("top", margin.top + "px");

    updateTree(root);

    function position() {
      this.style("left", function(d) { return d.x + "px"; })
          .style("top", function(d) { return d.y + "px"; })
          .style("width", function(d) { return Math.max(0, d.dx - 1) + "px"; })
          .style("height", function(d) { return Math.max(0, d.dy - 1) + "px"; });
    }
</script>
