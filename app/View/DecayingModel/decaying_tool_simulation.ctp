<div id="simulationContainer">
    <div style="padding: 15px; height: 90vh; display: flex; flex-direction: column;">
        <div style="height: 40%; display: flex">
            <div style="width: 30%; display: flex; flex-direction: column;">
                <div class="panel-container" style="display: flex; flex-direction: column; flex-grow: 1">
                    <select id="select_model_to_simulate" style="width: 100%;">
                        <?php foreach ($all_models as $model): ?>
                            <option value="<?php echo h($model['DecayingModel']['id']) ?>" <?php echo $decaying_model['DecayingModel']['id'] == $model['DecayingModel']['id'] ? 'selected' : '' ?>><?php echo h($model['DecayingModel']['name']); ?></option>
                        <?php endforeach; ?>
                    </select>

                    <ul class="nav nav-tabs" style="margin-right: -5px; margin-bottom: 10px;" id="simulation-tabs">
                        <li class="active"><a href="#restsearch" data-toggle="tab">RestSearch</a></li>
                        <li><a href="#specificid" data-toggle="tab">Specific ID</a></li>
                    </ul>

                    <div class="tab-content" style="padding: 5px;">
                        <div class="tab-pane active" id="restsearch">
                            <div style="display: flex; flex-direction: column;">
                                <h3 style="">Attribute RestSearch<span style="vertical-align: top; font-size: x-small;" class="fa fa-question-circle" title="Enforced fields: returnFormat"></span></h3>
<?php
    $registered_taxonomies = array_keys($decaying_model['DecayingModel']['parameters']['base_score_config']);
    foreach ($registered_taxonomies as $i => &$taxonomy_name) {
        $taxonomy_name = $taxonomy_name . ':%' ;
    }
?>
                                <textarea style="margin-bottom: 0px; margin-left: 4px; width: auto;height: unset !important;" rows="12">
{
    "decayingModel": <?php echo h($decaying_model['DecayingModel']['id']); ?>,
    "to_ids": 1,
    "org": <?php echo h($user['Organisation']['id']);?>,
    "deleted": 0,
    "tags": <?php echo json_encode($registered_taxonomies); ?>

}</textarea>
                                </br>
                                <span class="btn btn-primary" style="width: fit-content;" role="button" onclick="doRestSearch(this)"><?php echo __('Search'); ?></span>
                            </div>
                        </div>
                        <div class="tab-pane" id="specificid">
                            <h3 style="">Unique Attribute</h3>
                            <div style="display: flex;">
                                <div style="margin-left: 4px; margin-bottom: 0px;" class="input-prepend">
                                    <span class="add-on">ID</span>
                                    <input class="span3" type="text" placeholder="<?php echo __('Attribute ID or UUID') ?>" onkeypress="handle_input_key(event)">
                                </div>
                                <span id="performRestSearchButton" class="btn btn-primary" style="width: fit-content; margin-left: 4px;" role="button" onclick="doSpecificSearch(this)"><?php echo __('Simulate'); ?></span>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
            <div style="width: 70%; display: flex;">
                <div class="panel-container" style="flex-grow: 1;">
                    <div id="chart-decay-simulation-container" style="width: 100%; height: 100%;">
                        <div id="simulation_chart" style="height: 100%;"></div>
                    </div>
                </div>
            </div>
        </div>
        <div style="height: 60%; overflow-y: auto; background-color: #ffffff;" class="panel-container">
            <div style="height: 100%;" id="attributeTableContainer"></div>
        </div>
    </div>
</div>
<?php echo $this->Html->script('d3'); ?>
<script>
var svg;
var chart_width;
var chart_height;
var timeFormatter = d3.time.format("%Y-%m-%d").parse;
$(document).ready(function() {
    // set the dimensions and margins of the graph
    var margin = {top: 10, right: 30, bottom: 30, left: 60};
    chart_width = $('#simulation_chart').width() - margin.left - margin.right;
    chart_height = $('#simulation_chart').height() - margin.top - margin.bottom;

    // append the svg object to the body of the page
    svg = d3.select("#simulation_chart")
        .append("svg")
        .attr("width", chart_width + margin.left + margin.right)
        .attr("height", chart_height + margin.top + margin.bottom)
        .append("g")
        .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

});

function doRestSearch(clicked, query) {
    var data = query === undefined ? $(clicked).parent().find('textarea').val() : query;
    fetchFormDataAjax('/decayingModel/decayingToolRestSearch/', function(formData) {
        var $formData = $(formData);
        url = $formData.find('form').attr('action');
        $('#simulationContainer').append($formData);
        $formData.find('#decayingToolRestSearchFilters').val(data);
        $.ajax({
            data: $formData.find('form').serialize(),
            beforeSend:function() {
                $('#attributeTableContainer').html('<div style="height:100%; display:flex; align-items:center; justify-content:center;"><span class="fa fa-spinner fa-spin" style="font-size: xx-large;"></span></div>');
            },
            success:function (data, textStatus) {
                $('#attributeTableContainer').html(data);
            },
            error:function() {
                showMessage('fail', '<?php echo __('Failed to perform RestSearch') ?>');
            },
            type:'post',
            cache: false,
            url: url,
        });
    });
}

function doSpecificSearch(clicked) {
    doRestSearch(clicked, '{ "id": "' + $(clicked).parent().find('input').val() + '" }');
}

function handle_input_key(e) {
    if(e.keyCode === 13){
        e.preventDefault();
        $('#performRestSearchButton').click();
    }
}

function doSimulation(clicked, attribute_id) {
    $('#attribute_div tr').removeClass('success');
    $(clicked).addClass('success');
    var model_id = $('#select_model_to_simulate').val();
    // $.ajax({
    //     beforeSend:function() {
    //         $('#chart-decay-simulation-container').html('<div style="height:100%; display:flex; align-items:center; justify-content:center;"><span class="fa fa-spinner fa-spin" style="font-size: xx-large;"></span></div>');
    //     },
    //     success:function (data, textStatus) {
    //         $('#chart-decay-simulation-container').html(data);
    //     },
    //     error:function() {
    //         showMessage('fail', '<?php echo __('Failed to perform the simulation') ?>');
    //     },
    //     type:'get',
    //     cache: false,
    //     url: '/decayingModel/decayingToolChartSimulation/' + model_id + '/' + attribute_id,
    // });

    // d3.csv('/decayingModel/decayingToolComputeSimulation/' + model_id + '/' + attribute_id,
    d3.csv('https://raw.githubusercontent.com/holtzy/data_to_viz/master/Example_dataset/3_TwoNumOrdered_comma.csv',

        // When reading the csv, I must format variables:
        function(d){
            return { date : timeFormatter(d.date), value : d.value }
        },

        // Now I can use this dataset:
        function(data) {
            // Add X axis --> it is a date format
            var x = d3.time.scale()
                .domain(d3.extent(data, function(d) { return d.date; }))
                .range([ 0, chart_width ]);
            svg.append("g")
                .attr('class', 'decayingGraphAxis axis-y')
                .attr("transform", "translate(0," + chart_height + ")")
                .call(d3.svg.axis().scale(x).orient('bottom'));

            // Add Y axis
            var y = d3.scale.linear()
                .domain([0, d3.max(data, function(d) { return +d.value; })])
                .range([ chart_height, 0 ]);
            svg.append("g")
                .attr('class', 'decayingGraphAxis axis-y')
                .call(d3.svg.axis().scale(y).orient("left"));

            // Add the line
            var line = svg.selectAll(".lineAxis")
                .data([data]);
            line
                .enter()
                .append("path")
                .attr("class","lineAxis")
                .attr("fill", "none")
                .attr("stroke", "steelblue")
                .attr("stroke-width", 2.5)
                // .merge(line)
                .transition()
                .duration(1000)
                .attr("d", d3.svg.line()
                        .x(function(d) { return x(d.date) })
                        .y(function(d) { return y(d.value) }))

        }
    );
}
</script>
