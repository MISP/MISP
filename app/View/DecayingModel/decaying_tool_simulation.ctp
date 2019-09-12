<div class="view">
    <div id="simulationContainer">
        <div class="simulationSubContainer">
            <div style="height: 40%; display: flex">
                <div style="width: 20%; display: flex; flex-direction: column;">
                    <div class="panel-container" style="display: flex; flex-direction: column; flex-grow: 1">
                        <div style="display: flex; flex-wrap: wrap;">
                            <select id="select_model_to_simulate" onchange="modelChangeHandler(this)" style="flex-grow: 1;">
                                <?php foreach ($all_models as $model): ?>
                                    <option value="<?php echo h($model['DecayingModel']['id']) ?>" <?php echo $decaying_model['DecayingModel']['id'] == $model['DecayingModel']['id'] ? 'selected' : '' ?>><?php echo h($model['DecayingModel']['name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <span id="select_model_to_simulate_infobox" class="btn"><span class="fa fa-question-circle"></span></span>
                        </div>

                        <ul class="nav nav-tabs" style="margin-right: -5px; margin-bottom: 0px;" id="simulation-tabs">
                            <li class="<?php echo isset($attribute_id) ? '' : 'active'; ?>"><a href="#restsearch" data-toggle="tab">RestSearch</a></li>
                            <li class="<?php echo !isset($attribute_id) ? '' : 'active'; ?>"><a href="#specificid" data-toggle="tab">Specific ID</a></li>
                        </ul>

                        <div class="tab-content" style="padding: 5px; height: 100%;">
                            <div class="tab-pane <?php echo isset($attribute_id) ? '' : 'active'; ?>" id="restsearch" style="height: 100%;">
                                <div style="display: flex; flex-direction: column; height: 100%;">
                                    <h3 style="">Attribute RestSearch<span style="vertical-align: top; font-size: x-small;" class="fa fa-question-circle" title="Enforced fields: [returnFormat, includeEventTags]"></span></h3>
    <?php
        $registered_taxonomies = array_keys($decaying_model['DecayingModel']['parameters']['base_score_config']);
        foreach ($registered_taxonomies as $i => &$taxonomy_name) {
            $taxonomy_name = $taxonomy_name . '%' ;
        }
    ?>
                                    <textarea id="restSearchTextarea">
    {
        "includeDecayScore": 1,
        "includeFullModel": 0,
        "score": <?php echo h($decaying_model['DecayingModel']['parameters']['threshold']); ?>,
        "excludeDecayed": 0,
        "decayingModel": [<?php echo h($decaying_model['DecayingModel']['id']); ?>],
        "to_ids": 1,
        "tags": <?php echo json_encode($registered_taxonomies); ?>,
        "modelOverrides": {
            
        }
    }</textarea>
                                    </br>
                                    <span class="btn btn-primary" style="width: fit-content;" role="button" onclick="doRestSearch(this)"><?php echo __('Search'); ?></span>
                                </div>
                            </div>
                            <div class="tab-pane <?php echo !isset($attribute_id) ? '' : 'active'; ?>" id="specificid">
                                <h3 style=""><?php echo __('Specific Attribute'); ?></h3>
                                <div style="display: flex; flex-wrap: wrap;">
                                    <div style="margin-left: 4px; margin-bottom: 0px;" class="input-prepend">
                                        <span class="add-on">ID</span>
                                        <input type="text" value="<?php echo isset($attribute_id) ? h($attribute_id) : ''; ?>" placeholder="<?php echo __('Attribute ID or UUID') ?>" onkeypress="handle_input_key(event)" style="width: auto;">
                                    </div>
                                    <span id="performRestSearchButton" class="btn btn-primary" style="width: fit-content; margin-left: 4px;" role="button" onclick="doSpecificSearch(this)"><?php echo __('Simulate'); ?></span>
                                </div>
                            </div>
                        </div>

                    </div>
                </div>
                <div style="width: 80%; display: flex;">
                    <div class="panel-container" style="flex-grow: 1; display: flex; width: 100%">
                        <div id="basescore-simulation-container" style="width: 30%; min-width: 300px; height: 100%; margin-right: 10px;">
                            <div>
                                <h5 style="display: inline-block;"><?php echo __('Base score') ?> <i id="basescore_enlarge_icon" class="fas fa-expand useCursorPointer"></i></h5>
                                <div id="alert-basescore-not-set" class="alert alert-warning" style="display: inline-block; margin-bottom: auto; margin-left: 5px; padding: 4px 8px;">
                                    <strong><?php echo __('Base score configuration'); ?></strong> <?php echo __('not set. But default value sets.') ?>
                                </div>
                                <div id="alert-basescore-not-set" class="alert alert-error" style="display: inline-block; margin-bottom: auto; margin-left: 5px; padding: 4px 8px;">
                                    <strong><?php echo __('Base score configuration'); ?></strong> <?php echo __('not set') ?>
                                </div>
                            </div>
                            <div style="position: relative; max-height: calc(100% - 75px); overflow: auto; margin-bottom: 5px;">
                                <?php echo $this->element('DecayingModels/View/basescore_computation_steps'); ?>
                            </div>
                            <div style="margin-bottom: 5px; white-space: nowrap;">
                                <div style="margin-left: 4px; margin-bottom: 0px;" class="input-prepend input-append">
                                    <span class="add-on"><?php echo __('Sighting'); ?></span>
                                    <span id="simulation-sighting" class="add-on"></span>
                                </div>
                                <div style="margin-left: 4px; margin-bottom: 0px;" class="input-prepend input-append">
                                    <span class="add-on"><?php echo __('Current score'); ?></span>
                                    <span id="simulation-current-score" class="add-on"></span>
                                </div>
                            </div>
                        </div>
                        <div id="chart-decay-simulation-container" style="width: 70%; height: 100%; position: relative; overflow: hidden;">
                            <div id="simulation_chart" class="svg-container"></div>
                        </div>
                    </div>
                </div>
            </div>
            <div style="height: 60%; overflow-y: auto; background-color: #ffffff; min-width: 1600px; " class="panel-container">
                <div style="height: 100%;" id="attributeTableContainer"></div>
            </div>
        </div>
    </div>
</div>
<?php echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => '')); ?>
<?php
    echo $this->element('genericElements/assetLoader', array(
        'css' => array('treemap', 'decayingTool'),
        'js' => array('d3', 'decayingModelSimulation')
    ));
?>

<script>
var model_list = <?php echo json_encode($all_models); ?>;
var models = {};
$('#alert-basescore-not-set').hide();
$('#alert-basescore-not-set.alert-error').hide();
$(document).ready(function() {
    model_list.forEach(function(m) {
        models[m.DecayingModel.id] = m.DecayingModel;
    });
    $('#select_model_to_simulate_infobox').popover({
        title: function() {
            return $('<div>').text($('#select_model_to_simulate option:selected').text()).html();
        },
        content: function() {
            return '<div>' + syntaxHighlightJson(models[$('#select_model_to_simulate').val()]) + '</div>';
        },
        html: true,
        placement: 'bottom'
    });

    $('#basescore_enlarge_icon').click(function() {
        var $table = $('#computation_help_container > table');
        var css_container = 'width: 1000px; left: calc(50% - 500px); margin-left: 0;';
        var css_body = 'max-height: 80%;';
        openModal('<?php echo __('Basescore computation steps'); ?>', $table[0].outerHTML, '', {}, css_container, css_body);
    });

    $('body').on('click', function (e) {
        if (
            $(e.target).attr('id')  !== 'select_model_to_simulate'
            && $(e.target).attr('id') !== 'select_model_to_simulate_infobox'
            && $(e.target).parents('#select_model_to_simulate_infobox').length === 0
            && $(e.target).parents('.popover.in').length === 0) {
            $('#select_model_to_simulate_infobox').popover('hide');
        }
    });

    <?php echo isset($attribute_id) ? '$("#performRestSearchButton").click();' : ''; ?>
});


function doRestSearch(clicked, query) {
    var data = query === undefined ? $(clicked).parent().find('textarea').val() : query;
    var json;
    try {
        json = JSON.parse(data);
    } catch (SyntaxError) {
        showMessage('fail', 'Invalid JSON syntax');
        return;
    }
    fetchFormDataAjax('/decayingModel/decayingToolRestSearch/', function(formData) {
        var $formData = $(formData);
        url = $formData.find('form').attr('action');
        $('#simulationContainer').append($formData);
        $formData.find('#decayingToolRestSearchFilters').val(data);
        $.ajax({
            data: $formData.find('form').serialize(),
            beforeSend:function() {
                $('#attributeTableContainer').html('<div class="loading-spinner-container"><span class="fa fa-spinner fa-spin" style="font-size: xx-large;"></span></div>');
            },
            success:function (data, textStatus) {
                $('#attributeTableContainer').html(data);
                var $trs = $('#attributeTableContainer tbody > tr');
                if ($trs.length == 1) {
                    $trs.click();
                }
                // pass potential model overrides
                if (json.modelOverrides !== undefined) {
                    $trs.data('modelOverride', JSON.stringify(json.modelOverrides));
                }
                if (json.score !== undefined) {
                    $trs.data('score', json.score);
                }
            },
            error:function(jqXHR, textStatus, errorThrown) {
                $('#attributeTableContainer').text(textStatus + ': ' + errorThrown);
                showMessage('fail', '<?php echo __('Failed to perform RestSearch') ?>');
            },
            type:'post',
            cache: false,
            url: url,
        });
    });
}

function doSpecificSearch(clicked) {
    var body = {
        id: $(clicked).parent().find('input').val(),
        decayingModel: $('#select_model_to_simulate').val()
    }
    doRestSearch(clicked, JSON.stringify(body));
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
    var simulation_chart = $('#simulation_chart').data('DecayingSimulation');
    var simulation_table = $('#basescore-simulation-container #computation_help_container_body').data('BasescoreComputationTable');
    if (simulation_chart === undefined) {
        simulation_chart = $('#simulation_chart').decayingSimulation({});
    }
    if (simulation_table === undefined) {
        simulation_table = $('#basescore-simulation-container #computation_help_container_body').basescoreComputationTable({});
    }
    var url = '/decayingModel/decayingToolComputeSimulation/' + model_id + '/' + attribute_id;
    var model_override = $(clicked).data('modelOverride');
    if (model_override !== undefined) {
        url += '/modelOverride:' + model_override;
    }
    var score = $(clicked).data('score');
    if (score !== undefined) {
        url += '/score:' + score;
    }
    $.ajax({
        beforeSend:function() {
            simulation_chart.toggleLoading(true);
            simulation_table.toggleLoading(true);
        },
        success:function (data, textStatus) {
            simulation_chart.update(data, data.Model);
            simulation_table.update(data, data.Model);
            if (Object.keys(data.base_score_config.taxonomy_effective_ratios).length > 0) { // show alert base_score not set
                $('#alert-basescore-not-set').hide();
                $('#alert-basescore-not-set.alert-error').hide();
                $('#basescore-simulation-container #computation_help_container_body tr').removeClass('warning').removeClass('error');
            } else {
                if (data.base_score_config.default_base_score == 0) { // show alert base_score not set
                    $('#alert-basescore-not-set.alert-error').show('fade', {}, 250);
                    $('#alert-basescore-not-set').hide();
                    $('#basescore-simulation-container #computation_help_container_body tr').removeClass('warning').addClass('error');
                } else {
                    $('#alert-basescore-not-set').show('fade', {}, 250);
                    $('#alert-basescore-not-set.alert-error').hide();
                    $('#basescore-simulation-container #computation_help_container_body tr').removeClass('error').addClass('warning');
                }
            }
            $('#simulation-sighting')
                .text(
                    d3.time.format("%c")(new Date(parseInt(data.last_sighting.Sighting.date_sighting)*1000))
                );
            $('#simulation-sighting').parent().tooltip({
                title: 'From ' + (data.last_sighting.Organisation !== undefined ? data.last_sighting.Organisation.name : '?'),
            });
            $('#simulation-current-score')
                .text(data.current_score.toFixed(2))
                .removeClass(data.current_score > models[$('#select_model_to_simulate').val()].parameters.threshold ? 'alert-error' : 'alert-success')
                .addClass(data.current_score > models[$('#select_model_to_simulate').val()].parameters.threshold ? 'alert-success' : 'alert-error');

        },
        error:function() {
            showMessage('fail', '<?php echo __('Failed to perform the simulation') ?>');
        },
        complete:function() {
            simulation_chart.toggleLoading(false);
            simulation_table.toggleLoading(false);
        },
        type:'get',
        cache: false,
        dataType: 'json',
        url: url,
    });
}

function refreshSimulation() {
    var $row = $('#attribute_div tr.success');
    var attribute_id = $row.find('td:first').text();
    if (attribute_id !== '') {
        doSimulation($row, attribute_id);
    }
}

function modelChangeHandler(clicked) {
    $('#select_model_to_simulate_infobox').popover('show');
    refreshSimulation();
}
</script>
