<div id="simulationContainer">
    <div style="padding: 15px; height: 90vh; display: flex; flex-direction: column;">
        <div style="height: 40%; display: flex">
            <div style="width: 30%; display: flex; flex-direction: column;">
                <div class="panel-container" style="display: flex; flex-direction: column; flex-grow: 1">
                    <ul class="nav nav-tabs" style="margin-right: -5px;" id="simulation-tabs">
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
                                    <input class="span4" type="text" placeholder="<?php echo __('Attribute ID or UUID') ?>" onkeypress="handle_input_key(event)">
                                </div>
                                <span id="performRestSearchButton" class="btn btn-primary" style="width: fit-content; margin-left: 4px;" role="button" onclick="doSpecificSearch(this)"><?php echo __('Simulate'); ?></span>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
            <div style="width: 70%; display: flex;">
                <div class="panel-container" style="flex-grow: 1;">
                    <div id="chart-decay-simulation" style="width: 100%; height: 100%;"></div>
                </div>
            </div>
        </div>
        <div style="height: 60%; overflow-y: auto; background-color: #ffffff;" class="panel-container">
            <div style="height: 100%;" id="attributeTableContainer"></div>
        </div>
    </div>
</div>

<script>
$(document).ready(function() {

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
}
</script>
