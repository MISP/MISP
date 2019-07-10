<div class="view">

<h2>Decaying Of Indicator Fine Tuning Tool</h2>

<div class="row">
    <div class="span9 form-inline" style="border: 1px solid #ddd; border-radius: 4px; margin-bottom: 15px;">
        <div style="border-bottom: 1px solid #ddd;">
            <label class="checkbox inline">
                <input id="table_toggle_all_type" type="checkbox"></input>
                <?php echo __('Show All Types'); ?>
            </label>
            <label class="checkbox inline">
                <input id="table_toggle_objects" type="checkbox"></input>
                <?php echo __('Show MISP Objects'); ?>
            </label>
            <input id="table_type_search" class="input" style="width: 250px; margin-left: 5px;" type="text" placeholder="<?php echo _('Search Attribute Type'); ?>"></input>
            <div style="position: relative; display: inline-block">
                <button class="btn btn-primary btn-small" onclick="decayingTool.restoreSelection()"><span class="fa fa-history"></span></button>
            </div>
        </div>
        <div style="height: calc(100vh - 175px - 25px); overflow-y: scroll;">
            <table id="table_attribute_type" class="table table-striped table-bordered">
                <thead>
                    <tr>
                        <th><input id="checkAll" type="checkbox" title="<?php echo __('Check all'); ?>"></input></th>
                        <th><?php echo _('Attribute Type'); ?></th>
                        <th><?php echo _('Category'); ?></th>
                        <th><?php echo _('Model ID'); ?></th>
                    </tr>
                </thead>
                <tbody id="attributeTypeTableBody">
                    <?php foreach ($types as $type => $info): ?>
                        <?php
                        $class = 'hidden ';
                        if (isset($info['isObject']) && $info['isObject']) {
                            $class .= 'isObject';
                        } else if (isset($info['to_ids']) && $info['to_ids'] != 1) {
                            $class .= 'isNotToIDS';
                        } else {
                            $class = "";
                        }
                        ?>
                        <tr class="<?php echo $class; ?>">
                            <td><input type="checkbox"></input></td>
                            <td class="useCursorPointer isFilteringField isAttributeTypeField">
                                <?php if(isset($info['isObject']) && $info['isObject']): ?>
                                    <it class="fa fa-cube" title="<?php echo __('Belong to a MISP Object'); ?>"></it>
                                <?php endif; ?>
                                <span title="<?php echo isset($info['desc']) ? $info['desc'] : ''; ?>"><?php echo h($type); ?></span>
                                <?php if(isset($info['to_ids']) && $info['to_ids'] == 1): ?>
                                    <it class="fa fa-flag fa-pull-right" title="<?php echo __('To IDS flag set'); ?>"></it>
                                <?php endif; ?>
                            </td>
                            <td class="useCursorPointer isFilteringField"><?php echo is_array($info['default_category']) ? implode('</br>', h($info['default_category'])) : h($info['default_category']); ?></td>
                            <td class="isFilteringField isModelIdField">
                                <?php if (isset($associated_models[$type])): ?>
                                    <?php foreach ($associated_models[$type] as $id): ?>
                                        <a href="#" onclick="$('#modelId_<?php echo h($id); ?>').find('.decayingLoadBtn').click();"><?php echo h($id); ?></a>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <div class="span12">
        <div class="span10" style="border: 1px solid #ddd; border-radius: 4px; margin-bottom: 20px;">
            <div id="decayGraph" style="width: 100%;"></div>
        </div>
        <div class="row">
            <div class="span6" style="margin-bottom: 20px;">
                <?php foreach ($parameters as $param => $config): ?>
                    <div class="input-prepend input-append">
                        <span class="add-on param-name" data-toggle="tooltip" data-placement="left" style="min-width: 100px;" title="<?php echo isset($config['info']) ? h($config['info']) : ''?>">
                            <?php echo h($config['name']) . (isset($config['greek']) ? ' <strong>'.h($config['greek']).'</strong>' : ''); ?>
                        </span>
                        <input id="input_<?php echo h($param); ?>" class="input-mini" type="number" min=0 step=<?php echo h($config['step']); ?> value=<?php echo h($config['value']); ?> oninput="refreshGraph(this);" ></input>
                        <span class="add-on"><input id="input_<?php echo h($param); ?>_range" type="range" min=0 <?php echo isset($config['max']) ? 'max=' . $config['max'] : '' ?> step=<?php echo h($config['step']); ?> value=<?php echo h($config['value']); ?> oninput="$('#input_<?php echo h($param); ?>').val(this.value).trigger('input');"></input></span>
                        <?php if (isset($config['unit'])): ?>
                            <span class="add-on"><?php echo h($config['unit']); ?></span>
                        <?php endif; ?>

                    </div>
                <?php endforeach; ?>
                <div class="input-append" style="margin-bottom: 0px;">
                    <input id="input_base_score_config" class="hidden" value="[]"></input>
                    <button class="btn btn-primary" style="border-radius: 4px 0px 0px 4px;" onclick="decayingTool.toggleBasescoreForm()">
                        <span class="fa fa-tags"> <?php echo __('Adjust base  score'); ?></span>
                    </button>
                    <span id="summary_base_score_config" class="add-on param-name">
                        <span class="far fa-square"></span>
                    </span>
                </div>
                <div style="display: inline-block; margin-left: 10px;">
                    <button id="button-toggle-simulation" class="btn btn-primary" data-modelid="" onclick="decayingTool.toggleSimulation($(this).data('modelid'))">
                        <span class="fa fa-chart-line"> <?php echo __('Toggle simulation panel'); ?></span>
                    </button>
                </div>
            </div>
            <div class="span6">
                <table class="table table-striped table-bordered">
                    <tbody>
                        <tr>
                            <td>Expire after (lifetime)</td>
                            <td id="infoCellExpired"></td>
                        </tr>
                        <tr>
                            <td>Score halved after (Half-life)</td>
                            <td id="infoCellHalved"></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="row">
            <div class="span12">
                <form id="saveForm" class="form-inline">
                    <input type="text" name="name" class="input" placeholder="Model name" required>
                    <textarea  rows="1" name="description" class="input" placeholder="Description"></textarea>
                    <span class="btn btn-success" data-save-type="add" onclick="decayingTool.saveModel(this)"><i class="fa fa-save"> Save</i></span>
                </form>
            </div>
        </div>

        <div class="row">
            <div class="span12">
                <table class="table table-striped table-bordered">
                    <thead>
                        <tr>
                            <th rowspan="2">ID</th>
                            <th rowspan="2">Model Name</th>
                            <th rowspan="2">Org id</th>
                            <th rowspan="2">Description</th>
                            <th colspan="4">Parameters</th>
                            <th rowspan="2"># Types</th>
                            <th rowspan="2">Action</th>
                        </tr>
                        <tr>
                            <th>Tau</th>
                            <th>Delta</th>
                            <th>Threshold</th>
                            <th>Basescore config</th>
                        </tr>
                    </thead>
                    <tbody id="modelTableBody">
                        <?php foreach ($savedModels as $k => $model): ?>
                            <tr id="modelId_<?php echo h($model['DecayingModel']['id']); ?>">
                                <td class="DMId"><a href="<?php echo $baseurl; ?>/decayingModel/view/<?php echo h($model['DecayingModel']['id']); ?>"><?php echo h($model['DecayingModel']['id']); ?></a></td>
                                <td class="DMName"><?php echo h($model['DecayingModel']['name']); ?></td>
                                <td class="DMOrg"><?php echo $this->OrgImg->getOrgImg(array('name' => $model['DecayingModel']['org_id'], 'size' => 24)); ?> </td>
                                <td class="DMDescription"><?php echo h($model['DecayingModel']['description']); ?></td>
                                <td class="DMParameterTau"><?php echo h($model['DecayingModel']['parameters']['tau']); ?></td>
                                <td class="DMParameterDelta"><?php echo h($model['DecayingModel']['parameters']['delta']); ?></td>
                                <td class="DMParameterThreshold"><?php echo h($model['DecayingModel']['parameters']['threshold']); ?></td>
                                <td class="DMParameterBasescoreConfig json-transform" data-basescoreconfig="<?php echo base64_encode(json_encode($model['DecayingModel']['parameters']['base_score_config'])); ?>">
                                    <?php if (isset($model['DecayingModel']['parameters']['base_score_config']) && !empty($model['DecayingModel']['parameters']['base_score_config'])): ?>
                                        <?php echo h(json_encode($model['DecayingModel']['parameters']['base_score_config'])); ?>
                                    <?php endif; ?>
                                </td>
                                <td class="DMNumType"><?php echo isset($associated_types[$model['DecayingModel']['id']]) ? count($associated_types[$model['DecayingModel']['id']]) : 0; ?></td>
                                <td>
                                    <button class="btn btn-info btn-small decayingLoadBtn" onclick="decayingTool.loadModel(this);"><span class="fa fa-line-chart"><?php echo __(' Load model') ?></span></button>
                                    <button class="btn btn-danger btn-small" data-save-type="edit" data-model-id="<?php echo h($model['DecayingModel']['id']); ?>" onclick="decayingTool.saveModel(this);"><span class="fa fa-paste"><?php echo __(' Overwrite model') ?></span></button>
                                    <button class="btn btn-success btn-small" onclick="decayingTool.activate(this);" title="<?php echo __(' Activate the model to selected attribute type') ?>"><span class="fa fa-upload"><?php echo __(' Activate') ?></span></button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</div>

</div>

<?php echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'decayingTool')); ?>
<?php echo $this->Html->script('Chart.min'); ?>
<?php echo $this->Html->script('d3'); ?>
<?php echo $this->Html->script('DecayingTool'); ?>

<script>
$(document).ready(function() {
    $('.json-transform').each(function(i) {
        var text = $(this).text().trim();
        var parsedJson = ''
        if (text !== '') {
            parsedJson = jsonToNestedTable(text, [], ['table', 'table-condensed', 'table-bordered']);
        }
        $(this).html(parsedJson);
    });
});
</script>
