<div class="view">
    <h2>Decaying Of Indicator Fine Tuning Tool</h2>

    <div class="row">
        <div class="span9 form-inline" style="border: 1px solid #ddd; border-radius: 4px; margin-bottom: 15px;">
            <div style="border-bottom: 1px solid #ddd;">
                <label class="checkbox inline">
                    <input id="table_toggle_all_type" type="checkbox">
                    <?php echo __('Show All Types'); ?>
                </label>
                <label class="checkbox inline">
                    <input id="table_toggle_objects" type="checkbox">
                    <?php echo __('Show MISP Objects'); ?>
                </label>
                <input id="table_type_search" class="input" type="text" placeholder="<?php echo __('Search Attribute Type'); ?>">
                <button class="btn btn-primary btn-small" onclick="decayingTool.restoreSelection()"><span class="fa fa-history"></span></button>
            </div>
            <div class="AttributeTypeTableContainer">
                <table id="table_attribute_type" class="table table-striped table-bordered">
                    <thead>
                        <tr>
                            <th><input id="checkAll" type="checkbox" title="<?php echo __('Check all'); ?>"></th>
                            <th><?php echo __('Attribute Type'); ?></th>
                            <th><?php echo __('Category'); ?></th>
                            <th><?php echo __('Model ID'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="attributeTypeTableBody">
                        <?php foreach ($types as $type => $info): ?>
                            <?php
                                $class = 'hidden ';
                                if (
                                    isset($info['isObject']) && $info['isObject'] &&
                                    !(isset($info['isAttribute']) && $info['isAttribute'])
                                ) {
                                    $class .= 'isObject';
                                } else if (isset($info['to_ids']) && $info['to_ids'] != 1) {
                                    $class .= 'isNotToIDS';
                                } else {
                                    $class = "";
                                }
                            ?>
                            <tr class="<?php echo $class; ?>">
                                <td><input type="checkbox"></td>
                                <td class="useCursorPointer isFilteringField isAttributeTypeField">
                                    <?php if(isset($info['isObject']) && $info['isObject'] && !(isset($info['isAttribute']) && $info['isAttribute'])): ?>
                                        <it class="fa fa-cube" title="<?php echo __('Belong to a MISP Object'); ?>"></it>
                                    <?php endif; ?>
                                    <span title="<?php echo isset($info['desc']) ? h($info['desc']) : ''; ?>"><?php echo h($type); ?></span>
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
            <div style="margin-bottom: 10px;">
                <select id="formulaSelectPicker" style="margin: 0px;">
                    <?php foreach ($available_formulas as $formula_name => $formula_data): ?>
                        <option value="<?php echo h($formula_name); ?>" data-extends="<?php echo h($formula_data['parent_class']); ?>" title="<?php echo h($formula_data['description']); ?>"><?php echo h($formula_name); ?></option>
                    <?php endforeach; ?>
                </select>
                <i id="formulaSelectPickerHelpText" class="fas fa-question-circle"></i>
            </div>
            <div id="containerFormulaSetting">
                <div class="span10 settings polynomial" style="border: 1px solid #ddd; border-radius: 4px; margin-bottom: 20px;">
                    <div id="decayGraph" style="width: 100%;"></div>
                </div>
                <div class="row">
                    <div class="span6" style="margin-bottom: 20px;">
                        <?php foreach ($parameters as $param => $config): ?>
                            <div class="input-prepend input-append settings polynomial <?php echo $param == 'threshold' ? 'sightings' : ''; ?>">
                                <span class="add-on param-name" data-toggle="tooltip" data-placement="left" style="min-width: 100px;" title="<?php echo isset($config['info']) ? h($config['info']) : ''?>">
                                    <?php echo h($config['name']) . (isset($config['greek']) ? ' <strong>' . h($config['greek']).'</strong>' : ''); ?>
                                </span>
                                <input id="input_<?php echo h($param); ?>" class="input-mini" type="number" min=0 step=<?php echo h($config['step']); ?> value=<?php echo h($config['value']); ?> max=<?php echo isset($config['max']) ? h($config['max']) : ''; ?> oninput="$('#input_<?php echo h($param); ?>_range').val(this.value); refreshGraph(this); ">
                                <span class="add-on"><input id="input_<?php echo h($param); ?>_range" type="range" min=0 <?php echo isset($config['max']) ? 'max=' . h($config['max']) : '' ?> step=<?php echo h($config['step']); ?> value=<?php echo h($config['value']); ?> oninput="$('#input_<?php echo h($param); ?>').val(this.value).trigger('input');"></span>
                                <?php if (isset($config['unit'])): ?>
                                    <span class="add-on"><?php echo h($config['unit']); ?></span>
                                <?php endif; ?>

                            </div>
                        <?php endforeach; ?>
                        <input id="input_default_base_score" value=0 class="hidden">
                        <div class="input-append settings polynomial sightings" style="margin-bottom: 0px;">
                            <input id="input_base_score_config" class="hidden" value="[]">
                            <button class="btn btn-primary" style="border-radius: 4px 0px 0px 4px;" onclick="decayingTool.toggleBasescoreForm()">
                                <span class="fa fa-tags"> <?php echo __('Adjust base  score'); ?></span>
                            </button>
                            <span id="summary_base_score_config" class="add-on param-name">
                                <span class="far fa-square"></span>
                            </span>
                        </div>
                        <div class="settings polynomial sightings" style="display: inline-block; margin-left: 10px;">
                            <a id="button-toggle-simulation" target="_blank" class="btn btn-primary" href="" onclick="return !$(this).hasClass('disabled');">
                                <span class="fa fa-chart-line"> <?php echo __('Simulate this model'); ?></span>
                            </a>
                        </div>
                    </div>
                    <div class="span6 settings polynomial">
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
                <div class="span6 settings other sightings hidden">
                  <textarea id="textarea_other_settings_formulas" style="width: 430px;" rows="5" placeholder="<?php echo(__('Model\'s Settings')); ?>"></textarea>
                </div>
            </div>

            <div class="row">
                <div class="span12">
                    <form id="saveForm" class="form-inline">
                        <input type="text" name="name" class="input" placeholder="Model name" required>
                        <textarea  rows="1" name="description" class="input" placeholder="Description"></textarea>
                        <span id="save-model-button" class="btn btn-success" data-save-type="add" onclick="decayingTool.saveModel(this)" data-modelid="0" data-isedit="0" data-edittext="<?php echo __("Edit") ?>" data-savetext="<?php echo __("Create") ?>"><i class="fa fa-plus"> <?php echo __("Create") ?></i></span>
                    </form>
                </div>
            </div>

            <div class="row">
                <div class="span12">
                    <span class="tableRadioFilterOptionsContainer">
                        <label class="radio inline">
                            <input type="radio" id="tableRadioFilterAll" name="tableRadioFilterOptions" value="all" checked><?php echo __('All available models');?>
                        </label>
                        <label class="radio inline">
                            <input type="radio" id="tableRadioFilterMy" name="tableRadioFilterOptions" value="my_models"><?php echo __('My models'); ?>
                        </label>
                        <label class="radio inline">
                            <input type="radio" id="tableRadioFilterDefault" name="tableRadioFilterOptions" value="default_models"><?php echo __('Default models'); ?>
                        </label>
                    </span>
                    <table id="table-model" class="table table-striped table-bordered">
                        <thead id="table-model-head"></thead>
                        <tbody id="table-model-body"></tbody>
                    </table>
                </div>
            </div>

        </div>
    </div>
</div>

<?php echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'decayingModel', 'menuItem' => 'decayingTool')); ?>
<?php
    echo $this->element('genericElements/assetLoader', array(
        'css' => array('decayingTool'),
        'js' => array('d3', 'Chart.min', 'decayingTool', 'jquery-ui.min')
    ));
?>

<script>
var logged_user_org_id = <?php echo h($me['org_id']); ?>;
$(document).ready(function() {
    $('.json-transform').each(function(i) {
        var text = $(this).text().trim();
        var parsedJson = ''
        if (text !== '') {
            parsedJson = jsonToNestedTable(text, [], ['table', 'table-condensed', 'table-bordered']);
        }
        $(this).html(parsedJson);
    });

    $('#formulaSelectPicker').change(function() {
        toggleContainer();
    })

    $('#formulaSelectPickerHelpText').tooltip({
        title: function() {
            return $('#formulaSelectPicker > option:selected').attr('title');
        },
        placement: 'right'
    });

});
function toggleContainer() {
    $('.settings').hide();

    var $option = $('#formulaSelectPicker').find('option:selected');
    if ($option.data('extends') == 'Polynomial') {
        $('.settings.polynomial').show();
    } else if ($option.data('extends') == 'Sightings') {
        $('.settings.sightings').show();
    } else {
        $('.settings.other').show();
    }
}
</script>
