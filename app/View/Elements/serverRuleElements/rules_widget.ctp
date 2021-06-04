<?php 
$seed = rand();
$pickerDisplayed = false;
?>
<div>
    <div style="display: flex;" class="rules-widget-container container-seed-<?= $seed ?> scope-<?= Inflector::pluralize(h($scope)) ?>" data-funname="initRuleWidgetPicker<?= $seed ?>">
        <div style="flex-grow: 1;">
            <div class="bold green" style="display: flex; align-items: center;">
                <?= __('Allowed %s (OR)', Inflector::pluralize(h($scopeI18n)));?>
                <i
                    class="useCursorPointer <?= $this->FontAwesome->getClass('trash') ?>"
                    style="margin-left: auto;"
                    title="<?= __('Delete selected rules') ?>"
                    onClick="<?= sprintf("handleDeleteButtonClick('%s', this); ", 'rules-allow') ?>"
                ></i>
            </div>
            <select
                id="<?= sprintf('%s%sLeftValues', Inflector::pluralize(h($scope)), h($technique)) ?>"
                size="6" multiple
                style="margin-bottom: 0;  width: 100%; overflow-x: auto;" class="rules-select-data rules-allow"
            >
                <?php foreach($initAllowOptions as $option): ?>
                    <?php if(is_array($option)): ?>
                        <option value="<?= !empty($optionNoValue) ? h($option['name']) : h($option['id']) ?>"><?= h($option['name']) ?></option>
                    <?php else: ?>
                        <option value="<?= h($option) ?>"><?= h($option) ?></option>
                    <?php endif; ?>
                <?php endforeach; ?>
            </select>
        </div>
        <div style="display: flex; margin: 0 0.5em; flex-shrink: 1; padding-top: 20px;">
            <div style="display: flex; flex-direction: column;">
                <?php if(!empty($options) || $allowEmptyOptions): ?>
                    <?php $pickerDisplayed = true; ?>
                    <div class="input-prepend input-append">
                        <button
                            class="btn"
                            type="button"
                            title="<?= __('Move %s to the list of %s to allow', h($scopeI18n), Inflector::pluralize(h($scopeI18n)));?>"
                            aria-label="<?= __('Move %s to the list of %s to allow', h($scopeI18n), Inflector::pluralize(h($scopeI18n)));?>"
                            role="button" tabindex="0"
                            onClick="<?= sprintf("handlePickerButtonClick('%s', this); ", 'rules-allow') ?>"
                        >
                        <i class="<?= $this->FontAwesome->getClass('caret-left') ?>"></i>
                        </button>
                        <select
                            class="rules-select-picker rules-select-picker-<?= h($scope) ?>"
                            multiple
                            placeholder="<?= sprintf('%s name', h($scopeI18n)) ?>"
                        >
                            <?php foreach($options as $option): ?>
                                <?php if(is_array($option)): ?>
                                    <option value="<?= !empty($optionNoValue) ? h($option['name']) : h($option['id']) ?>"><?= h($option['name']) ?></option>
                                <?php else: ?>
                                    <option value="<?= h($option) ?>"><?= h($option) ?></option>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        </select>
                        <button
                            class="btn"
                            type="button"
                            title="<?= __('Move %s to the list of %s to block', h($scopeI18n), Inflector::pluralize(h($scopeI18n)));?>"
                            aria-label="<?= __('Move %s to the list of %s to block', h($scopeI18n), Inflector::pluralize(h($scopeI18n)));?>"
                            role="button" tabindex="0"
                            onClick="<?= sprintf("handlePickerButtonClick('%s', this); ", 'rules-block') ?>"
                        >
                            <i class="<?= $this->FontAwesome->getClass('caret-right') ?>"></i>
                        </button>
                    </div>
                <?php endif; ?>
                <?php if(!isset($disableFreeText) || !$disableFreeText): ?>
                    <?php if ($pickerDisplayed): ?>
                        <a
                            data-toggle="collapse" data-target="#collapse-freetext-<?= h($scope) ?>-<?= $seed ?>"
                            class="text-left useCursorPointer freetext-button-toggle-<?= h($scope) ?>"
                            title="<?= __('This text input allows you to add custom values to the rules') ?>"
                        >
                            <i class="fas fa-caret-down fa-rotate"></i>
                            <?= __('Show freetext input') ?>
                        </a>
                    <?php endif; ?>
                    <div
                        id="collapse-freetext-<?= h($scope) ?>-<?= $seed ?>"
                        class="collapse collapse-freetext-<?= h($scope) ?>"
                    >
                        <div class="input-prepend input-append" style="margin: 1px;">
                            <button
                                class="btn"
                                type="button"
                                title="<?= __('Move %s to the list of %s to allow', h($scopeI18n), Inflector::pluralize(h($scopeI18n)));?>"
                                aria-label="<?= __('Move %s to the list of %s to allow', h($scopeI18n), Inflector::pluralize(h($scopeI18n)));?>"
                                role="button" tabindex="0"
                                onClick="<?= sprintf("handleFreetextButtonClick('%s', this); ", 'rules-allow') ?>"
                            >
                            <i class="<?= $this->FontAwesome->getClass('caret-left') ?>"></i>
                            </button>
                            <input type="text" style="" placeholder="<?= sprintf('Freetext %s name', h($scopeI18n)) ?>">
                            <button
                                class="btn"
                                type="button"
                                title="<?= __('Move %s to the list of %s to block', h($scopeI18n), Inflector::pluralize(h($scopeI18n)));?>"
                                aria-label="<?= __('Move %s to the list of %s to block', h($scopeI18n), Inflector::pluralize(h($scopeI18n)));?>"
                                role="button" tabindex="0"
                                onClick="<?= sprintf("handleFreetextButtonClick('%s', this); ", 'rules-block') ?>"
                            >
                                <i class="<?= $this->FontAwesome->getClass('caret-right') ?>"></i>
                            </button>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <div style="flex-grow: 1;">
            <div class="bold red" style="display: flex; align-items: center;">
                <?php echo __('Blocked %s (AND NOT)', Inflector::pluralize(h($scopeI18n)));?>
                <i
                    class="useCursorPointer <?= $this->FontAwesome->getClass('trash') ?>"
                    style="margin-left: auto;"
                    title="<?= __('Delete selected rules') ?>"
                    onClick="<?= sprintf("handleDeleteButtonClick('%s', this); ", 'rules-block') ?>"
                ></i>
            </div>
            <select
                id="<?= sprintf('%s%sRightValues', Inflector::pluralize(h($scope)), h($technique)) ?>"
                size="6" multiple
                style="margin-bottom: 0; width: 100%; overflow-x: auto;" class="rules-select-data rules-block"
            >
                <?php foreach($initBlockOptions as $option): ?>
                    <?php if(is_array($option)): ?>
                        <option value="<?= !empty($optionNoValue) ? h($option['name']) : h($option['id']) ?>"><?= h($option['name']) ?></option>
                    <?php else: ?>
                        <option value="<?= h($option) ?>"><?= h($option) ?></option>
                    <?php endif; ?>
                <?php endforeach; ?>
            </select>
        </div>
    </div>
</div>

<script>
function initRuleWidgetPicker<?= $seed ?>() {
    var $baseContainer = $('.container-seed-<?= $seed ?>');
    $baseContainer.find('select.rules-select-picker').chosen({
        placeholder_text_multiple: "<?= __('Select some %s', Inflector::humanize(Inflector::pluralize(h($scopeI18n)))); ?>"
    })
    $baseContainer.find('select.rules-select-data').keydown(function(evt) {
        var $select = $(this)
        var $pickerSelect = $select.closest('.rules-widget-container').find('select.rules-select-picker')
        if (evt.keyCode === 46) { // <DELETE>
            deleteSelectedRules($select, $pickerSelect)
        }
    });
    rebuildRules($baseContainer)
    $baseContainer.data('initial-rules-allow', $baseContainer.find('.rules-allow').children())
    $baseContainer.data('initial-rules-block', $baseContainer.find('.rules-block').children())
    $baseContainer.data('resetrulesfun', function() {
        $baseContainer.find('.rules-allow').empty().append(
            $baseContainer.data('initial-rules-allow')
        )
        $baseContainer.find('.rules-block').empty().append(
            $baseContainer.data('initial-rules-block')
        )
    })
}

function deleteSelectedRules($select, $pickerSelect) {
    $select.find(":selected").each(function() {
        var $item = $(this)
        if (!getValuesFromSelect($pickerSelect).includes($item.val())) {
            $pickerSelect.append($('<option/>', {
                value: $item.val(),
                text : $item.text()
            }))
        }
        $item.remove()
    })
    $pickerSelect.trigger('chosen:updated')
    rebuildRules($select.closest('.rules-widget-container'))
}

function handleDeleteButtonClick(targetClass, clicked) {
    var $select = $(clicked).closest('.rules-widget-container').find('select.' + targetClass)
    var $pickerSelect = $select.closest('.rules-widget-container').find('select.rules-select-picker')
    deleteSelectedRules($select, $pickerSelect)
}

function handleFreetextButtonClick(targetClass, clicked) {
    var $target = $(clicked).closest('.rules-widget-container').find('select.' + targetClass)
    var $input = $(clicked).parent().find('input');
    addItemToSelect($target, $input.val())
    $input.val('')
}

function handlePickerButtonClick(targetClass, clicked) {
    var $select = $(clicked).parent().find('select');
    var values = $select.val()
    $select.children().each(function() {
        if (values.includes($(this).val())) {
            var $target = $select.closest('.rules-widget-container').find('select.' + targetClass)
            moveItemToSelect($target, $(this))
        }
    });
    $select.trigger('chosen:updated')
}

function moveItemToSelect($target, $source) {
    if (!getValuesFromSelect($target).includes($source.val())) {
        $target.append($('<option/>', {
            value: $source.val(),
            text : $source.text()
        }));
    }
    $source.remove()
    rebuildRules($target.closest('.rules-widget-container'))
}

function addItemToSelect($target, data) {
    if (!getValuesFromSelect($target).includes(data)) {
        $target.append($('<option/>', {
            value: data,
            text : data
        }));
    }
    rebuildRules($target.closest('.rules-widget-container'))
}

function getValuesFromSelect($select) {
    var values = []
    $select.find('option').each(function() {
        values.push($(this).val())
    })
    return values
}

function rebuildRules($ruleContainer) {
    var tmpRules = {}
    var $selectAllow = $ruleContainer.find('select.rules-allow')
    var $selectBlock = $ruleContainer.find('select.rules-block')
    tmpRules['OR'] = getValuesFromSelect($selectAllow)
    tmpRules['NOT'] = getValuesFromSelect($selectBlock)
    $ruleContainer.data('rules', tmpRules)
}
</script>

<style>
.rules-widget-container.container-seed-<?= $seed ?> .chosen-container .chosen-drop {
    width: fit-content;
    border-top: 1px solid #aaa;
}

.rules-widget-container.container-seed-<?= $seed ?> .chosen-container .search-choice > span {
    white-space: normal;
}
</style>