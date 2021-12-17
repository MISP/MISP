<div id="eventreport_div">
    <span class="report-title-section">
        <label class="checkbox">
            <input id="type-filtering-cb" type="checkbox" onclick="$('div.server-rule-container-<?= $technique ?> .type-filtering-container').toggle()"><?= __('Type filtering') ?>
        </label>
    </span>
    <div class="type-filtering-container hidden">
        <div class="alert alert-error">
            <button type="button" class="close" data-dismiss="alert">&times;</button>
            <strong><?= __('Warning!') ?></strong>
            <?= __('Use this feature only if you know exactly what you are doing as it might introduce unwanted behaviour:') ?>
            <ul>
                <li><?= __('This instance will potentially receive incomplete events (missing the filtered-out types)') ?></li>
                <li><?= __('If later on you were to decide to have the previously filtered types included, the only way for this instance to receive them is to completely delete the affected events, as a full sync is needed') ?></li>
                <li><?= __('Any instances synchronising with this instances will also receive incomplete events') ?></li>
            </ul>
            <strong><?= __('Any instance being synchronised with this one will also be affected by these shortcomings!') ?></strong>
            <label class="checkbox">
                <input id="type-filtering-notice-cb" type="checkbox" onclick="$('div.server-rule-container-<?= $technique ?> .type-filtering-subcontainer').toggle()"><?= __('I understand the caveats mentioned above resulting from the use of these filters') ?>
            </label>
        </div>
        <div class="type-filtering-subcontainer" style="display: flex; flex-direction: column;">
            <div style="display: flex;">
                <h4 class="bold green" style=""></h4>
                <h4 class="bold red" style="margin-left: auto;"><?= __('AND NOT'); ?></h4>
            </div>
            <?php
            echo $this->element('serverRuleElements/rules_widget', [
                'scope' => 'type_attributes',
                'scopeI18n' => __('Attribute Types'),
                'technique' => $technique,
                'allowEmptyOptions' => true,
                'options' => $allAttributeTypes,
                'optionNoValue' => true,
                'initAllowOptions' => [],
                'initBlockOptions' => $attributeTypeBlockRules,
                'disableAllow' => true,
                'disableFreeText' => true,
            ]);
            ?>
            <?php
            echo $this->element('serverRuleElements/rules_widget', [
                'scope' => 'type_objects',
                'scopeI18n' => __('Object Types'),
                'technique' => $technique,
                'allowEmptyOptions' => true,
                'options' => $allObjectTypes,
                'optionNoValue' => false,
                'initAllowOptions' => [],
                'initBlockOptions' => $objectTypeBlockRules,
                'disableAllow' => true,
                'disableFreeText' => true,
            ]);
            ?>
        </div>
    </div>
</div>
