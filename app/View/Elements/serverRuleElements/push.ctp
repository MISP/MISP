<div style="display: flex; flex-direction: column;" class="server-rule-container-push">
    <?php
        $tagAllowRules = [];
        $tagBlockRules = [];
        $orgAllowRules = [];
        $orgBlockRules = [];
        $attributeTypeBlockRules = [];
        $objectTypeBlockRules = [];
        if (!empty($ruleObject)) {
            $tagAllowRules = mapIDsToObject($allTags, $ruleObject['tags']['OR']);
            $tagBlockRules = mapIDsToObject($allTags, $ruleObject['tags']['NOT']);
            $orgAllowRules = mapIDsToObject($allOrganisations, $ruleObject['orgs']['OR']);
            $orgBlockRules = mapIDsToObject($allOrganisations, $ruleObject['orgs']['NOT']);
            $attributeTypeBlockRules = !empty($ruleObject['type_attributes']['NOT']) ? $ruleObject['type_attributes']['NOT'] : [];
            $objectTypeBlockRules = !empty($ruleObject['type_objects']['NOT']) ? $ruleObject['type_objects']['NOT'] : [];
        }
        function mapIDsToObject($data, $ids) {
            $result = [];
            foreach ($ids as $i => $id) {
                foreach ($data as $j => $entry) {
                    if ($id == $entry['id']) {
                        $result[] = $entry;
                        unset($data[$j]);
                        unset($ids[$i]);
                        break;
                    }
                }
            }
            foreach ($ids as $freetextValue) {
                $result[] = [
                    'name' => $freetextValue,
                    'id' => $freetextValue
                ];
            }
            return $result;
        }
    ?>
    <?php
        echo $this->element('serverRuleElements/rules_widget', [
            'scope' => 'tag',
            'scopeI18n' => __('tag'),
            'technique' => 'push',
            'options' => $allTags,
            'initAllowOptions' => $tagAllowRules,
            'initBlockOptions' => $tagBlockRules
        ]);
    ?>

    <div style="display: flex;">
        <h4 class="bold green" style=""><?= __('AND');?></h4>
        <h4 class="bold red" style="margin-left: auto;"><?= __('AND NOT');?></h4>
    </div>

    <?php
        echo $this->element('serverRuleElements/rules_widget', [
            'scope' => 'org',
            'scopeI18n' => __('org'),
            'technique' => 'push',
            'options' => $allOrganisations,
            'initAllowOptions' => $orgAllowRules,
            'initBlockOptions' => $orgBlockRules,
            'disableFreeText' => true
        ]);
    ?>

    <?php
    if (!empty(Configure::read('MISP.enable_synchronisation_filtering_on_type'))) {
        echo $this->element('serverRuleElements/rules_filtering_type', [
            'technique' => 'push',
            'allowEmptyOptions' => true,
            'allAttributeTypes' => $allAttributeTypes,
            'attributeTypeBlockRules' => $attributeTypeBlockRules,
            'allObjectTypes' => $allObjectTypes,
            'objectTypeBlockRules' => $objectTypeBlockRules,
        ]);
    }
    ?>
    <div style="height: 50px;"></div>
</div>

<script>
    var pullRemoteRules404Error = '<?= __('Connection error or the remote version is not supporting remote filter lookups (v2.4.142+). Make sure that the remote instance is accessible and that it is up to date.') ?>'
    var cm;
    $(function() {
        var serverID = "<?= isset($id) ? $id : '' ?>"
        <?php if (empty($attributeTypeBlockRules) && empty($objectTypeBlockRules)) : ?>
            $('div.server-rule-container-push .type-filtering-subcontainer').hide()
        <?php else : ?>
            $('div.server-rule-container-push #type-filtering-cb').prop('checked', true)
            $('div.server-rule-container-push #type-filtering-notice-cb').prop('checked', true)
            $('div.server-rule-container-push .type-filtering-container').show()
        <?php endif; ?>
    })
</script>