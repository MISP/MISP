<div style="display: flex; flex-direction: column;" class="server-rule-container-push">
    <?php
        $tagAllowRules = [];
        $tagBlockRules = [];
        $orgAllowRules = [];
        $orgBlockRules = [];
        if (!empty($ruleObject)) {
            $tagAllowRules = mapIDsToObject($allTags, $ruleObject['tags']['OR']);
            $tagBlockRules = mapIDsToObject($allTags, $ruleObject['tags']['NOT']);
            $orgAllowRules = mapIDsToObject($allOrganisations, $ruleObject['orgs']['OR']);
            $orgBlockRules = mapIDsToObject($allOrganisations, $ruleObject['orgs']['NOT']);
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
    <div style="height: 50px;"></div>
</div>
