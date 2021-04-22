<div style="display: flex; flex-direction: column;" class="server-rule-container-push">
    <?php
        $tagAllowRules = [];
        $tagBlockRules = [];
        $orgAllowRules = [];
        $orgBlockRules = [];
        if (!empty($server['Server']['push_rules'])) {
            $tagRules = json_decode($server['Server']['push_rules'], true);
            $tagAllowRules = mapIDsToObject($allTags, $tagRules['tags']['OR']);
            $tagBlockRules = mapIDsToObject($allTags, $tagRules['tags']['NOT']);
            $orgAllowRules = mapIDsToObject($allOrganisations, $tagRules['orgs']['OR']);
            $orgBlockRules = mapIDsToObject($allOrganisations, $tagRules['orgs']['NOT']);
        }
        function mapIDsToObject($data, $ids) {
            $result = [];
            foreach ($ids as $id) {
                foreach ($data as $i => $entry) {
                    if ($id == $entry['id']) {
                        $result[] = $entry;
                        unset($data[$i]);
                        break;
                    }
                }
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
            'initBlockOptions' => $orgBlockRules
        ]);
    ?>
    <div style="height: 50px;"></div>
</div>
