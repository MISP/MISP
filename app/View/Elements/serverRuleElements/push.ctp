<div style="display: flex; flex-direction: column;" class="server-rule-container-push">
    <?php
        echo $this->element('serverRuleElements/rules_widget', [
            'scope' => 'tag',
            'scopeI18n' => __('tag'),
            'technique' => 'push',
            'options' => $allTags
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
            'options' => $allOrganisations
        ]);
    ?>
    <div style="height: 50px;"></div>
</div>
