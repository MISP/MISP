<?php echo $this->Form->input('pull_rules', array('style' => 'display:none;', 'label' => false, 'div' => false)); ?>
<b><?php echo __('Filter rules'); ?>:</b><br />
<span id="pull_tags_OR" style="display:none;"><?php echo __('Events with the following tags allowed'); ?>: <span id="pull_tags_OR_text" style="color:green;"></span><br /></span>
<span id="pull_tags_NOT" style="display:none;"><?php echo __('Events with the following tags blocked'); ?>: <span id="pull_tags_NOT_text" style="color:red;"></span><br /></span>
<span id="pull_orgs_OR" style="display:none;"><?php echo __('Events with the following organisations allowed'); ?>: <span id="pull_orgs_OR_text" style="color:green;"></span><br /></span>
<span id="pull_orgs_NOT" style="display:none;"><?php echo __('Events with the following organisations blocked'); ?>: <span id="pull_orgs_NOT_text" style="color:red;"></span><br /></span>
<span id="pull_modify" class="btn btn-inverse" style="line-height:10px; padding: 4px 4px;"><?php echo __('Modify'); ?></span><br /><br />

<div id="hiddenRuleForms">
    <?php
    $pullRules = json_decode($fieldData['pull_rules'], true);
    $pullRules['url_params'] = json_decode($pullRules['url_params'], true);

    $modalData = [
        'data' => [
            'title' => __('Set PULL rules'),
            'content' => [
                [
                    'html' => sprintf('<h5 style="font-weight: normal;"><i>%s</i></h5>', __('Configure the rules to be applied when PULLing data to the server'))
                ],
                [
                    'html' => $this->element('serverRuleElements/pull', [
                        'context' =>  $this->Form->defaultModel,
                        'allTags' => $fieldData['tags'],
                        'allOrganisations' => $fieldData['orgs'],
                        'ruleObject' => $pullRules
                    ])
                ]
            ],
        ],
        'type' => 'xl',
        'class' => 'pull-rule-modal',
        'confirm' => [
            'title' => __('Update'),
            'onclick' => "serverRulesUpdateState('pull');"
        ]
    ];
    echo $this->element('genericElements/infoModal', $modalData);
    ?>
</div>

<script type="text/javascript">
    var rules = {};
    var validOptions = ['pull'];
    var validFields = ['tags', 'orgs'];
    var modelContext = '<?= h($this->Form->defaultModel) ?>';

    $(document).ready(function() {
        rules = convertServerFilterRules(rules);
        $("#pull_modify").click(function() {
            $('#genericModal.pull-rule-modal').modal()
                .on('shown', function() {
                    var $containers = $(this).find('.rules-widget-container')
                    $containers.each(function() {
                        var initFun = $(this).data('funname');
                        if (typeof window[initFun] === 'function') {
                            window[initFun]()
                        }
                    })
                    if (typeof window['cm'] === "object") {
                        window['cm'].refresh()
                    }
                })
                .on('hidden', function() {
                    var $containers = $(this).find('.rules-widget-container')
                    $containers.each(function() {
                        if ($(this).data('resetrulesfun') !== undefined) {
                            $(this).data('resetrulesfun')()
                        }
                    })
                });
        });
    });
</script>