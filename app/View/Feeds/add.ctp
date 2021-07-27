<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => $edit ? __('Edit MISP feed') : __('Add MISP Feed'),
        'description' => __('Add a new MISP feed source.'),
        'notice' => !empty(Configure::read('Security.disable_local_feed_access')) ? __('Warning: local feeds are currently disabled by policy, to re-enable the feature, set the Security.disable_local_feed_access flag to false in the server settings. This setting can only be set via the CLI.') : '',
        'fields' => [
            [
                'field' => 'enabled',
                'label' => __('Enabled'),
                'type' => 'checkbox'
            ],
            [
                'field' => 'caching_enabled',
                'label' => __('Caching enabled'),
                'type' => 'checkbox'
            ],
            [
                'field' => 'lookup_visible',
                'label' => __('Lookup visible'),
                'type' => 'checkbox'
            ],
            [
                'field' => 'name',
                'label' => __('Name'),
                'placeholder' => __('Feed name'),
                'required' => 1,
                'class' => 'form-control span6'
            ],
            [
                'field' => 'provider',
                'label' => __('Provider'),
                'placeholder' => __('Name of the content provider'),
                'required' => 1,
                'class' => 'form-control span6'
            ],
            [
                'field' => 'input_source',
                'label' => __('Input Source'),
                'options' => $dropdownData['inputSources'],
                'type' => 'dropdown',
                'class' => 'form-control span6'
            ],
            [
                'field' => 'url',
                'label' => __('URL'),
                'placeholder' => 'URL of the feed',
                'required' => 1,
                'class' => 'form-control span6'
            ],
            [
                'field' => 'source_format',
                'label' => __('Source Format'),
                'options' => $dropdownData['feedTypes'],
                'type' => 'dropdown',
                'class' => 'form-control span6'
            ],
            [
                'field' => 'headers',
                'label' => __('Any headers to be passed with requests (for example: Authorization)'),
                'class' => 'input-xxlarge',
                'type' => 'headers',
                'placeholder' => __('Line break separated list of headers in the "headername: value" format'),
                'rows' => 4,
            ],
            [
                'field' => 'orgc_id',
                'label' => __('Creator organisation'),
                'options' => $dropdownData['orgs'],
                'type' => 'dropdown',
                'div' => ['id' => 'OrgcDiv', 'style' => 'display:none', 'class' => 'optionalField'],
                'class' => 'form-control span6'
            ],
            [
                'field' => 'fixed_event',
                'label' => __('Target Event'),
                'options' => ['New Event Each Pull', 'Fixed Event'],
                'type' => 'dropdown',
                'div' => ['id' => 'TargetDiv', 'style' => 'display:none', 'class' => 'optionalField'],
                'class' => 'form-control span6'
            ],
            [
                'field' => 'target_event',
                'label' => __('Target Event ID'),
                'placeholder' => __('Leave blank unless you want to reuse an existing event.'),
                'div' => ['id' => 'TargetEventDiv', 'style' => 'display:none', 'class' => 'optionalField'],
                'class' => 'form-control span6'
            ],
            [
                'field' => 'Feed.settings.csv.value',
                'label' => __('Value field(s) in the CSV'),
                'title' => __('Select one or several fields that should be parsed by the CSV parser and converted into MISP attributes'),
                'placeholder' => __('2,3,4 (column position separated by commas)'),
                'div' => ['id' => 'settingsCsvValueDiv', 'style' => 'display:none', 'class' => 'optionalField'],
                'class' => 'form-control span6'
            ],
            [
                'field' => 'Feed.settings.csv.delimiter',
                'label' => __('Delimiter'),
                'title' => __('Set the default CSV delimiter (default = ",")'),
                'placeholder' => ',',
                'div' => ['id' => 'settingsCsvDelimiterDiv', 'style' => 'display:none', 'class' => 'optionalField'],
                'class' => 'form-control span6',
                'value' => isset($entity['Feed']['settings']['csv']['delimiter']) ? $entity['Feed']['settings']['csv']['delimiter'] : ','
            ],
            [
                'field' => 'Feed.settings.common.excluderegex',
                'label' => __('Exclusion Regex'),
                'placeholder' => __('Leave blank unless you want to reuse an existing event.'),
                'div' => ['id' => 'settingsCommonExcluderegexDiv', 'style' => 'display:none', 'class' => 'optionalField'],
                'placeholder' => __('Regex pattern, for example: "/^https://myfeedurl/i'),
                'class' => 'form-control span6'
            ],
            [
                'field' => 'publish',
                'label' => __('Auto Publish'),
                'title' => __('Publish events directly after pulling the feed - if you would like to review the event before publishing uncheck this'),
                'type' => 'checkbox',
                'div' => ['id' => 'PublishDiv', 'style' => 'display:none', 'class' => 'input checkbox optionalField']
            ],
            [
                'field' => 'override_ids',
                'label' => __('Override IDS Flag'),
                'title' => __('If checked, the IDS flags will always be set to off when pulling from this feed'),
                'type' => 'checkbox',
                'div' => ['id' => 'OverrideIdsDiv', 'style' => 'display:none', 'class' => 'input checkbox optionalField']
            ],
            [
                'field' => 'delta_merge',
                'label' => __('Delta Merge'),
                'title' => __('Merge attributes (only add new attributes, remove revoked attributes)'),
                'type' => 'checkbox',
                'div' => ['id' => 'DeltaMergeDiv', 'style' => 'display:none', 'class' => 'input checkbox optionalField']
            ],
            [
                'field' => 'distribution',
                'label' => __('Distribution'),
                'options' => $dropdownData['distributionLevels'],
                'selected' => isset($entity['Feed']['distribution']) ? $entity['Feed']['distribution'] : 3,
                'type' => 'dropdown'
            ],
            [
                'field' => 'tag_id',
                'label' => __('Default Tag'),
                'options' => $dropdownData['tags'],
                'selected' => isset($entity['Feed']['tag_id']) ? $entity['Feed']['tag_id'] : '0',
                'type' => 'dropdown',
                'searchable' => 1
            ],
            [
                'field' => 'rules',
                'label' => __('Filter rules'),
                'type' => 'pullRules',
                'tags' => $dropdownData['tags'],
                'orgs' => $dropdownData['orgs'],
                'pull_rules' => $edit ? $entity['Feed']['rules'] : $defaultPullRules
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
?>

<?php
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
?>

<script type="text/javascript">
    $(document).ready(function() {
        feedFormUpdate();
        $("#FeedSourceFormat, #FeedFixedEvent, #FeedInputSource").change(function() {
            feedFormUpdate();
        });
    });
</script>