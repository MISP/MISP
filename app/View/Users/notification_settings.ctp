<?php
echo $this->element('genericElements/Form/genericForm', [
    'data' => [
        'title' => __('Notification settings'),
        'fields' => [
            [
                'field' => 'notification_daily',
                'label' => __('Subscribe to daily notifications'),
                'default' => 0,
                'type' => 'checkbox'
            ],
            [
                'field' => 'notification_weekly',
                'label' => __('Subscribe to weekly notifications'),
                'default' => 0,
                'type' => 'checkbox'
            ],
            [
                'field' => 'notification_monthly',
                'label' => __('Subscribe to monthly notifications'),
                'default' => 0,
                'type' => 'checkbox'
            ],
            sprintf('<h4>%s</h4>', __('Notification filters')),
            [
                'field' => 'periodic_settings.orgc_id',
                'label' => __('Creator organisation'),
                'class' => 'span6',
                'options' => $orgs,
                'type' => 'dropdown',
                'multiple' => true,
                'picker' => true,
            ],
            [
                'field' => 'periodic_settings.distribution',
                'label' => __('Distribution level'),
                'class' => 'input span6',
                'options' => [-1 => ' '] + $distributionLevels,
                'type' => 'dropdown'
            ],
            [
                'field' => 'periodic_settings.sharing_group_id',
                'label' => __('Sharing Group'),
                'class' => 'input span6',
                'options' => $sharingGroups,
                'type' => 'dropdown',
                'multiple' => true,
            ],
            [
                'field' => 'periodic_settings.event_info',
                'label' => __('Event info'),
                'class' => 'input span6',
                'placeholder' => 'Phishing URL',
            ],
            [
                'field' => 'periodic_settings.tags',
                'label' => __('Event Tags'),
                'class' => 'span6',
                'type' => 'tagsPicker',
                'placeholder' => '["tlp:red"]',
            ],
            sprintf('<h4>%s</h4>', __('Report settings')),
            [
                'field' => 'periodic_settings.trending_for_tags',
                'label' => __('Generate trends for tag namespaces'),
                'class' => 'span6',
                'type' => 'textarea',
                'placeholder' => '["misp-galaxy:mitre-attack-pattern", "admiralty-scale"]',
            ],
            [
                'field' => 'periodic_settings.trending_period_amount',
                'label' => __('Trending Period Amount'),
                'class' => 'span6',
                'type' => 'number',
            ],
            [
                'field' => 'periodic_settings.include_correlations',
                'label' => __('Include events correlations'),
                'default' => 0,
                'type' => 'checkbox'
            ],
        ],
        'submit' => [
            'action' => $this->request->params['action'],
            'ajaxSubmit' => 'submitGenericFormInPlace();'
        ]
    ]
]);
if (!$ajax) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'notification_settings'));
}
?>

<script>
    $(document).ready(function() {
        checkSharingGroup('periodic_settings');

        $('#periodic_settingsDistribution').change(function() {
            checkSharingGroup('periodic_settings');
        });
    })
</script>

<style>
</style>