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
                'label' => __('Subscribe to montly notifications'),
                'default' => 0,
                'type' => 'checkbox'
            ],
            sprintf('<h4>%s</h4>', __('Notification filters')),
            [
                'field' => 'periodic_settings.orgc_id',
                'label' => __('Creator organisation'),
                'options' => [0 => ' '] + $orgs,
                'type' => 'dropdown'
            ],
            [
                'field' => 'periodic_settings.distribution',
                'class' => 'input',
                'options' => [0 => ' '] + $distributionLevels,
                'type' => 'dropdown'
            ],
            [
                'field' => 'periodic_settings.sharing_group_id',
                'label' => __('Sharing Group'),
                'class' => 'input',
                'options' => $sharingGroups,
                'type' => 'dropdown'
            ],
            [
                'field' => 'periodic_settings.event_info',
                'label' => __('Event info'),
                'class' => 'input',
                'placeholder' => 'Phishing URL',
            ],
            [
                'field' => 'periodic_settings.tags',
                'label' => __('Tag list'),
                'type' => 'tagsPicker',
                'placeholder' => '["tlp:red"]',
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