<?php
$mainNoticeHeading = [
    'critical' => __('Your Cerebrate instance requires immediate attention.'),
    'warning' => __('Issues found, it is recommended that you resolve them.'),
    'info' => __('There are some optional settings that are incorrect or not set.'),
];
$headingPerLevel = [
    'critical' => __('Critical settings'),
    'warning' => __('Warning settings'),
    'info' => __('Info settings'),
];
$noticeDescriptionPerLevel = [
    'critical' => __('Cerebrate will not operate correctly or will be unsecure until these issues are resolved.'),
    'warning' => __('Some of the features of Cerebrate cannot be utilised until these issues are resolved.'),
    'info' => __('There are some optional tweaks that could be done to improve the looks of your Cerebrate instance.'),
];

$settingNoticeListHeader = [];
$settingNoticeList = [];

$alertVariant = 'info';
$skipHeading = false;
$alertBody = '';
$tableItems = [];
foreach (array_keys($mainNoticeHeading) as $level) {
    if(!empty($notices[$level])) {
        $variant = $variantFromSeverity[$level];
        if (!$skipHeading) {
            $alertBody .= sprintf('<h5 class="alert-heading">%s</h5>', $mainNoticeHeading[$level]);
            $alertVariant = $variant;
            $skipHeading = true;
        }
        $tableItems[] = [
            'severity' => $headingPerLevel[$level],
            'issues' => count($notices[$level]),
            'badge-variant' => $variant,
            'description' => $noticeDescriptionPerLevel[$level],
        ];
        $settingNoticeListHeader[] = [
            'html' => $this->Bootstrap->badge([
                'variant' => $variantFromSeverity[$level],
                'text' => $level
            ])
        ];
        $settingNoticeList[] = $this->Bootstrap->table([
            'small' => true,
            'striped' => false,
            'hover' => false,
            'borderless' => true,
            'bordered' => false,
        ], [
            'fields' => [
                ['key' => 'name', 'label' => __('Name'), 'formatter' => function($name, $row) {
                    $settingID = preg_replace('/(\.|\W)/', '_', h($row['true-name']));
                    return sprintf('<a style="max-width: 200px; white-space: pre-wrap;" href="#lb-%s" onclick="redirectToSetting(\'#lb-%s\')">%s</a>', $settingID, $settingID, h($name));
                }],
                ['key' => 'setting-path', 'label' => __('Category'), 'formatter' => function($path, $row) {
                    return '<span class="text-nowrap">' . h(str_replace('.', ' ▸ ', $path)) . '</span>';
                }],
                ['key' => 'value', 'label' => __('Value'), 'formatter' => function($value, $row) {
                    $formatedValue = '<span class="p-1 rounded mb-0" style="background: #eeeeee55; font-family: monospace;">';
                    if (is_null($value)) {
                        $formatedValue .= '<i class="text-nowrap">' . __('No value') . '</i>';
                    } else if ($value === '') {
                        $formatedValue .= '<i class="text-nowrap">' . __('Empty string') . '</i>';
                    } else if (is_bool($value)) {
                        $formatedValue .= '<i class="text-nowrap">' . ($value ? __('true') : __('false')) . '</i>';
                    } else {
                        $formatedValue .= h($value);
                    }
                    $formatedValue .= '</span>';
                    return $formatedValue;
                }],
                ['key' => 'description', 'label' => __('Description')]
            ],
            'items' => $notices[$level],
        ]);
    }
}

$alertBody = $this->Bootstrap->table([
    'small' => true,
    'striped' => false,
    'hover' => false,
    'borderless' => true,
    'bordered' => false,
    'tableClass' => 'mb-0'
], [
    'fields' => [
        ['key' => 'severity', 'label' => __('Severity')],
        ['key' => 'issues', 'label' => __('Issues'), 'formatter' => function($count, $row) {
            return $this->Bootstrap->badge([
                'variant' => $row['badge-variant'],
                'text' => $count
            ]);
        }],
        ['key' => 'description', 'label' => __('Description')]
    ],
    'items' => $tableItems,
]);

$settingNotice = $this->Bootstrap->alert([
    'dismissible' => false,
    'variant' => $alertVariant,
    'html' => $alertBody
]);
$settingNotice = sprintf('<div class="mt-3">%s</div>', $settingNotice);
echo $settingNotice;

$tabsOptions = [
    'card' => true,
    'pills' => false,
    'data' => [
        'navs' => $settingNoticeListHeader,
        'content' => $settingNoticeList
    ]
];
echo $this->Bootstrap->tabs($tabsOptions);
