<?php
if (!function_exists('isLeaf')) {
    function isLeaf($setting)
    {
        return !empty($setting['name']) && !empty($setting['type']);
    }
}
if (!function_exists('getResolvableID')) {
    function getResolvableID($sectionName, $panelName = false)
    {
        $id = sprintf('sp-%s', preg_replace('/(\.|\W)/', '_', h($sectionName)));
        if (!empty($panelName)) {
            $id .= '-' . preg_replace('/(\.|\W)/', '_', h($panelName));
        }
        return $id;
    }
}

$panelHTML = '';
if (isLeaf($panelSettings)) {
    $singleSetting = $this->element('Settings/fieldGroup', [
        'panelName' => $panelName,
        'panelSettings' => $panelSettings,
        'settingName' => $panelName,
        'setting' => $panelSettings,
    ]);
    $panelHTML = "<div>{$singleSetting}</div>";
} else {
    $panelID = getResolvableID($sectionName, $panelName);
    $panelHTML .= sprintf('<h4 id="%s"><a class="text-reset text-decoration-none" href="#%s">%s%s</a></h4>',
        $panelID,
        $panelID,
        !empty($panelSettings['_icon']) ? $this->Bootstrap->icon($panelSettings['_icon'], ['class' => 'me-1']) : '',
        h($panelName)
    );
    if (!empty($panelSettings['_description'])) {
        $panelHTML .= $this->Bootstrap->genNode('div', [
            'class' => ['mb-1',],
        ], h($panelSettings['_description']));
    }
    $groupIssueSeverity = false;
    foreach ($panelSettings as $singleSettingName => $singleSetting) {
        if (substr($singleSettingName, 0, 1) == '_') {
            continue;
        }
        $singleSettingHTML = $this->element('Settings/fieldGroup', [
            'panelName' => $panelName,
            'panelSettings' => $panelSettings,
            'settingName' => $singleSettingName,
            'setting' => $singleSetting,
        ]);
        $panelHTML .= sprintf('<div class="ms-3">%s</div>', $singleSettingHTML);
        if (!empty($singleSetting['error'])) {
            $settingVariant = $this->get('variantFromSeverity')[$singleSetting['severity']];
            if ($groupIssueSeverity != 'danger') {
                if ($groupIssueSeverity != 'warning') {
                    $groupIssueSeverity = $settingVariant;
                }
            }
        }
    }
    $panelHTML = $this->Bootstrap->genNode('div', [
        'class' => [
            'shadow',
            'p-2',
            'mb-4',
            'rounded',
            'settings-group',
            'callout',
            (!empty($groupIssueSeverity) ? "callout-${groupIssueSeverity}" : ''),
        ],
    ], $panelHTML);
}
echo $panelHTML;