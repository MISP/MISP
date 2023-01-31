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

$sectionHtml = '';
if (isLeaf($sectionContent)) {
    $sectionHtml .= $this->element('Settings/panel', [
        'sectionName' => $sectionName,
        'panelName' => $sectionName,
        'panelSettings' => $sectionContent,
    ]);
} else {
    if (count($sectionContent) > 0) {
        $sectionHtml .= sprintf('<h2 id="%s">%s</h2>', getResolvableID($sectionName), h($sectionName));
    }
    foreach ($sectionContent as $panelName => $panelSettings) {
        if (!empty($panelSettings)) {
            $sectionHtml .= $this->element('Settings/panel', [
                'sectionName' => $sectionName,
                'panelName' => $panelName,
                'panelSettings' => $panelSettings,
            ]);
        } else {
            $sectionHtml .= '';
        }
    }
}
?>

<div>
    <?= $sectionHtml ?>
</div>