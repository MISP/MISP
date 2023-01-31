<?php
if (!function_exists('isLeaf')) {
    function isLeaf($setting)
    {
        return !empty($setting['name']) && !empty($setting['type']);
    }
}

$variantFromSeverity = [
    'critical' => 'danger',
    'warning' => 'warning',
    'info' => 'info',
];
$this->set('variantFromSeverity', $variantFromSeverity);
$includeScrollspy = !empty($includeScrollspy);

$groupedContent = [];
$scrollSpyContent = [];
foreach ($settings as $sectionName => $sectionContent) {
    if (!empty($sectionContent)) {
        $groupedContent[] = $this->element('Settings/section', [
            'sectionName' => $sectionName,
            'sectionContent' => $sectionContent,
        ]);
    } else {
        $groupedContent[] = '';
    }
    if ($includeScrollspy) {
        if (!isLeaf($sectionContent)) {
            $scrollSpyContent[$sectionName] = array_filter( // only show grouped settings
                array_keys($sectionContent),
                function ($settingGroupName) use ($sectionContent) {
                    return !isLeaf($sectionContent) && !empty($sectionContent[$settingGroupName]);
                }
            );
        }
    }
}

$contentHtml = implode('', $groupedContent);
if ($includeScrollspy) {
    $scrollspyNav = $this->element('Settings/scrollspyNav', [
        'groupedSetting' => $scrollSpyContent
    ]);
}
$mainPanelHeight = 'calc(100vh - 42px - 1rem - 56px - 38px - 1rem)';
?>

<?php if ($includeScrollspy) : ?>
    <div class="d-flex">
        <div class="" style="flex: 0 0 10em;">
            <?= $scrollspyNav ?>
        </div>
        <div data-bs-spy="scroll" data-bs-target="#navbar-scrollspy-setting" data-bs-offset="25" style="height: <?= $mainPanelHeight ?>" class="p-3 overflow-auto position-relative flex-grow-1">
            <?= $contentHtml ?>
        </div>
    </div>
<?php else: ?>
    <div>
        <?= !empty($contentHtml) ? $contentHtml : sprintf('<p class="text-center mt-3">%s</p>', __('No settings available for this category')) ?>
    </div>
<?php endif; ?>