<?php
$links = [];
foreach ($event['warnings'] as $id => $name) {
    $links[] = sprintf(
        '<a href="#attributeList" title="%s" onclick="setAttributeFilter(\'warninglistId\', %s)">%s</a> <a href="%s/warninglists/view/%s" class="black fa fa-search" title="%s" aria-label="%s"></a>',
        __('Show just attributes that have warning from this list'),
        (int) $id,
        h($name),
        $baseurl,
        (int)$id,
        __('View warninglist %s', h($name)),
        __('View warninglist')
    );
}
echo sprintf(
    '<div class="warning_container">%s%s</div>',
    sprintf(
        '<h4>%s</h4>',
        sprintf(
            '%s <a href="#attributeList" title="%s" onclick="toggleBoolFilter(\'warning\');">(%s)</a>',
            __('Warning: Potential false positives'),
            __('Show just attributes that have warnings'),
            __('show')
        )
    ),
    implode('<br>', $links)
);
