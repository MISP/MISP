<?php
$links = [];
foreach ($event['warnings'] as $id => $name) {
    $links[] = sprintf(
        '<a href="%s/warninglists/view/%s">%s</a>',
        $baseurl,
        (int)$id,
        h($name)
    );
}
echo sprintf(
    '<div class="warning_container">%s%s</div>',
    sprintf(
        '<h4>%s</h4>',
        sprintf(
            '%s <a href="#attributeList" title="%s" onclick="toggleBoolFilter(\'%s/events/view/%s\', \'warning\');">(%s)</a>',
            __('Warning: Potential false positives'),
            __('Show just attributes that have warnings'),
            $baseurl,
            (int)$event['Event']['id'],
            __('show')
        )
    ),
    implode('<br>', $links)
);
