<?php
$linksByCategory = [];

foreach ($event['warnings'] as $category => $warnings) {
    foreach ($warnings as $id => $name) {
        $linksByCategory[$category][] = sprintf(
            '<a href="#attributeList" title="%s" onclick="toggleWarningFilter(\'warninglistId:%s\')">%s</a> <a href="%s/warninglists/view/%s" class="black fa fa-search" title="%s" aria-label="%s"></a>',
            __('Show just attributes that have warning from this list'),
            (int) $id,
            h($name),
            $baseurl,
            (int)$id,
            __('View warninglist: %s', h($name)),
            __('View warninglist')
        );
    }
}


if (!empty($linksByCategory['false_positive'])) {
    echo sprintf(
        '<div class="warning_container false_positive">%s%s</div>',
        sprintf(
            '<h4>%s</h4>',
            sprintf(
                '%s <a href="#attributeList" title="%s" onclick="toggleWarningFilter(\'warning:3\');">(%s)</a>',
                __('Warning: Potential false positives'),
                __('Show just attributes that have warnings'),
                __('show')
            )
        ),
        implode('<br>', $linksByCategory['false_positive'])
    );
}

if (!empty($linksByCategory['known'])) {
    echo sprintf(
        '<div class="warning_container known_identifier">%s%s</div>',
        sprintf(
            '<h4>%s</h4>',
            sprintf(
                '%s <a href="#attributeList" title="%s" onclick="toggleWarningFilter(\'warning:4\');">(%s)</a>',
                __('Warning: Potential known identifier'),
                __('Show just attributes that have warnings'),
                __('show')
            )
        ),
        implode('<br>', $linksByCategory['known'])
    );
}