<?php
echo sprintf(
    '<div id="widget_%s"
            class="widget-wrapper"
            style="%s"
            gs-x="%s"
            gs-y="%s"
            gs-w="%s"
            gs-h="%s"
            widget="%s"
            config="%s">
        <div class="widgetTitle">
            <span class="widgetTitleText">%s</span>
            %s %s %s
        </div>
        <div class="widgetContent">
        </div>
        <div class="widget-data">&nbsp;</div>
    </div>',
    h($k),
    'border: 1px solid #0088cc;',

    // position used by JS when hydrating
    isset($widget['position']['x']) ? h($widget['position']['x']) : 0,
    isset($widget['position']['y']) ? h($widget['position']['y']) : 0,
    isset($widget['position']['width']) ? h($widget['position']['width']) : 2,
    isset($widget['position']['height']) ? h($widget['position']['height']) : 2,

    // widget type + config
    h($widget['widget']),
    empty($widget['config']) ? '[]' : h(json_encode($widget['config'])),

    // title / alias
    empty($widget['config']['alias']) ? h($widget['title']) : h($widget['config']['alias']),

    // export dropdown
    sprintf(
        '<span class="dropdown">
            <a class="dropdown-toggle" data-toggle="dropdown" href="#" title="%s">
                <i class="%s"></i>
            </a>
            <ul class="dropdown-menu widget-export-menu" role="menu">
                <li><a tabindex="-1" href="#" data-exporttype="json">%s</a></li>
                <li><a tabindex="-1" href="#" data-exporttype="csv">%s</a></li>
            </ul>
        </span>',
        __('Export raw data'),
        $this->FontAwesome->getClass('download'),
        __('Export as JSON'),
        __('Export as CSV')
    ),

    // edit button
    sprintf(
        '<span class="fas fa-edit edit-widget useCursorPointer" title="%s"></span>',
        __('Configure widget')
    ),

    // remove button
    sprintf(
        '<span class="fas fa-trash remove-widget useCursorPointer" title="%s"></span>',
        __('Remove widget')
    ),

    h($k)
);
?>
