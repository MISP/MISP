<?php
    echo sprintf(
        '<div id="widget_%s" class="grid-stack-item" data-gs-x="%s" data-gs-y="%s" data-gs-width="%s" data-gs-height="%s" style="%s" config="%s" widget="%s">%s<div class="widget-data">&nbsp;</div></div>',
        h($k),
        isset($widget['position']['x']) ? h($widget['position']['x']) : 1,
        isset($widget['position']['y']) ? h($widget['position']['y']) : 1,
        isset($widget['position']['width']) ? h($widget['position']['width']) : 2,
        isset($widget['position']['height']) ? h($widget['position']['height']) : 2,
        'border: 1px solid #0088cc;',
        empty($widget['config']) ? '[]' : h(json_encode($widget['config'])),
        h($widget['widget']),
        sprintf(
            '<div class="grid-stack-item-content"><div class="widgetTitle"><span class="widgetTitleText">%s</span> %s %s %s</div><div class="widgetContent">%s</div></div>',
            empty($widget['config']['alias']) ? h($widget['title']) : h($widget['config']['alias']),
            sprintf('<span class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="#" title="%s"><i class="%s"></i></a>
                    <ul class="dropdown-menu widget-export-menu" role="menu" aria-labelledby="dLabel">
                        <li><a tabindex="-1" href="#" data-exporttype="json">%s</a></li>
                        <li><a tabindex="-1" href="#" data-exporttype="csv">%s</a></li>
                    </ul>
                </span>',
                __('Export raw data'),
                $this->FontAwesome->getClass('download'),
                __('Export as JSON'),
                __('Export as CSV')
            ),
            sprintf(
                '<span class="fas fa-edit edit-widget useCursorPointer" title="%s"></span>',
                __('Configure widget')
            ),
            sprintf(
                '<span class="fas fa-trash remove-widget useCursorPointer" title="%s"></span>',
                __('Remove widget')
            ),
            '&nbsp;'
        )
    );
?>
