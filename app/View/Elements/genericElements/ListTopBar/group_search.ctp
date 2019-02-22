<?php

    if (!isset($data['requirement']) || $data['requirement']) {

        $button = empty($data['button']) ? '' : sprintf(
            '<button class=" btn btn-small btn-inverse" %s id="quickFilterButton">%s</button>',
            empty($data['data']) ? '' : h($data['data']),
            h($data['button'])
        );
        $input = sprintf(
            '<input type="text" class="span3 input-small" placeholder="%s" aria-label="%s" style="padding: 2px 6px;" id="quickFilterField">',
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['placeholder']) ? '' : h($data['placeholder'])
        );
        echo sprintf(
            '<div class="btn-group pull-right"><div class="input-append" style="margin-bottom:0px;">%s%s</div></div>',
            $input,
            $button
        );
    }
?>
