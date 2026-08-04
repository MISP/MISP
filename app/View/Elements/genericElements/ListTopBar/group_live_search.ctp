<?php
    if (!isset($data['requirement']) || $data['requirement']) {
        $input = sprintf(
            '<input type="text" class="span3 input-small" placeholder="%s" aria-label="%s" style="padding: 2px 6px;margin:0px;" id="liveFilterField">',
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['placeholder']) ? '' : h($data['placeholder'])
        );
        echo sprintf(
            '<div class="btn-group pull-right"><div class="" style="margin-bottom:0px;">%s</div></div>',
            $input
        );
    }
?>
