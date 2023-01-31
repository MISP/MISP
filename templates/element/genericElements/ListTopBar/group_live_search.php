<?php
    if (!isset($data['requirement']) || $data['requirement']) {
        $input = sprintf(
            '<input type="text" class="form-control" placeholder="%s" aria-label="%s" id="liveFilterField">',
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['placeholder']) ? '' : h($data['placeholder'])
        );
        echo sprintf(
            '<div class="input-group">%s</div>',
            $input
        );
    }
?>
