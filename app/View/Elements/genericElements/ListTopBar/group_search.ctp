<?php
    if (!isset($data['requirement']) || $data['requirement']) {
        $button = empty($data['button']) && empty($data['fa-icon']) ? '' : sprintf(
            '<button class=" btn btn-small btn-inverse" %s id="quickFilterButton">%s%s</button>',
            empty($data['data']) ? '' : h($data['data']),
            empty($data['fa-icon']) ? '' : sprintf('<i class="fa fa-%s"></i>', h($data['fa-icon'])),
            empty($data['button']) ? '' : h($data['button'])
        );
        if (!empty($data['cancel'])) {
            $button .= $this->element('/genericElements/ListTopBar/element_simple', array('data' => $data['cancel']));
        }
        $input = sprintf(
            '<input type="text" class="span3 input-small" placeholder="%s" aria-label="%s" style="padding: 2px 6px;" id="%s">',
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['id']) ? 'quickFilterField' : h($data['id'])
        );
        echo sprintf(
            '<div class="btn-group pull-right"><div class="input-append" style="margin-bottom:0px;">%s%s</div></div>',
            $input,
            $button
        );
    }
?>
