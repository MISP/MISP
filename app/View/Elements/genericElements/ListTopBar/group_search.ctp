<?php
    /*
     *  Run a quick filter against the current API endpoint
     *  Result is passed via URL parameters, by default using the searchall key
     *  Valid parameters:
     *  - data: data-* fields
     *  - searchKey: data-search-key, specifying the key to be used (defaults to searchall)
     *  - fa-icon: an icon to use for the lookup $button
     *  - buttong: Text to use for the lookup button
     *  - cancel: Button for quickly removing the filters
     *  - placeholder: optional placeholder for the text field
     *  - id: element ID for the input field - defaults to quickFilterField
     */
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
            '<input type="text" class="span3 input-small" placeholder="%s" aria-label="%s" style="padding: 2px 6px;" id="%s" data-searchkey="%s" value="%s">',
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['placeholder']) ? '' : h($data['placeholder']),
            empty($data['id']) ? 'quickFilterField' : h($data['id']),
            empty($data['searchKey']) ? 'searchall' : h($data['searchKey']),
            empty($data['value']) ? '' : h($data['value'])
        );
        echo sprintf(
            '<div class="btn-group pull-right"><div class="input-append" style="margin-bottom:0px;">%s%s</div></div>',
            $input,
            $button
        );
    }
?>
