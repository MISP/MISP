<?php
/*
 *  Toggle element - a simple checkbox with the current state selected
 *  On click, issues a GET to a given endpoint, retrieving a form with the
 *  value flipped, which is immediately POSTed.
 *  to fetch it.
 *
 */

    $url = $baseurl . $field['url'];
    if (!empty($field['url_params_data_paths'][0])) {
        $id = Hash::extract($row, $field['url_params_data_paths'][0]);
        $url .= '/' . h($id[0]);
    }

    $data = Hash::extract($row, $field['data_path']);
    $seed = rand();
    $checkboxId = 'GenericToggle-' . $seed;
    echo sprintf(
        '<input type="checkbox" id="%s" data-action="%s" %s>',
        $checkboxId,
        h($url),
        empty($data[0]) ? '' : 'checked',
    );

