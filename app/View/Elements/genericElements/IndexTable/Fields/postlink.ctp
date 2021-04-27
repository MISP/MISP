<?php
/**
 *    - url: url to reference. Can have `%s` in it to be replaced by `url_params_data_paths` extracted value(s).
 *    - url_params_data_paths: a single or an array of replacement strings. Replacements will occur from left to right using an ordered list if multiple exist
 *    - data_path: The path to the data used to display as the text representation of the link
 *    - payload_paths: Payloads to encode as form values - key value list with the key being the field name and value being in the typical dot notation extraction path
 */
    $randomId = bin2hex(openssl_random_pseudo_bytes(8));
    $fieldsArray = [];
    if (!empty($field['payload_paths'])) {
        foreach ($field['payload_paths'] as $fieldName => $path) {
            $fieldsArray[$fieldName] = Hash::extract($row, $path)[0];
        }
    }
    $url = $field['url'];
    if (strpos($url, '%s') !== false) {
        if (!is_array($field['url_params_data_paths'])) {
            $field['url_params_data_paths'] = [$field['url_params_data_paths']];
        }
        $replacements = [];
        foreach ($field['url_params_data_paths'] as $path) {
            $replacements[] = Hash::extract($row, $path)[0];
        }
        $urlArray = explode('%s', $url);
        $url = '';
        foreach ($urlArray as $i => $urlPart) {
            if ($i > 0) {
                $url .= $replacements[$i-1];
            }
            $url .= $urlPart;
        }
    }
    $text = Hash::extract($row, $field['data_path'])[0];
    $form = $this->Form->create(false, [
        'type' => 'post',
        'class' => 'hidden',
        'id' => 'form-' . $randomId,
        'url' => $baseurl . $url,
    ]);
    foreach ($fieldsArray as $field => $value) {
        $form .= $this->Form->input($field, ['value' => $value]);
    }
    $form .= $this->Form->end();
    echo sprintf(
        '%s<a href="#" onClick="event.preventDefault(); %s">%s</a>',
        $form,
        sprintf(
            '$(\'#form-%s\').submit();',
            $randomId
        ),
        $text
    );
