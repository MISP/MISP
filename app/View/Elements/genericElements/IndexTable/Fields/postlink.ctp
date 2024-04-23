<?php
/**
 *    - url: url to reference. Can have `%s` in it to be replaced by `url_params_data_paths` extracted value(s).
 *    - url_params_data_paths: a single or an array of replacement strings. Replacements will occur from left to right using an ordered list if multiple exist
 *    - data_path: The path to the data used to display as the text representation of the link
 *    - payload_paths: Payloads to encode as form values - key value list with the key being the field name and value being in the typical dot notation extraction path
 */
    $randomId = dechex(mt_rand());
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
    foreach ($fieldsArray as $inputField => $value) {
        $form .= $this->Form->input($inputField, ['value' => $value]);
    }
    $form .= $this->Form->end();
    $onclick = sprintf(
        '$(\'#form-%s\').submit();',
        $randomId
    );
    if (!empty($field['confirm_post'])) {
        $field['confirm_message'] = !empty($field['confirm_message']) ? $field['confirm_message'] : __('Confirm action?');
        $onclick = sprintf(
            '%s ? $(\'#form-%s\').submit() : \'\';',
            sprintf('confirm(\'%s\')', h($field['confirm_message'])),
            $randomId
        );
    }
    echo sprintf(
        '%s<a href="#" onclick="event.preventDefault(); %s">%s</a>',
        $form,
        $onclick,
        h($text)
    );
