<?php
/**
 *    - url: A url to link to. Can include placeholders for variables using the {{0}} notation
 *    - url_vars: ordered list of parameters, to be used as replacements in the url (first parameter would replace {{0}} for example)
 */
    if (!empty($field['url_vars']) && !empty($field['url'])) {
        if (!is_array($field['url_vars'])) {
            $field['url_vars'] = [$field['url_vars']];
        }
        foreach ($field['url_vars'] as $k => $path) {
            $field['url'] = str_replace('{{' . $k . '}}', $this->Hash->extract($row, $path)[0], $field['url']);
        }
    }
    echo sprintf(
        '<a href="%s" title="%s">%s</a>',
        empty($field['name']) ? h($field['url']) : h($field['name']),
        empty($field['name']) ? h($field['url']) : h($field['name']),
        h($field['url'])
    );
?>
