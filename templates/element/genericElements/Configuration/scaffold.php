<?php
/*
 * Generic configuration panel builder
 *
 * Simply pass a JSON with the following keys set:
 * - title: The title for the configuration interface
 * - diagnostic-view (optional): url of the diagnostic page to be shown and refreshed on any setting change
 * - fields: an array with each element generating an input field
 *     - field: the unique field name for the context
 *     - description: a brief description of the field
 *     - type (optional): the type of form element to use
 *     - options (optional): for select style elements
 *     - validation (optional): regex to validate input
 *     - requirements (optional): boolean, if false is passed the field is skipped
 */
$diagnostics = '';
if (!empty($data['diagnostics'])) {
    $diagnostics = '<div data-url="' . h($data['diagnostics']) . '"></div>';
}
$fields = '';
if (!empty($data['fields'])) {
    foreach ($data['fields'] as $field) {
        $fields .= $this->element('genericElements/Configuration/Fields/scaffold.php', ['data' => $field]);
    }
}
echo sprintf(
    '<div class="%s"><h2>%s</h2><div>%s</div><div><%s/div></div>',
    empty($ajax) ? 'col-8' : '',
    h($data['title']),
    $diagnostics,
    $fields
);
?>
