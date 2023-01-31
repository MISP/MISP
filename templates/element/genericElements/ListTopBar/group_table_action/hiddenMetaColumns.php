<?php
$tableSettings['hidden_column'] = $tableSettings['hidden_column'] ?? [];

$availableMetaColumnsHtml = '';
if (!empty($meta_template)) {
    foreach ($meta_template->meta_template_fields as $j => $meta_template_field) {
        $fieldName = $meta_template_field['field'];
        $fieldId = "metatemplate-{$meta_template_field->meta_template_id}-{$meta_template_field->id}";
        $isVisible = false;
        if (!empty($tableSettings['visible_meta_column']) && !empty($tableSettings['visible_meta_column'][$meta_template_field->meta_template_id])) {
            $isVisible = in_array($meta_template_field->id, $tableSettings['visible_meta_column'][$meta_template_field->meta_template_id]);
        }
        $availableMetaColumnsHtml .= sprintf(
            '<div class="form-check">
            <input class="form-check-input" type="checkbox" value="" id="columnCheck-%s" data-columnname="%s" %s>
            <label class="form-check-label w-100 cursor-pointer font-monospace user-select-none" for="columnCheck-%s">
                %s
            </label>
        </div>',
            h($fieldId),
            h($fieldId),
            $isVisible ? 'checked' : '',
            h($fieldId),
            h($fieldName)
        );
    }
}

$availableMetaColumnsHtml = $this->Bootstrap->genNode('form', [
    'class' => ['visible-meta-column-form', 'px-2 py-1'],
], $availableMetaColumnsHtml);
echo $availableMetaColumnsHtml;
?>
