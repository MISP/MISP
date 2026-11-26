<?php
$tagName = $this->request->data['Taxonomy']['name'];

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Disable tag'),
    'model' => 'Taxonomy',
    'url' => $this->request->here(false),
    'hiddenField' => ['taxonomy_id', 'name'],
    'eyebrow' => __('Taxonomy tags'),
    'accent' => 'warning',
    'message' => __('It is hidden and can no longer be attached. Where it is already attached, it stays.'),
    'bodyHtml' => '<div class="d-flex align-items-center gap-2 p-2 rounded-2 border bg-body-tertiary min-w-0">'
        . '<i class="fas fa-tag text-body-secondary"></i>'
        . '<span class="font-monospace small text-break">' . h($tagName) . '</span></div>',
    'submitLabel' => __('Disable tag'),
    'submitIcon' => 'eye-slash',
]);
