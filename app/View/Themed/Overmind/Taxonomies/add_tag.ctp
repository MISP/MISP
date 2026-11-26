<?php
/*
 * Create, update or re-enable one tag of a taxonomy. Server-rendered so the
 * POST spends a token minted for this URL; addTag() reads the two fields.
 */
$enable = !empty($this->request->params['named']['enable']);
$update = !empty($this->request->params['named']['update']);
$tagName = $this->request->data['Taxonomy']['name'];

if ($enable) {
    $mode = [__('Enable tag'), 'play', __('It becomes available for tagging again.')];
} elseif ($update) {
    $mode = [__('Update tag'), 'sync', __('Its colour and numerical value are refreshed from the taxonomy.')];
} else {
    $mode = [__('Create tag'), 'plus', __('It becomes available for tagging.')];
}

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => $mode[0],
    'model' => 'Taxonomy',
    'url' => $this->request->here(false),
    'hiddenField' => ['taxonomy_id', 'name'],
    'eyebrow' => __('Taxonomy tags'),
    'accent' => 'tag',
    'message' => $mode[2],
    'bodyHtml' => '<div class="d-flex align-items-center gap-2 p-2 rounded-2 border bg-body-tertiary min-w-0">'
        . '<i class="fas fa-tag text-body-secondary"></i>'
        . '<span class="font-monospace small text-break">' . h($tagName) . '</span></div>',
    'submitLabel' => $mode[0],
    'submitIcon' => $mode[1],
]);
