<?php
/*
 * "Enable all tags" — the index asking before it creates every tag the
 * taxonomy is still missing. Server-rendered, so the POST it submits spends a
 * token minted for this very URL (TaxonomiesController::addTag answers both).
 */
$missing = $totalCount - $currentCount;

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => __('Enable all tags'),
    'model' => 'Taxonomy',
    'hiddenField' => false,
    'url' => $this->request->here(false),
    'eyebrow' => __('Taxonomies'),
    'description' => $taxonomy['namespace'],
    'descriptionClass' => 'font-monospace',
    'accent' => 'success',
    'message' => __n(
        '%s of the %s tags of this taxonomy has not been created yet.',
        '%s of the %s tags of this taxonomy have not been created yet.',
        $missing,
        $missing,
        $totalCount
    ),
    'hint' => __('Every value becomes available for tagging.'),
    'submitLabel' => __('Enable all tags'),
    'submitIcon' => 'bolt',
]);
