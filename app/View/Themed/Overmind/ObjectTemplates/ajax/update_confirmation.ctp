<?php
/*
 * Asks before ObjectTemplatesController::update() reinstalls templates from the
 * misp-objects library on disk. Server-rendered so the POST spends a token
 * minted for this URL.
 */
$scoped = !empty($templateName);

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => $scoped ? __('Update object template') : __('Update all object templates'),
    'model' => 'ObjectTemplate',
    'url' => $this->request->here(false),
    'hiddenField' => false,
    'eyebrow' => __('Object templates'),
    'description' => $scoped ? $templateName : '',
    'descriptionClass' => 'font-monospace',
    'accent' => $force ? 'warning' : 'primary',
    'message' => $force
        ? __('The definition on disk is installed again, even where the version has not changed.')
        : __('A newer definition from the misp-objects library is installed if there is one; otherwise nothing changes.'),
    'warning' => $force
        ? __('A forced update creates a new copy of the template.')
        : null,
    'hint' => __('A newer version is installed as a new template, the old one is kept.'),
    'submitLabel' => __('Update'),
    'submitIcon' => 'sync',
]);
