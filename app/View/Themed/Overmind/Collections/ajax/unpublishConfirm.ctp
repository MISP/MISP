<?php
/**
 * Unpublish a collection shared beyond its organisation.
 *
 * @var array $collection Unwrapped, with its Orgc
 */
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => 'Collection',
    'url' => $baseurl . '/collections/unpublish/' . (int)$collection['id'],
    'hiddenField' => false,
    'eyebrow' => __('Publication'),
    'accent' => 'warning',
    'title' => __('Unpublish collection'),
    'description' => $collection['name'],
    'message' => __('Unpublish this collection?'),
    'warning' => __('Partners keep the version they last received. Its changes wait, with those made from now on, until someone publishes it again.'),
    'submitLabel' => __('Unpublish'),
    'submitIcon' => 'eye-slash',
    'icon' => 'fas fa-eye-slash',
    'meta' => [['label' => __('Collection'), 'id' => (int)$collection['id']]],
]);
