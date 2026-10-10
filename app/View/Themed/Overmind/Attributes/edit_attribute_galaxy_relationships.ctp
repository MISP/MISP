<?php
/*
 * GET/POST /attributes/editAttributeGalaxyRelationships/{id}
 * (POST body: JSON { relationship, tag_connector_ids })
 *
 * Thin wrapper around the shared tag-relationship modal, cluster side. No
 * reloadHook: an attribute row has no card, so the modal refreshes the index
 * behind it.
 * Variables come from AttributesController::editAttributeGalaxyRelationships:
 * - $attributeClusters
 * - $relationshipOptions
 * - $attributeId
 * - $mayModify
 */
echo $this->element('genericElementsBS5/Modals/tag_relationship_picker', [
    'saveUrl'             => $baseurl . '/attributes/editAttributeGalaxyRelationships/' . $attributeId,
    'uid'                 => 'attr-galaxies-' . $attributeId,
    'kind'                => 'galaxy',
    'headerEyebrow'       => __('Attribute Galaxies'),
    'rows'                => $attributeClusters,
    'relationshipOptions' => $relationshipOptions,
    'mayModify'           => $mayModify,
]);
