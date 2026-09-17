<?php
/*
 * GET/POST /attributes/editAttributeTagRelationships/{id}
 * (POST body: JSON { relationship, tag_connector_ids })
 *
 * Thin wrapper around the shared tag-relationship modal. No reloadHook: an
 * attribute row has no card, so the modal refreshes the index behind it.
 * Variables come from AttributesController::editAttributeTagRelationships:
 * - $attributeTags
 * - $relationshipOptions
 * - $attributeId
 * - $mayModify
 */
echo $this->element('genericElementsBS5/Modals/tag_relationship_picker', [
    'saveUrl'             => $baseurl . '/attributes/editAttributeTagRelationships/' . $attributeId,
    'uid'                 => 'attr-tags-' . $attributeId,
    'kind'                => 'tag',
    'headerEyebrow'       => __('Attribute Tags'),
    'rows'                => $attributeTags,
    'relationshipOptions' => $relationshipOptions,
    'mayModify'           => $mayModify,
]);
