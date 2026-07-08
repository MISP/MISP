<?php
/*
 * GET/POST /attributes/editAttributeTags/{id}  (POST body: JSON { global_ids, local_ids })
 *
 * Thin wrapper around the shared tag-picker modal.
 * Variables come from AttributesController::editAttributeTags:
 * - $allTags
 * - $customTags
 * - $tagCollections
 * - $currentGlobalTags
 * - $currentLocalTags
 * - attributeId
 * - $mayModify
 */
echo $this->element('genericElementsBS5/Modals/tag_picker', [
    'saveUrl'           => $baseurl . '/attributes/editAttributeTags/' . $attributeId,
    'uid'               => 'attr-tags-' . $attributeId,
    'headerEyebrow'     => __('Attribute Tags'),
    'allTags'           => $allTags,
    'customTags'        => $customTags,
    'tagCollections'    => $tagCollections,
    'currentGlobalTags' => $currentGlobalTags,
    'currentLocalTags'  => $currentLocalTags,
    'mayModify'         => $mayModify,
]);
