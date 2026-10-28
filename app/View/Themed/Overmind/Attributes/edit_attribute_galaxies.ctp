<?php
/*
 * GET/POST /attributes/editAttributeGalaxies/{id}  (POST body: JSON { global_ids, local_ids })
 *
 * Thin wrapper around the shared galaxy-picker modal.
 * Variables come from AttributesController::editAttributeGalaxies:
 * - $currentGlobalClusters
 * - $currentLocalClusters
 * - $attributeId
 * - $mayModify
 */
echo $this->element('genericElementsBS5/Modals/galaxy_picker', [
    'saveUrl'               => $baseurl . '/attributes/editAttributeGalaxies/' . $attributeId,
    'uid'                   => 'attr-galaxies-' . $attributeId,
    'headerEyebrow'         => __('Attribute Galaxies'),
    'currentGlobalClusters' => $currentGlobalClusters,
    'currentLocalClusters'  => $currentLocalClusters,
    'mayModify'             => $mayModify,
]);
