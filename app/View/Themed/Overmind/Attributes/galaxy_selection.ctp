<?php
/*
 * GET/POST /attributes/galaxySelection/{ids}  (POST body: JSON { global_ids, local_ids })
 *
 * The attribute index's "Cluster" mass action: the shared galaxy picker, opened
 * on the clusters the selection carries.
 * Variables come from AttributesController::galaxySelection.
 */
$count = count($selectionIds);
echo $this->element('genericElementsBS5/Modals/galaxy_picker', [
    'saveUrl'               => $baseurl . '/attributes/galaxySelection/' . json_encode($selectionIds),
    'uid'                   => 'attr-mass-galaxies',
    'headerEyebrow'         => __n('%s selected attribute', '%s selected attributes', $count, $count),
    'title'                 => __('Clusters of selected attributes'),
    'description'           => __('These are the clusters the selection carries; one only some attributes carry shows how many. Remove one to detach it from all of them, add one to attach it to all of them.'),
    'saveLabel'             => __('Apply to selection'),
    'galaxyList'            => $galaxyList,
    'currentGlobalClusters' => $currentGlobalClusters,
    'currentLocalClusters'  => $currentLocalClusters,
    'mayModify'             => true,
]);
