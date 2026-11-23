<?php
/*
 * GET/POST /events/editEventGalaxies/{id}  (POST body: JSON { global_ids, local_ids })
 *
 * Thin wrapper around the shared galaxy-picker modal.
 * Variables come from EventsController::editEventGalaxies:
 * - $currentGlobalClusters
 * - $currentLocalClusters
 * - $eventId
 * - $mayModify
 */
echo $this->element('genericElementsBS5/Modals/galaxy_picker', [
    'saveUrl'               => $baseurl . '/events/editEventGalaxies/' . $eventId,
    'uid'                   => 'evt-galaxies-' . $eventId,
    'headerEyebrow'         => __('Galaxies'),
    'reloadHook'            => 'reloadGalaxiesCard_',
    'currentGlobalClusters' => $currentGlobalClusters,
    'currentLocalClusters'  => $currentLocalClusters,
    'mayModify'             => $mayModify,
]);
