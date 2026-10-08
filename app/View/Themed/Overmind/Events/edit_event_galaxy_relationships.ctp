<?php
/*
 * GET/POST /events/editEventGalaxyRelationships/{id}
 * (POST body: JSON { relationship, tag_connector_ids })
 *
 * Thin wrapper around the shared tag-relationship modal, cluster side.
 * Variables come from EventsController::editEventGalaxyRelationships:
 * - $eventClusters
 * - $relationshipOptions
 * - $eventId
 * - $mayModify
 */
echo $this->element('genericElementsBS5/Modals/tag_relationship_picker', [
    'saveUrl'             => $baseurl . '/events/editEventGalaxyRelationships/' . $eventId,
    'uid'                 => 'evt-galaxies-' . $eventId,
    'kind'                => 'galaxy',
    'headerEyebrow'       => __('Galaxies'),
    'reloadHook'          => 'reloadGalaxiesCard_',
    'rows'                => $eventClusters,
    'relationshipOptions' => $relationshipOptions,
    'mayModify'           => $mayModify,
]);
