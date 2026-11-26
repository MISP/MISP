<?php
/*
 * GET/POST /events/editEventTagRelationships/{id}
 * (POST body: JSON { relationship, tag_connector_ids })
 *
 * Thin wrapper around the shared tag-relationship modal.
 * Variables come from EventsController::editEventTagRelationships:
 * - $eventTags
 * - $relationshipOptions
 * - $eventId
 * - $mayModify
 */
echo $this->element('genericElementsBS5/Modals/tag_relationship_picker', [
    'saveUrl'             => $baseurl . '/events/editEventTagRelationships/' . $eventId,
    'uid'                 => 'evt-tags-' . $eventId,
    'kind'                => 'tag',
    'headerEyebrow'       => __('Tags'),
    'reloadHook'          => 'reloadTagsCard_',
    'rows'                => $eventTags,
    'relationshipOptions' => $relationshipOptions,
    'mayModify'           => $mayModify,
]);
