<?php
/*
 * GET/POST /attributes/editEventTags/{id}  (POST body: JSON { global_ids, local_ids })
 *
 * Thin wrapper around the shared tag-picker modal.
 * Variables come from EventsController::editEventTags:
 * - $allTags
 * - $customTags
 * - $tagCollections
 * - $currentGlobalTags
 * - $currentLocalTags
 * - eventId
 * - $mayModify
 */
echo $this->element('genericElementsBS5/Modals/tag_picker', [
    'saveUrl'           => $baseurl . '/events/editEventTags/' . $eventId,
    'uid'               => 'evt-tags-' . $eventId,
    'headerEyebrow'     => __('Tags'),
    'reloadHook'        => 'reloadTagsCard_',
    'allTags'           => $allTags,
    'customTags'        => $customTags,
    'tagCollections'    => $tagCollections,
    'currentGlobalTags' => $currentGlobalTags,
    'currentLocalTags'  => $currentLocalTags,
    'mayModify'         => $mayModify,
]);
