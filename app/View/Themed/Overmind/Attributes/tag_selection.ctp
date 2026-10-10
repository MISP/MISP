<?php
/*
 * GET/POST /attributes/tagSelection/{ids}  (POST body: JSON { global_ids, local_ids })
 *
 * The attribute index's "Tag" mass action: the shared tag picker, opened on the
 * tags the selection carries.
 * Variables come from AttributesController::tagSelection.
 */
$count = count($selectionIds);
echo $this->element('genericElementsBS5/Modals/tag_picker', [
    'saveUrl'           => $baseurl . '/attributes/tagSelection/' . json_encode($selectionIds),
    'uid'               => 'attr-mass-tags',
    'headerEyebrow'     => __n('%s selected attribute', '%s selected attributes', $count, $count),
    'title'             => __('Tags of selected attributes'),
    'description'       => __('These are the tags the selection carries; one only some attributes carry shows how many. Remove one to detach it from all of them, add one to attach it to all of them.'),
    'saveLabel'         => __('Apply to selection'),
    'allTags'           => $allTags,
    'customTags'        => $customTags,
    'tagCollections'    => $tagCollections,
    'taxonomies'        => $taxonomies,
    'currentGlobalTags' => $currentGlobalTags,
    'currentLocalTags'  => $currentLocalTags,
    'mayModify'         => true,
]);
