<?php
/**
 * Publish/unpublish galaxy cluster confirmation modal (Overmind theme).
 * Available vars: $cluster, $type ('publish').
 */
$c = $cluster['GalaxyCluster'];
$isPublish = ($type !== 'unpublish');
$message = $isPublish
    ? sprintf(__('Are you sure you want to publish Galaxy Cluster %s (%s)?'), h($c['value']), h($c['id']))
    : sprintf(__('Are you sure you want to unpublish Galaxy Cluster %s (%s)?'), h($c['value']), h($c['id']));

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => $isPublish ? __('Publish Galaxy Cluster') : __('Unpublish Galaxy Cluster'),
    'model' => 'GalaxyCluster',
    'url' => $baseurl . '/galaxy_clusters/' . h($type) . '/' . h($c['id']),
    'message' => $message,
    'accent' => 'galaxy',
    'submitLabel' => $isPublish ? __('Publish') : __('Unpublish'),
    'submitIcon' => $isPublish ? 'upload' : 'eye-slash',
]);
