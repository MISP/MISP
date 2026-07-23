<?php
$relationSummary = sprintf(
    '%s — %s → %s',
    !empty($relation['SourceCluster']['value']) ? $relation['SourceCluster']['value'] : __('Unknown source'),
    $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_type'],
    !empty($relation['TargetCluster']['value']) ? $relation['TargetCluster']['value'] : __('Unknown target')
);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Galaxy Cluster Relationship Deletion'),
    'model' => 'GalaxyClusterRelation',
    'url' => $baseurl . '/galaxy_cluster_relations/delete/' . h($relation['GalaxyClusterRelation']['id']),
    'message' => __('Are you sure you want to delete relationship #%s (%s)?', $relation['GalaxyClusterRelation']['id'], $relationSummary)
]);
