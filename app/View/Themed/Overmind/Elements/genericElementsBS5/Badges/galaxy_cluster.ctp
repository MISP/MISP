<?php
/**
 * One galaxy cluster as a chip, the way Badges/tag draws a tag.
 * - $cluster (array) value, galaxy, and optionally id, galaxy_id, icon,
 *   description
 * - $local (bool)
 * - $relationship (string) optional, EventTag/AttributeTag.relationship_type
 * - $hiddenClass (string) optional
 * - $showGalaxy (bool) optional, the galaxy name on the chip (default yes)
 * - $link (bool) optional, link to the cluster (default no)
 */
$cluster['local'] = !empty($local);
$cluster['relationship_type'] = !empty($relationship) ? trim((string)$relationship) : null;
$link = !empty($link);
echo $this->TagChip->cluster($cluster, [
    'display' => isset($showGalaxy) && empty($showGalaxy) ? 'leaf' : 'full',
    'href' => function () use ($cluster, $link, $baseurl) {
        return $link && !empty($cluster['id'])
            ? $baseurl . '/galaxy_clusters/view/' . (int)$cluster['id']
            : null;
    },
    'class' => $hiddenClass ?? '',
]);
