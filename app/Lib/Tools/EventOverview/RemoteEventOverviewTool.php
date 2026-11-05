<?php
App::uses('EventContextTool', 'Tools/EventOverview');
App::uses('EventOverviewTool', 'Tools/EventOverview');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');

/**
 * The overview cards of an event held elsewhere — a feed, a remote
 * instance — drawn from its MISP-format body rather than the database.
 *
 * Its tags need not exist here: each name stands in as a Tag row with a
 * negative id, and its galaxy tags resolve to the clusters this instance
 * holds.
 */
class RemoteEventOverviewTool
{
    /**
     * @param array $user
     * @param array $event MISP-format event: Event carrying Tag, Attribute and Object
     * @return array context and inObjects (as viewEventContext sets them),
     *               inventory, markings, profileName, profileId
     */
    public function overview(array $user, array $event)
    {
        $body = $event['Event'];
        $ids = [];
        $tagRow = function (array $tag) use (&$ids) {
            $name = (string)$tag['name'];
            if (!isset($ids[$name])) {
                $ids[$name] = -(count($ids) + 1);
            }
            return [
                'id' => $ids[$name],
                'name' => $name,
                'colour' => $tag['colour'] ?? null,
                'is_galaxy' => strpos($name, 'misp-galaxy:') === 0,
            ];
        };

        $eventTags = [];
        foreach ($body['Tag'] ?? [] as $tag) {
            if (isset($tag['name']) && $tag['name'] !== '') {
                $eventTags[] = [
                    'Tag' => $tagRow($tag),
                    'local' => !empty($tag['local']),
                    'relationship_type' => $tag['relationship_type'] ?? '',
                ];
            }
        }

        // tag id => [loose attributes, attributes in objects]
        $split = [];
        $indicatorTags = [];
        $count = function (array $attribute, $loose) use ($tagRow, &$split, &$indicatorTags) {
            if (!empty($attribute['deleted'])) {
                return;
            }
            foreach ($attribute['Tag'] ?? [] as $tag) {
                if (!isset($tag['name']) || $tag['name'] === '') {
                    continue;
                }
                $row = $tagRow($tag);
                $indicatorTags[$row['id']] = $row;
                $split[$row['id']] = $split[$row['id']] ?? [0, 0];
                $split[$row['id']][$loose ? 0 : 1]++;
            }
        };
        foreach ($body['Attribute'] ?? [] as $attribute) {
            $count($attribute, true);
        }
        foreach ($body['Object'] ?? [] as $object) {
            if (empty($object['deleted'])) {
                foreach ($object['Attribute'] ?? [] as $attribute) {
                    $count($attribute, false);
                }
            }
        }

        $galaxyNames = [];
        foreach (array_merge(array_column($eventTags, 'Tag'), array_values($indicatorTags)) as $tag) {
            if ($tag['is_galaxy']) {
                $galaxyNames[$tag['id']] = $tag['name'];
            }
        }
        $clusters = [];
        if (!empty($galaxyNames)) {
            $GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            foreach ($GalaxyCluster->getClustersByTags($galaxyNames, $user, true, false) as $cluster) {
                $cluster = $cluster['GalaxyCluster'];
                if (!empty($cluster['tag_id'])) {
                    $clusters[(int)$cluster['tag_id']] = $cluster;
                }
            }
        }
        $eventClusters = [];
        foreach ($eventTags as $eventTag) {
            if (isset($clusters[$eventTag['Tag']['id']])) {
                $eventClusters[] = $clusters[$eventTag['Tag']['id']] + [
                    'local' => $eventTag['local'],
                    'relationship_type' => $eventTag['relationship_type'] ?: false,
                ];
            }
        }

        $AnalystProfile = ClassRegistry::init('AnalystProfile');
        $profile = $AnalystProfile->resolveFor($user);
        $permitted = $AnalystProfile->pivotLabels($user, ValueLabelPriority::planFor($profile))['permitted'];
        $rows = EventContextTool::rows(
            $eventTags,
            $eventClusters,
            array_map('array_sum', $split),
            $indicatorTags,
            array_intersect_key($clusters, $indicatorTags),
            $profile,
            $permitted
        );

        return [
            'context' => $rows,
            'inObjects' => array_map(function ($counts) {
                return $counts[1];
            }, $split),
            'inventory' => EventOverviewTool::inventoryOf($body),
            'markings' => [
                'declared' => ValueLabelPriority::markings($profile),
                'present' => $rows['markings'],
                'absent' => $rows['markings_absent'],
            ],
            'profileName' => $profile['name'] ?? null,
            'profileId' => $profile['id'] ?? null,
        ];
    }
}
