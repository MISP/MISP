<?php
App::uses('EventContextTool', 'Tools/EventOverview');
App::uses('EventCardTool', 'Tools/EventOverview');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
App::uses('ValueTrustTool', 'Tools/ValueIntelligence');

/**
 * The part of the index cards a page of events draws from the events alone:
 * their context lanes, markings, the reader's grade of their creator org,
 * their publish state and distribution. A fixed number of queries for the
 * page, then EventCardTool for each event.
 *
 * Shared by the events index and the feed preview, whose remote events carry
 * the same fields but nothing this instance holds about them.
 */
class EventCardBatch
{
    /**
     * @param array $events rows with Event, Orgc, EventTag (each with its Tag),
     *  GalaxyCluster and SharingGroup
     * @param array $user
     * @param array|null $profile the reader's analyst profile
     * @param array $plan ValueLabelPriority::planFor($profile)
     * @return array keyed as $events: rows, markings, grade, state, distribution
     */
    public static function cards(array $events, array $user, $profile, array $plan)
    {
        if (empty($events)) {
            return [];
        }
        $permitted = ClassRegistry::init('AnalystProfile')->pivotLabels($user, $plan)['permitted'];
        $markingNamespaces = ValueLabelPriority::markings($profile);
        $grades = ValueTrustTool::planFor($profile)['grades'];
        $pinned = EventCardTool::pinned($profile);
        $pinnedExtras = array_diff($pinned, $markingNamespaces);

        $contexts = [];
        $pinnedTagNames = [];
        foreach ($events as $k => $event) {
            $contexts[$k] = EventContextTool::rows(
                $event['EventTag'] ?? [],
                $event['GalaxyCluster'] ?? [],
                null,
                [],
                [],
                $profile,
                $permitted
            );
            foreach ($contexts[$k]['classification'] as $item) {
                if ($item['kind'] === 'tag' && in_array($item['key'], $pinnedExtras, true)) {
                    $pinnedTagNames[$item['name']] = true;
                }
            }
        }
        // Redis-cached, and bounded by the distinct pinned tags on the page.
        $descriptions = [];
        if ($pinnedTagNames) {
            $Taxonomy = ClassRegistry::init('Taxonomy');
            foreach (array_keys($pinnedTagNames) as $tagName) {
                $descriptions[$tagName] = EventCardTool::tagDescription($Taxonomy->getTaxonomyForTag($tagName));
            }
        }

        $cards = [];
        foreach ($events as $k => $event) {
            $e = $event['Event'];
            $cards[$k] = [
                'rows' => EventCardTool::rows($contexts[$k], $profile),
                'markings' => EventCardTool::markings($contexts[$k], $markingNamespaces, $pinned, $descriptions),
                'grade' => EventCardTool::grade($event['Orgc'] ?? [], $grades),
                'state' => EventCardTool::state($e),
                'distribution' => EventCardTool::distribution($e['distribution'] ?? null, $event['SharingGroup'] ?? null),
            ];
        }
        return $cards;
    }
}
