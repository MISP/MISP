<?php
App::uses('LazyRailCards', 'Tools/RailCards');

/**
 * Rail cards for a sharing group blueprint. $blueprint is
 * ['SharingGroupBlueprint' => [...]] as its view loads it.
 */
class SharingGroupBlueprintRailCards extends LazyRailCards
{
    const CHANGE_LIMIT = 8;

    protected function railCardUrl()
    {
        return '/sharing_group_blueprints/railCard/';
    }

    protected function lazyCards()
    {
        return [
            'blueprint-pending' => ['list', __('If run now'), 'fas fa-code-compare', 'pending'],
        ];
    }

    /**
     * What running the blueprint would change: the organisations it would
     * add to and remove from its sharing group, worked out the way a run
     * does but without saving anything.
     *
     * @param array $blueprint
     * @return array
     */
    public function pending(array $blueprint)
    {
        $Blueprint = ClassRegistry::init('SharingGroupBlueprint');
        $b = $blueprint['SharingGroupBlueprint'];
        $owner = [
            'Role' => ['perm_site_admin' => false],
            'org_id' => $b['org_id'],
            'id' => 1,
        ];
        list(, $title, $icon) = $this->head('blueprint-pending');
        try {
            $wanted = $Blueprint->evaluateSharingGroupBlueprint($blueprint, $owner)['orgs'] ?? [];
        } catch (Exception $e) {
            return RailCard::rows('blueprint-pending', $title, $icon, [], null, [
                'empty' => __('Its rules cannot be evaluated: %s', $e->getMessage()),
                'lazy' => true,
            ]);
        }
        $wanted = array_values(array_unique(array_map('intval', $wanted)));
        $existing = [];
        $sgExists = false;
        if (!empty($b['sharing_group_id'])) {
            $sgExists = $Blueprint->SharingGroup->hasAny(['SharingGroup.id' => $b['sharing_group_id']]);
            $existing = array_map('intval', $Blueprint->SharingGroup->SharingGroupOrg->find('column', [
                'conditions' => ['SharingGroupOrg.sharing_group_id' => $b['sharing_group_id']],
                'fields' => ['SharingGroupOrg.org_id'],
            ]));
        }
        $added = array_values(array_diff($wanted, $existing));
        $removed = array_values(array_diff($existing, $wanted));
        $names = ClassRegistry::init('Organisation')->find('list', [
            'conditions' => ['Organisation.id' => array_merge($added, $removed)],
            'fields' => ['Organisation.id', 'Organisation.name'],
        ]);
        $rows = [];
        foreach ([[$added, __('Added'), 'ok'], [$removed, __('Removed'), 'danger']] as list($ids, $label, $tone)) {
            foreach ($ids as $orgId) {
                $rows[] = [
                    'label' => $names[$orgId] ?? __('Organisation #%s', $orgId),
                    'href' => '/organisations/view/' . $orgId,
                    'icon' => 'misp-icon misp-icon-organisation misp-simple',
                    'badge' => ['label' => $label, 'tone' => $tone],
                ];
            }
        }
        $count = count($rows);
        return RailCard::rows(
            'blueprint-pending',
            $title,
            $icon,
            array_slice($rows, 0, self::CHANGE_LIMIT),
            $count > self::CHANGE_LIMIT
                ? ['label' => __('%s more changes', $count - self::CHANGE_LIMIT), 'href' => '#tab-organisations']
                : null,
            [
                'empty' => __('Running it changes nothing.'),
                'note' => $sgExists
                    ? __('%s to add, %s to remove, %s unchanged.', count($added), count($removed), count(array_intersect($wanted, $existing)))
                    : __('No sharing group yet: running it creates one with %s organisations.', count($wanted)),
                'lazy' => true,
            ]
        );
    }

    /**
     * The sharing group the blueprint maintains.
     *
     * @param array $user
     * @param array $blueprint
     * @return array
     */
    public function result(array $user, array $blueprint)
    {
        $sgId = $blueprint['SharingGroupBlueprint']['sharing_group_id'] ?? null;
        $SharingGroup = ClassRegistry::init('SharingGroup');
        $sg = empty($sgId) ? [] : $SharingGroup->find('first', [
            'recursive' => -1,
            'conditions' => ['SharingGroup.id' => $sgId],
            'fields' => ['SharingGroup.id', 'SharingGroup.name', 'SharingGroup.modified'],
        ]);
        if (empty($sg) || !$SharingGroup->checkIfAuthorised($user, $sgId)) {
            return RailCard::status(
                'blueprint-result',
                __('Sharing group'),
                'fas fa-share-nodes',
                'muted',
                __('Not generated yet. Running the blueprint creates it.'),
                []
            );
        }
        $members = $SharingGroup->SharingGroupOrg->find('count', [
            'recursive' => -1,
            'conditions' => ['SharingGroupOrg.sharing_group_id' => $sgId],
        ]);
        $Event = ClassRegistry::init('Event');
        $conditions = $Event->createEventConditions($user);
        $conditions['AND'][] = ['Event.distribution' => 4, 'Event.sharing_group_id' => $sgId];
        $events = $Event->find('count', ['recursive' => -1, 'conditions' => $conditions]);
        $modified = strtotime((string)$sg['SharingGroup']['modified']);
        $items = [
            ['label' => __('Members'), 'value' => $members],
            ['label' => __('Events'), 'value' => $events],
        ];
        if ($modified) {
            $items[] = ['label' => __('Last modified'), 'value' => RailCard::ago($modified)];
        }
        return RailCard::status(
            'blueprint-result',
            __('Sharing group'),
            'fas fa-share-nodes',
            'info',
            $sg['SharingGroup']['name'],
            $items,
            ['label' => __('Open sharing group'), 'href' => '/sharing_groups/view/' . $sgId, 'method' => 'get']
        );
    }
}
