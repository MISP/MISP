<?php
App::uses('LazyRailCards', 'Tools/RailCards');

/**
 * Rail cards for an organisation, counting the events it created that the
 * viewer can see.
 */
class OrganisationRailCards extends LazyRailCards
{
    const ACTIVITY_MONTHS = 12;
    const RECENT_DAYS = 90;

    protected function railCardUrl()
    {
        return '/organisations/railCard/';
    }

    protected function lazyCards()
    {
        return [
            'org-glance' => ['status', __('At a glance'), 'misp-icon misp-icon-organisation misp-simple', 'glance'],
            'org-activity' => ['activity', __('Activity'), 'fas fa-chart-column', 'activity'],
        ];
    }

    /**
     * @param array $user
     * @param int $orgId
     * @return array
     */
    private function eventConditions(array $user, $orgId)
    {
        $conditions = ClassRegistry::init('Event')->createEventConditions($user);
        $conditions['AND'][] = ['Event.orgc_id' => $orgId];
        return $conditions;
    }

    /**
     * When the organisation last published, how many of its events the user
     * can see, the sharing groups it belongs to and, for its admins, users.
     *
     * @param array $user
     * @param int $orgId
     * @param array $may ['users' => bool, 'sharingGroups' => bool]
     * @return array
     */
    public function glance(array $user, $orgId, array $may)
    {
        $Event = ClassRegistry::init('Event');
        $conditions = $this->eventConditions($user, $orgId);
        $events = $Event->find('count', ['recursive' => -1, 'conditions' => $conditions]);
        $published = $Event->find('first', [
            'recursive' => -1,
            'conditions' => $conditions + ['Event.published' => 1],
            'fields' => ['MAX(Event.publish_timestamp) AS last_ts'],
        ]);
        $lastTs = (int)($published[0]['last_ts'] ?? 0);

        $items = [
            ['label' => __('Events'), 'value' => $events],
        ];
        if ($may['sharingGroups']) {
            $items[] = ['label' => __('Sharing groups'), 'value' => $this->sharingGroupCount($user, $orgId)];
        }
        if ($may['users']) {
            $User = ClassRegistry::init('User');
            $users = $User->find('count', ['recursive' => -1, 'conditions' => ['User.org_id' => $orgId]]);
            $disabled = $User->find('count', [
                'recursive' => -1,
                'conditions' => ['User.org_id' => $orgId, 'User.disabled' => 1],
            ]);
            $items[] = [
                'label' => __('Users'),
                'value' => $disabled ? __('%s (%s disabled)', number_format($users), number_format($disabled)) : $users,
            ];
        }

        if (!$events) {
            $state = 'muted';
            $headline = __('No event from this organisation.');
        } else if (!$lastTs) {
            $state = 'muted';
            $headline = __('Has not published an event.');
        } else {
            $state = $lastTs >= time() - self::RECENT_DAYS * 86400 ? 'ok' : 'muted';
            $headline = __('Last published an event %s.', RailCard::ago($lastTs));
        }
        list(, $title, $icon) = $this->head('org-glance');
        return RailCard::status('org-glance', $title, $icon, $state, $headline, $items, null, [
            'link' => ['label' => __('Events'), 'href' => '#tab-events'],
            'lazy' => true,
        ]);
    }

    /**
     * Sharing groups the user can see that the organisation created or is
     * a member of.
     *
     * @param array $user
     * @param int $orgId
     * @return int
     */
    private function sharingGroupCount(array $user, $orgId)
    {
        $SharingGroup = ClassRegistry::init('SharingGroup');
        $visible = $SharingGroup->authorizedIds($user);
        if (empty($visible)) {
            return 0;
        }
        $member = $SharingGroup->SharingGroupOrg->find('column', [
            'conditions' => ['SharingGroupOrg.org_id' => $orgId, 'SharingGroupOrg.sharing_group_id' => $visible],
            'fields' => ['SharingGroupOrg.sharing_group_id'],
        ]);
        $created = $SharingGroup->find('column', [
            'conditions' => ['SharingGroup.org_id' => $orgId, 'SharingGroup.id' => $visible],
            'fields' => ['SharingGroup.id'],
        ]);
        return count(array_unique(array_merge($member, $created)));
    }

    /**
     * Visible events created by the organisation, per month of their event
     * date, with the attributes they hold.
     *
     * @param array $user
     * @param int $orgId
     * @return array
     */
    public function activity(array $user, $orgId)
    {
        $since = (new DateTime('first day of this month'))
            ->modify('-' . (self::ACTIVITY_MONTHS - 1) . ' months')
            ->format('Y-m-d');
        $conditions = $this->eventConditions($user, $orgId);
        $conditions['AND'][] = ['Event.date >=' => $since, 'Event.date <=' => date('Y-m-d')];
        $days = ClassRegistry::init('Event')->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Event.date', 'COUNT(Event.id) AS event_count', 'SUM(Event.attribute_count) AS attribute_count'],
            'group' => ['Event.date'],
        ]);
        $perMonth = [];
        $attributes = 0;
        $latest = null;
        foreach ($days as $day) {
            $date = $day['Event']['date'];
            $month = substr($date, 0, 7);
            $perMonth[$month] = ($perMonth[$month] ?? 0) + (int)$day[0]['event_count'];
            $attributes += (int)$day[0]['attribute_count'];
            if ($latest === null || $date > $latest) {
                $latest = $date;
            }
        }
        $series = RailCard::series($perMonth, 'month', self::ACTIVITY_MONTHS);
        $total = array_sum(array_column($series, 'count'));
        list(, $title, $icon) = $this->head('org-activity');
        return RailCard::activity(
            'org-activity',
            $title,
            $icon,
            'month',
            $series,
            ['count' => $total, 'label' => __n('event in 12 months', 'events in 12 months', $total)],
            $latest === null ? null : RailCard::last(strtotime($latest), __('Latest event')),
            $total ? [['label' => __('Attributes'), 'value' => number_format($attributes)]] : [],
            ['empty' => __('No event in the last 12 months.'), 'lazy' => true]
        );
    }
}
