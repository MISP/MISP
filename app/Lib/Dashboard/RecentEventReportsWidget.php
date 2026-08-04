<?php

/**
 * Recent Event Reports (dashboard v2, analyst track — AD-W10 / AD-18).
 *
 * A "what's new" feed of the N most-recent Event Reports the viewer can see,
 * newest first. Reports are markdown write-ups attached to events; this
 * widget surfaces freshly created / updated ones at a glance.
 *
 * Render = the shared `FeedList` kind (AD-17): each row is a report glyph ·
 * the report name (title) · a content snippet (subtitle) · the author org ·
 * relative time · an "Event #<id>" context · a drilldown to the report.
 *
 * Fetch / ACL: EventReport->fetchReports() applies the right ACL
 * (buildACLConditions = Event::createEventConditions + the report's own
 * distribution / sharing-group; site-admin sees all) — but it IGNORES
 * `order` / `limit`, so for a reverse-chron top-N feed we call the SAME
 * public `buildACLConditions()` + `DEFAULT_CONTAIN` in a direct find() that
 * does order + limit. ACL-identical to fetchReports, just orderable; no
 * existing model code is touched (the controller builds its own find params
 * the same way).
 *
 * Recency anchor = EventReport.timestamp (epoch; set on create, bumped on
 * edit — honestly "recently created or updated"). `deleted = 0` only.
 *
 * Cache: NONE. Like the W6 event stream this is a per-user ACL'd view, not an
 * aggregate — it re-fetches live (cheap: indexed timestamp + LIMIT N).
 *
 * Additive-only: a brand-new widget class, render = the existing FeedList
 * kind (B10). No existing widget / handler / model behaviour changes.
 */
class RecentEventReportsWidget
{
    public $title = 'Recent Event Reports';
    public $category = 'events';
    public $render = 'FeedList';
    public $width = 4;
    public $height = 2;

    public $params = array(
        'time_window' => 'Optional time filter: only reports whose timestamp '
            . 'falls in this window, going back in seconds (e.g. "30d"); '
            . '-1 = no time filter (just the newest N). Default: -1.',
        'limit' => 'How many reports to show (newest first). Default: 10.',
    );

    public $schema = array(
        'time_window' => array(
            'type' => 'time_window',
            // -1 = no time bound: the feed is N-newest-bounded, so it always
            // shows content regardless of corpus age. Set a window to scope it.
            'default' => -1,
            'help' => 'Optional window — only reports updated in the last N '
                . 'days/hours, or all time. Driven by the dashboard toolbar.',
        ),
        'limit' => array(
            'type' => 'int',
            'default' => 10,
            'help' => 'Number of recent reports to list (newest first).',
        ),
    );

    public $placeholder =
'{
    "time_window": -1,
    "limit": 10
}';

    public $description = 'A feed of the most recently created or updated '
        . 'Event Reports you can see, newest first.';

    const MAX_LIMIT = 50;
    const SNIPPET_CHARS = 200;

    public function handler($user, $options = array())
    {
        $limit = $this->parseLimit($options);
        $windowSeconds = $this->parseWindow($options);
        $since = ($windowSeconds === -1) ? null : (time() - $windowSeconds);

        $EventReport = ClassRegistry::init('EventReport');

        // Reuse the model's own ACL builder (public), then add the feed's
        // own filters as top-level AND'd conditions. Site-admin → buildACL
        // returns [] (sees all); non-admin → ['AND' => [...]] which composes
        // fine with the extra top-level keys.
        $conditions = $EventReport->buildACLConditions($user);
        $conditions['EventReport.deleted'] = 0;
        if ($since !== null) {
            $conditions['EventReport.timestamp >='] = $since;
        }

        $reports = $EventReport->find('all', array(
            'conditions' => $conditions,
            'contain' => EventReport::DEFAULT_CONTAIN,
            'recursive' => -1,
            'order' => array('EventReport.timestamp' => 'DESC'),
            'limit' => $limit,
        ));

        $rows = array();
        foreach ($reports as $report) {
            $r = isset($report['EventReport']) ? $report['EventReport'] : array();
            $ev = isset($report['Event']) && is_array($report['Event']) ? $report['Event'] : array();

            $name = isset($r['name']) ? (string)$r['name'] : '';
            if ($name === '') {
                continue; // FeedList skips title-less rows anyway; skip early
            }
            $id = isset($r['id']) ? (int)$r['id'] : 0;
            $eventId = isset($ev['id']) ? (int)$ev['id']
                : (isset($r['event_id']) ? (int)$r['event_id'] : 0);
            $org = isset($ev['Orgc']['name']) ? (string)$ev['Orgc']['name'] : '';

            $rows[] = array(
                'icon' => 'file-alt',
                'title' => $name,
                'org' => $org,
                'timestamp' => isset($r['timestamp']) ? (int)$r['timestamp'] : 0,
                'context' => $eventId > 0 ? ('Event #' . $eventId) : null,
                'chips' => array(__('Report')),
                'subtitle' => $this->snippet(isset($r['content']) ? $r['content'] : ''),
                'drilldown' => $id > 0 ? ('/eventReports/view/' . $id) : null,
            );
        }

        // FeedList consumes the BARE row list (no { data: } wrapper).
        return $rows;
    }

    /**
     * Clamp the configured limit to a sane [1, MAX_LIMIT] range; default 10.
     */
    private function parseLimit($options)
    {
        $raw = isset($options['limit']) ? (int)$options['limit'] : 0;
        if ($raw <= 0) {
            $raw = 10;
        }
        return max(1, min(self::MAX_LIMIT, $raw));
    }

    /**
     * Window seconds-back from config. "<N>d" → N*86400; -1 / "-1" / empty →
     * -1 (no time bound — the feed is N-newest-bounded); other → int seconds.
     * Mirrors the OverlapWithMyOrgWidget / TrendingWidget parsing (the
     * canonical adapter pre-translates ISO durations to the "Nd" form).
     */
    private function parseWindow($options)
    {
        $tw = isset($options['time_window']) ? $options['time_window'] : null;
        if ($tw === -1 || $tw === '-1') {
            return -1;
        }
        if (is_string($tw) && substr($tw, -1) === 'd') {
            return ((int)substr($tw, 0, -1)) * 24 * 60 * 60;
        }
        if (empty($tw)) {
            return -1;
        }
        return (int)$tw;
    }

    /**
     * A one-line plain-text snippet of a report's markdown content. Event
     * reports are markdown with MISP-specific embed syntax, so a raw slice is
     * noisy (`## headings`, `**bold**`, and `@[attribute](<uuid>)` references
     * showing bare UUIDs). Strip that structural markup down to readable prose,
     * collapse whitespace, bound the length (FeedList truncates further to its
     * card width). `_` is deliberately left alone (it appears in identifiers,
     * not just markdown italics).
     */
    private function snippet($content)
    {
        $c = trim((string)$content);
        if ($c === '') {
            return '';
        }
        $c = strip_tags($c);
        // MISP report embeds: @[attribute](uuid) / @[object](uuid) / … → drop.
        $c = preg_replace('/@\[[a-z_]+\]\([^)]*\)/i', '', $c);
        // Markdown links [text](url) → keep the visible text only.
        $c = preg_replace('/\[([^\]]*)\]\([^)]*\)/', '$1', $c);
        // Heading / emphasis / blockquote / code structural markers.
        $c = preg_replace('/[#*`>~]+/', '', $c);
        $c = preg_replace('/\s+/', ' ', $c);
        $c = trim($c);
        if (function_exists('mb_substr')) {
            return mb_substr($c, 0, self::SNIPPET_CHARS);
        }
        return substr($c, 0, self::SNIPPET_CHARS);
    }
}
