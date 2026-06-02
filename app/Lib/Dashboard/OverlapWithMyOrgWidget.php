<?php

/**
 * Overlap-with-my-org (dashboard v2, analyst track — AD-W8 / AD-13, AD-14).
 *
 * The "affects me" payoff widget: surfaces NEW, ACL-visible events (those
 * whose Event.timestamp falls in the window) that CORRELATE with events my
 * own organisation created. Answers "what just landed that touches what we
 * track?" without a value-intersection scan.
 *
 * Approach (AD-13, forced by correlation-engine research — NOT a fork):
 * anchor on the bounded window-event set rather than scanning
 * `default_correlations` by org_id (which has no org_id/timestamp index, whose
 * org_id is visibility-not-creator, and which doesn't exist at all under the
 * OnDemand engine). For each candidate window event we call
 * Correlation::getRelatedEventIds() — ACL-correct AND engine-agnostic
 * (Default / NoAcl / OnDemand), inheriting correlation denoising + fuzzy
 * (ssdeep / CIDR) matches — and keep the candidate iff a related event's
 * orgc_id is my org. Overlap strength = # of my-org events the candidate
 * correlates to; rows rank by strength desc then recency.
 *
 * AD-14 (build refinement, user-chosen): `exclude_own_org` config (default
 * TRUE) drops candidates my OWN org created, so the widget reads as a pure
 * "external affects-me" signal. Set false to honour the literal AD-W8
 * candidate-set definition (every ACL-visible window event).
 *
 * Render: reuses the W6 `EventCards` kind (no new render kind / glyph) with an
 * additive "overlaps N of your events" badge — the per-record `_analyst_overlap`
 * payload key, which EventCards.ctp renders only when present, so the W6 event
 * stream is unaffected.
 *
 * Cache: per-ORG (AD-04) — the candidate fetch + getRelatedEventIds are
 * ACL-scoped, so an org-keyed entry is both correct and shared (WidgetCache
 * 'org' scope; site-admins land in the no-ACL `sa:` bucket).
 *
 * Additive-only: a brand-new widget class + one optional EventCards payload
 * key. No existing widget's behaviour changes.
 */
class OverlapWithMyOrgWidget
{
    public $title = 'Overlap with my organisation';
    public $category = 'events';
    public $render = 'EventCards';
    public $width = 4;
    public $height = 2;

    public $params = array(
        'time_window' => 'The time window, going back in seconds, for the '
            . 'candidate "new" events (e.g. "30d"; -1 = all historic data). '
            . 'Anchored on Event.timestamp. Default: 7 days.',
        'exclude_own_org' => 'Whether to drop candidate events your OWN org '
            . 'created (orgc), so the widget only surfaces other orgs\' new '
            . 'events that overlap yours — a pure "external affects-me" signal '
            . '(AD-14). Accepts true/false. Default: true.',
    );

    public $schema = array(
        'time_window' => array(
            'type' => 'time_window',
            'default' => 'P7D',
            'help' => 'Window over which an event counts as "new" (last N '
                . 'days/hours, or all time). Driven by the dashboard toolbar.',
        ),
    );

    public $placeholder =
'{
    "time_window": "30d",
    "exclude_own_org": true
}';

    public $description = 'Surfaces new events (in a time window) that '
        . 'correlate with events your organisation created — "what just landed '
        . 'that affects me". Each card shows how many of your events it '
        . 'overlaps.';

    // Cache (AD-04): per-ORG, ~20 min. Same-org users share one entry; the
    // candidate set + getRelatedEventIds are ACL-scoped, so an org key is both
    // correct and shared. Site-admins → the no-ACL `sa:` bucket.
    public $cache_duration = 1200;
    public $cache_scope = 'org';

    // Cost guard (AD-W8): cap the candidate window-event set (most-recent
    // first) before the per-event correlation lookups. If the fetch hits the
    // cap, older in-window events are NOT scanned — surfaced via CakeLog,
    // never silently dropped.
    const CANDIDATE_CAP = 200;

    public function handler($user, $options = array())
    {
        $myOrgId = isset($user['org_id']) ? (int)$user['org_id'] : 0;
        if ($myOrgId <= 0) {
            // No org → nothing can be "my org's". Empty, not an error.
            return array('data' => array(), 'fields' => array());
        }

        $windowSeconds = $this->parseWindow($options);
        $since = ($windowSeconds === -1) ? null : (time() - $windowSeconds);
        $excludeOwnOrg = $this->parseBool(
            isset($options['exclude_own_org']) ? $options['exclude_own_org'] : true,
            true
        );

        $Event = ClassRegistry::init('Event');

        // (1) Candidate set: ACL-visible events, most-recent first, capped.
        // Fetching the top-N most recent then window-filtering yields exactly
        // "top-N most recent in-window": when >=N events sit in-window the N
        // newest are all in-window (capped); when fewer do, the filter trims
        // to precisely the in-window set.
        $candidates = $Event->fetchEvent($user, array(
            'metadata' => 1,
            'limit' => self::CANDIDATE_CAP,
            'page' => 1,
            'order' => 'Event.timestamp DESC',
        ));
        $cappedFetch = (count($candidates) >= self::CANDIDATE_CAP);

        if ($since !== null) {
            $candidates = array_values(array_filter($candidates, function ($ev) use ($since) {
                return isset($ev['Event']['timestamp'])
                    && (int)$ev['Event']['timestamp'] >= $since;
            }));
        }
        if ($excludeOwnOrg) {
            $candidates = array_values(array_filter($candidates, function ($ev) use ($myOrgId) {
                return !isset($ev['Event']['orgc_id'])
                    || (int)$ev['Event']['orgc_id'] !== $myOrgId;
            }));
        }
        if (empty($candidates)) {
            if ($cappedFetch) {
                $this->logCap($windowSeconds);
            }
            return array('data' => array(), 'fields' => array());
        }

        // (2) Overlap test. getRelatedEventIds is engine-agnostic + ACL-correct.
        $sgids = $Event->SharingGroup->authorizedIds($user);
        $Correlation = $Event->Attribute->Correlation;

        $relatedByCandidate = array();
        $allRelated = array();
        foreach ($candidates as $ev) {
            $cid = (int)$ev['Event']['id'];
            $related = $Correlation->getRelatedEventIds($user, $cid, $sgids);
            $clean = array();
            foreach ($related as $rid) {
                $rid = (int)$rid;
                if ($rid === $cid) {
                    continue; // never count a self-correlation
                }
                $clean[$rid] = true;
                $allRelated[$rid] = true;
            }
            $relatedByCandidate[$cid] = array_keys($clean);
        }

        // Batched orgc lookup for every related event id (the related set is
        // already ACL-vetted by getRelatedEventIds; orgc_id is metadata).
        $orgcMap = array();
        if (!empty($allRelated)) {
            $orgcMap = $Event->find('list', array(
                'recursive' => -1,
                'conditions' => array('Event.id' => array_keys($allRelated)),
                'fields' => array('Event.id', 'Event.orgc_id'),
            ));
        }

        // (3) Score + keep candidates that overlap >=1 of my org's events.
        $scored = array();
        foreach ($candidates as $ev) {
            $cid = (int)$ev['Event']['id'];
            $strength = 0;
            foreach ($relatedByCandidate[$cid] as $rid) {
                if (isset($orgcMap[$rid]) && (int)$orgcMap[$rid] === $myOrgId) {
                    $strength++;
                }
            }
            if ($strength <= 0) {
                continue;
            }
            $ev['_analyst_overlap'] = $strength;
            $scored[] = array(
                'event' => $ev,
                'strength' => $strength,
                'ts' => isset($ev['Event']['timestamp']) ? (int)$ev['Event']['timestamp'] : 0,
            );
        }

        // Rank: overlap strength desc, then recency desc.
        usort($scored, function ($a, $b) {
            if ($a['strength'] !== $b['strength']) {
                return $b['strength'] - $a['strength'];
            }
            return $b['ts'] - $a['ts'];
        });

        if ($cappedFetch) {
            $this->logCap($windowSeconds);
        }

        return array(
            'data' => array_map(function ($s) { return $s['event']; }, $scored),
            'fields' => array(),
        );
    }

    /**
     * Window seconds-back from config. "<N>d" → N*86400; "-1" → -1 (all
     * history); other → int seconds; empty → 7 days. Mirrors TrendingWidget /
     * TrendingTags parsing (the canonical adapter pre-translates ISO P7D).
     */
    private function parseWindow($options)
    {
        $tw = isset($options['time_window']) ? $options['time_window'] : null;
        if (is_string($tw) && substr($tw, -1) === 'd') {
            return ((int)substr($tw, 0, -1)) * 24 * 60 * 60;
        }
        if ($tw === -1 || $tw === '-1') {
            return -1;
        }
        return empty($tw) ? (7 * 24 * 60 * 60) : (int)$tw;
    }

    /**
     * Lenient boolean config coercion (JSON true / "true" / 1 / "1" → true;
     * false / "false" / "no" / "off" / 0 / "0" → false), with a default for
     * null / unset / empty-string.
     */
    private function parseBool($value, $default)
    {
        if ($value === null) {
            return $default;
        }
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value)) {
            return $value !== 0;
        }
        if (is_string($value)) {
            $v = strtolower(trim($value));
            if ($v === '') {
                return $default;
            }
            return !in_array($v, array('0', 'false', 'no', 'off'), true);
        }
        return (bool)$value;
    }

    private function logCap($windowSeconds)
    {
        $win = ($windowSeconds === -1) ? 'all-time' : ($windowSeconds . 's');
        CakeLog::write('info', sprintf(
            'OverlapWithMyOrgWidget: candidate set capped at %d most-recent '
            . 'events (window=%s); older in-window events were not scanned.',
            self::CANDIDATE_CAP,
            $win
        ));
    }
}
