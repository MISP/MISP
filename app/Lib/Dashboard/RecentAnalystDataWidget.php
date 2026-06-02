<?php

/**
 * Recent Analyst Data (dashboard v2, analyst track — AD-W11 / AD-19).
 *
 * A "what's new" feed of the most recent analyst **Notes and Opinions** the
 * viewer can see, newest first — "what are people saying lately?". Each row
 * shows the note / opinion text, who wrote it, when, and — per the user's
 * requirement — the TARGET object type it is attached to (Event, Attribute,
 * Galaxy Cluster, …), as a chip.
 *
 * RE-SCOPED from the original "analyst data on MY ORG's events" brief
 * (AD-19): that needed a child-UUID `IN` list (notes on attributes/objects
 * inside my events) — a perf / feasibility risk the user flagged — so it was
 * dropped in favour of the simpler, strictly safe "newest analyst data I can
 * see". **Notes + Opinions only** (Relationships are object-to-object
 * structural links, not commentary — excluded); **any target type**.
 *
 * Render = the shared `FeedList` kind (AD-17): icon (sticky-note / balance-
 * scale) · text (title) · author org · relative time · type + target-type
 * chips · best-effort drilldown to the target.
 *
 * Fetch / ACL: one ACL'd find per type via the model's own
 * AnalystData::buildConditions($user) (org_uuid + distribution + sharing
 * group; site-admin sees all), ordered by `modified` DESC, limited; the two
 * lists are merged and re-sorted to the global top-N. Viewing relies on this
 * distribution ACL — NOT `perm_analyst_data`, matching
 * AnalystDataController::index() (the perm_analyst_data gate there is on a
 * sync action, not on viewing).
 *
 * Recency anchor = `modified` (datetime, UTC). Cache: NONE — per-user ACL'd
 * live fetch (like the W6 event stream).
 *
 * Drilldown: Event targets link to `/events/view/<uuid>` (Events::view
 * resolves a uuid); other target types show the type chip without a link
 * (richer per-type linking is a noted follow-up). All DD-03-gated.
 *
 * Additive-only: a new widget class, render = the existing FeedList kind.
 */
class RecentAnalystDataWidget
{
    public $title = 'Recent Analyst Data';
    public $category = 'events';
    public $render = 'FeedList';
    public $width = 4;
    public $height = 2;

    public $params = array(
        'time_window' => 'Optional time filter: only analyst data modified in '
            . 'this window, going back in seconds (e.g. "30d"); -1 = no time '
            . 'filter (just the newest N). Default: -1.',
        'limit' => 'How many notes/opinions to show (newest first). Default: 10.',
    );

    public $schema = array(
        'time_window' => array(
            'type' => 'time_window',
            'default' => -1,
            'help' => 'Optional window — only analyst data modified in the last '
                . 'N days/hours, or all time. Driven by the dashboard toolbar.',
        ),
        'limit' => array(
            'type' => 'int',
            'default' => 10,
            'help' => 'Number of recent notes/opinions to list (newest first).',
        ),
    );

    public $placeholder =
'{
    "time_window": -1,
    "limit": 10
}';

    public $description = 'A feed of the most recent analyst Notes and Opinions '
        . 'you can see, newest first — each tagged with the kind of object it '
        . 'comments on.';

    const MAX_LIMIT = 50;
    const TITLE_CHARS = 110;

    /** type => [FontAwesome icon, text column]. */
    private $sources = array(
        'Note' => array('icon' => 'sticky-note', 'text' => 'note'),
        'Opinion' => array('icon' => 'balance-scale', 'text' => 'comment'),
    );

    public function handler($user, $options = array())
    {
        $limit = $this->parseLimit($options);
        $windowSeconds = $this->parseWindow($options);
        $since = ($windowSeconds === -1) ? null : (time() - $windowSeconds);
        // `modified` is stored UTC; bound it with a UTC string when windowed.
        $sinceUtc = ($since !== null) ? gmdate('Y-m-d H:i:s', $since) : null;

        // Gather the newest-N of each type, then resolve author org names in
        // one bulk query. (The model's Org/Orgc belongsTo is a uuid-keyed
        // custom association with foreignKey=false — it does not hydrate
        // reliably through Containable here, so we map orgc_uuid → name
        // ourselves: deterministic and a single extra query.)
        $collected = array();
        $orgcUuids = array();
        foreach ($this->sources as $type => $meta) {
            $Model = ClassRegistry::init($type);
            $conditions = $Model->buildConditions($user);
            if ($sinceUtc !== null) {
                $conditions[$type . '.modified >='] = $sinceUtc;
            }
            $items = $Model->find('all', array(
                'conditions' => $conditions,
                'order' => array($type . '.modified' => 'DESC'),
                'limit' => $limit,
                'recursive' => -1,
            ));
            foreach ($items as $item) {
                $d = isset($item[$type]) ? $item[$type] : array();
                if (empty($d)) {
                    continue;
                }
                $collected[] = array('type' => $type, 'meta' => $meta, 'd' => $d);
                if (!empty($d['orgc_uuid'])) {
                    $orgcUuids[(string)$d['orgc_uuid']] = true;
                }
            }
        }

        $orgMap = array();
        if (!empty($orgcUuids)) {
            $Org = ClassRegistry::init('Organisation');
            $orgMap = $Org->find('list', array(
                'recursive' => -1,
                'conditions' => array('Organisation.uuid' => array_keys($orgcUuids)),
                'fields' => array('Organisation.uuid', 'Organisation.name'),
            ));
        }

        $rows = array();
        foreach ($collected as $c) {
            $row = $this->mapRow($c['type'], $c['meta'], $c['d'], $orgMap);
            if ($row !== null) {
                $rows[] = $row;
            }
        }

        // Merge the two per-type lists into the global newest-N by `modified`.
        usort($rows, function ($a, $b) {
            return (isset($b['timestamp']) ? $b['timestamp'] : 0)
                <=> (isset($a['timestamp']) ? $a['timestamp'] : 0);
        });

        // FeedList consumes the BARE row list (no { data: } wrapper).
        return array_slice($rows, 0, $limit);
    }

    /**
     * Build one FeedList row from a Note / Opinion record. Returns null when
     * there's nothing meaningful to show.
     */
    private function mapRow($type, $meta, $d, $orgMap)
    {
        if (empty($d)) {
            return null;
        }

        $objType = isset($d['object_type']) ? (string)$d['object_type'] : '';
        $objUuid = isset($d['object_uuid']) ? (string)$d['object_uuid'] : '';
        $orgcUuid = isset($d['orgc_uuid']) ? (string)$d['orgc_uuid'] : '';
        $org = ($orgcUuid !== '' && isset($orgMap[$orgcUuid])) ? (string)$orgMap[$orgcUuid] : '';
        $ts = isset($d['modified']) ? (int)strtotime($d['modified'] . ' UTC') : 0;

        $text = $this->clean(isset($d[$meta['text']]) ? $d[$meta['text']] : '');
        $subtitle = '';

        if ($type === 'Opinion') {
            // 0–100 agreement scale. The comment (if any) is the headline;
            // the numeric score rides the subtitle. With no comment, the
            // score IS the headline.
            $score = isset($d['opinion']) ? (int)$d['opinion'] : null;
            $scoreLabel = ($score !== null)
                ? sprintf(__('Opinion score: %d/100'), $score) : '';
            if ($text !== '') {
                $title = $this->truncate($text, self::TITLE_CHARS);
                $subtitle = $scoreLabel;
            } else {
                $title = ($scoreLabel !== '') ? $scoreLabel : __('Opinion');
            }
        } else {
            // Note.
            $title = ($text !== '')
                ? $this->truncate($text, self::TITLE_CHARS)
                // Empty note text → still surface the note with a sensible label.
                : ($objType !== ''
                    ? sprintf(__('Note on %s'), $this->humanize($objType))
                    : __('Note'));
        }

        $chips = array(__($type));
        if ($objType !== '') {
            $chips[] = $this->humanize($objType);
        }

        // Drilldown: Event targets are viewable by uuid; others show the type
        // chip only (richer per-type linking is a follow-up). DD-03-gated.
        $drilldown = ($objType === 'Event' && $objUuid !== '')
            ? '/events/view/' . $objUuid
            : null;

        return array(
            'icon' => $meta['icon'],
            'title' => $title,
            'org' => $org,
            'timestamp' => $ts,
            'chips' => $chips,
            'subtitle' => $subtitle,
            'drilldown' => $drilldown,
        );
    }

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
     * Reduce note/opinion markdown to readable one-line prose: strip HTML,
     * MISP embed syntax (`@[attribute](<uuid>)`), markdown links / heading /
     * emphasis / code markers, and collapse whitespace. `_` left alone (it
     * appears in identifiers, not just markdown italics).
     */
    private function clean($s)
    {
        $c = trim((string)$s);
        if ($c === '') {
            return '';
        }
        $c = strip_tags($c);
        $c = preg_replace('/@\[[a-z_]+\]\([^)]*\)/i', '', $c);
        $c = preg_replace('/\[([^\]]*)\]\([^)]*\)/', '$1', $c);
        $c = preg_replace('/[#*`>~]+/', '', $c);
        $c = preg_replace('/\s+/', ' ', $c);
        return trim($c);
    }

    private function truncate($s, $len)
    {
        if (function_exists('mb_strlen')) {
            if (mb_strlen($s) <= $len) {
                return $s;
            }
            return rtrim(mb_substr($s, 0, $len)) . '…';
        }
        if (strlen($s) <= $len) {
            return $s;
        }
        return rtrim(substr($s, 0, $len)) . '…';
    }

    /**
     * "GalaxyCluster" → "Galaxy Cluster", "EventReport" → "Event Report" — a
     * readable label for the target-type chip.
     */
    private function humanize($type)
    {
        return trim(preg_replace('/(?<!^)([A-Z])/', ' $1', (string)$type));
    }
}
