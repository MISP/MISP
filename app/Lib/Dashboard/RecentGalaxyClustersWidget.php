<?php

/**
 * Recently Added Galaxy Clusters (dashboard v2, analyst track — AD-W12 / AD-20).
 *
 * A "what's new" feed of the N most-recently added/updated **local** galaxy
 * clusters the viewer can see, newest first — new threat actors, malware,
 * techniques, etc. that this instance's analysts have created or forked.
 *
 * Population = LOCAL clusters only (`default = 0`) (AD-20, user fork): the
 * ~tens-of-thousands of shipped (`default = 1`) clusters are bulk-imported
 * with batch `version` dates, so including them would flood the feed with
 * "new" clusters on every sync/import. `default = 0` is the genuinely
 * user-"added" set.
 *
 * Render = the shared `FeedList` kind (AD-17): Galaxy.icon · cluster value
 * (title) · description snippet · author org · relative time · galaxy-name
 * chip · drilldown to the cluster.
 *
 * Recency anchor = `version` (epoch — the ONLY timestamp on galaxy_clusters;
 * set on create AND edit, so this is honestly "recently added or updated").
 * A few legacy rows carry version≈0; they sort to the bottom and a finite
 * window drops them.
 *
 * Fetch / ACL: GalaxyCluster->fetchGalaxyClusters($user, …) applies the
 * model's own buildConditions (org / distribution / sharing-group + parent-
 * galaxy access; site-admin sees all) and honours order/limit/conditions;
 * `contain ['Galaxy','Orgc']` hydrates the galaxy icon/name + author org.
 *
 * Cache: NONE — per-user ACL'd live fetch (like the W6 event stream).
 *
 * Additive-only: a new widget class, render = the existing FeedList kind.
 */
class RecentGalaxyClustersWidget
{
    public $title = 'Recently Added Galaxy Clusters';
    public $category = 'tags';
    public $render = 'FeedList';
    public $width = 4;
    public $height = 2;

    public $params = array(
        'time_window' => 'Optional time filter: only clusters whose version '
            . '(added/updated time) falls in this window, going back in seconds '
            . '(e.g. "30d"); -1 = no time filter (just the newest N). Default: -1.',
        'limit' => 'How many clusters to show (newest first). Default: 10.',
    );

    public $schema = array(
        'time_window' => array(
            'type' => 'time_window',
            'default' => -1,
            'help' => 'Optional window — only clusters added/updated in the last '
                . 'N days/hours, or all time. Driven by the dashboard toolbar.',
        ),
        'limit' => array(
            'type' => 'int',
            'default' => 10,
            'help' => 'Number of recent local clusters to list (newest first).',
        ),
    );

    public $placeholder =
'{
    "time_window": -1,
    "limit": 10
}';

    public $description = 'A feed of the most recently added or updated local '
        . 'galaxy clusters you can see (custom / forked clusters, not the '
        . 'bulk-shipped defaults), newest first.';

    const MAX_LIMIT = 50;
    const SNIPPET_CHARS = 160;

    public function handler($user, $options = array())
    {
        $limit = $this->parseLimit($options);
        $windowSeconds = $this->parseWindow($options);
        $since = ($windowSeconds === -1) ? null : (time() - $windowSeconds);

        $GalaxyCluster = ClassRegistry::init('GalaxyCluster');

        // Reuse the model's public ACL builder, then add the feed's filters as
        // top-level AND'd conditions: local clusters only (default=0),
        // non-deleted, optional version window. (A direct find() rather than
        // fetchGalaxyClusters() — the latter's findOrder rejects an aliased
        // order and its post-processing doesn't hydrate Galaxy/Orgc here. Both
        // are standard-FK belongsTo associations, so Containable hydrates them
        // in a plain find; ACL-identical to fetchGalaxyClusters, still additive.)
        $conditions = $GalaxyCluster->buildConditions($user);
        $conditions['GalaxyCluster.default'] = 0;
        $conditions['GalaxyCluster.deleted'] = 0;
        if ($since !== null) {
            $conditions['GalaxyCluster.version >='] = $since;
        }

        $clusters = $GalaxyCluster->find('all', array(
            'conditions' => $conditions,
            'contain' => array('Galaxy', 'Orgc'),
            'recursive' => -1,
            'order' => array('GalaxyCluster.version' => 'DESC'),
            'limit' => $limit,
        ));

        $rows = array();
        foreach ($clusters as $cluster) {
            $c = isset($cluster['GalaxyCluster']) ? $cluster['GalaxyCluster'] : array();
            if (empty($c)) {
                continue;
            }
            $g = isset($cluster['Galaxy']) && is_array($cluster['Galaxy']) ? $cluster['Galaxy'] : array();

            $value = isset($c['value']) ? (string)$c['value'] : '';
            if ($value === '') {
                continue;
            }
            $id = isset($c['id']) ? (int)$c['id'] : 0;
            $org = isset($cluster['Orgc']['name']) ? (string)$cluster['Orgc']['name'] : '';

            // Chip = the human galaxy name (fallback to the machine type).
            $galaxyLabel = '';
            if (!empty($g['name'])) {
                $galaxyLabel = (string)$g['name'];
            } elseif (!empty($g['type'])) {
                $galaxyLabel = (string)$g['type'];
            }

            $rows[] = array(
                'icon' => !empty($g['icon']) ? (string)$g['icon'] : null,
                'title' => $value,
                'org' => $org,
                'timestamp' => isset($c['version']) ? (int)$c['version'] : 0,
                'chips' => $galaxyLabel !== '' ? array($galaxyLabel) : array(),
                'subtitle' => $this->snippet(isset($c['description']) ? $c['description'] : ''),
                'drilldown' => $id > 0 ? ('/galaxy_clusters/view/' . $id) : null,
            );
        }

        // FeedList consumes the BARE row list (no { data: } wrapper).
        return $rows;
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
     * A one-line plain-text snippet of a cluster description: strip HTML,
     * collapse whitespace, bound the length (FeedList truncates further).
     */
    private function snippet($description)
    {
        $c = trim((string)$description);
        if ($c === '') {
            return '';
        }
        $c = strip_tags($c);
        $c = preg_replace('/\s+/', ' ', $c);
        $c = trim($c);
        if (function_exists('mb_substr')) {
            return mb_substr($c, 0, self::SNIPPET_CHARS);
        }
        return substr($c, 0, self::SNIPPET_CHARS);
    }
}
