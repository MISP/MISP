<?php

/**
 * MISP Cache Status — sync-server & feed cache-freshness widget (DD-40).
 *
 * Hub-and-spoke diagram (NetworkGraph render kind, DD-33) where the
 * spokes are:
 *
 *   - every Server with `caching_enabled = 1`  (server-rack glyph)
 *   - every Feed with `caching_enabled = 1`    (RSS-waves glyph, DD-40)
 *
 * Each spoke is coloured by its cache age:
 *
 *   - info     — cached within the last 24 h        (`< 86400 s`)
 *   - warning  — cached, but older than 24 h        (`>= 86400 s`)
 *   - danger   — caching enabled but never cached   (`cache_timestamp` null)
 *
 * Sibling to `MispAdminSyncTestWidget`: same front end (NetworkGraph),
 * different dimension. Pure consumer of the existing model helpers
 * `Server::attachServerCacheTimestamps()` and
 * `Feed::attachFeedCacheTimestamps()` — they read
 * `misp:server_cache_timestamp:{id}` / `misp:feed_cache_timestamp:{id}`
 * from Redis. No Redis key read directly here, no logic re-implemented.
 *
 * Site-admin only. Manual refresh — the diagram doesn't auto-refresh
 * (cache state moves slowly; auto-polling buys nothing and adds Redis
 * pressure with no user looking).
 */
class MispCacheStatusWidget
{
    public $title = 'MISP Cache Status';
    public $category = 'system';
    public $render = 'NetworkGraph';
    public $width = 4;
    public $height = 5;
    public $params = array();
    public $schema = array();
    public $description = 'Sync servers and feeds with caching enabled, coloured by cache age (info < 1d, warn >= 1d, danger no cache).';
    // Tiny v1-style cache to absorb refresh-button spam within a tick;
    // not the freshness-controlling cache (the timestamps in Redis are
    // already cheap to read and they move slowly).
    public $cacheLifetime = 1;
    public $autoRefreshDelay = false;

    /** @var Server */
    private $Server;
    /** @var Feed */
    private $Feed;

    public function handler($user, $options = array())
    {
        $this->Server = ClassRegistry::init('Server');
        $this->Feed   = ClassRegistry::init('Feed');

        $nodes = array($this->_hubNode());
        $links = array();

        $serverCount = $this->_addServerSpokes($nodes, $links);
        $feedCount   = $this->_addFeedSpokes($nodes, $links);

        if (($serverCount + $feedCount) === 0) {
            return array(
                'nodes' => $nodes,
                'links' => $links,
                'error' => __('No sync servers or feeds with caching enabled.'),
            );
        }

        return array('nodes' => $nodes, 'links' => $links);
    }

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }

    // ----------------------------------------------------------------

    private function _hubNode()
    {
        $baseurl = (string)Configure::read('MISP.baseurl');
        $selfName = (string)Configure::read('MISP.org');
        return array(
            'id' => 'self',
            'name' => $selfName !== '' ? $selfName : __('This instance'),
            'url' => $baseurl,
            'status' => 'self',
            'message' => __('Current instance (cache root).'),
        );
    }

    /**
     * @return int Number of server spokes appended.
     */
    private function _addServerSpokes(array &$nodes, array &$links)
    {
        $servers = $this->Server->find('all', array(
            'fields' => array('id', 'url', 'name'),
            'conditions' => array('caching_enabled' => 1),
            'recursive' => -1,
        ));
        if (empty($servers)) {
            return 0;
        }
        $servers = $this->Server->attachServerCacheTimestamps($servers);
        foreach ($servers as $row) {
            $id = 'srv-' . (int)$row['Server']['id'];
            $rawTs = $row['Server']['cache_timestamp'] ?? null;
            list($status, $ageLabel, $messagePrefix) = $this->_classify($rawTs);
            $name = sprintf(
                '#%d %s · %s',
                (int)$row['Server']['id'],
                (string)$row['Server']['name'],
                $ageLabel
            );
            $nodes[] = array(
                'id'      => $id,
                'kind'    => 'server',
                'name'    => $name,
                'url'     => (string)($row['Server']['url'] ?? ''),
                'status'  => $status,
                'message' => $messagePrefix . __('Server cache.'),
            );
            $links[] = array('source' => 'self', 'target' => $id);
        }
        return count($servers);
    }

    /**
     * @return int Number of feed spokes appended.
     */
    private function _addFeedSpokes(array &$nodes, array &$links)
    {
        $feeds = $this->Feed->find('all', array(
            'fields' => array('id', 'name', 'url', 'provider', 'source_format'),
            'conditions' => array('caching_enabled' => 1),
            'recursive' => -1,
        ));
        if (empty($feeds)) {
            return 0;
        }
        $feeds = $this->Feed->attachFeedCacheTimestamps($feeds);
        foreach ($feeds as $row) {
            $id = 'feed-' . (int)$row['Feed']['id'];
            $rawTs = $row['Feed']['cache_timestamp'] ?? null;
            list($status, $ageLabel, $messagePrefix) = $this->_classify($rawTs);
            $name = sprintf(
                '%s · %s',
                (string)$row['Feed']['name'],
                $ageLabel
            );
            $tooltipUrl = (string)($row['Feed']['provider'] ?? '');
            if ($tooltipUrl === '') {
                $tooltipUrl = (string)($row['Feed']['url'] ?? '');
            }
            $sourceFormat = (string)($row['Feed']['source_format'] ?? '');
            $msg = $messagePrefix . __('Feed cache.');
            if ($sourceFormat !== '') {
                $msg .= ' ' . sprintf(__('Format: %s.'), $sourceFormat);
            }
            $nodes[] = array(
                'id'      => $id,
                'kind'    => 'feed',
                'name'    => $name,
                'url'     => $tooltipUrl,
                'status'  => $status,
                'message' => $msg,
            );
            $links[] = array('source' => 'self', 'target' => $id);
        }
        return count($feeds);
    }

    /**
     * Map a raw cache_timestamp (string|int|null|false from Redis) to
     * (status, age-label, message-prefix) per the DD-40 thresholds:
     * empty → danger/never; > 1d → warning/stale; otherwise → info/fresh.
     */
    private function _classify($rawTs)
    {
        if (empty($rawTs) && $rawTs !== '0') {
            return array('error', __('never'), __('Caching enabled — never cached. '));
        }
        $ts = (int)$rawTs;
        $age = time() - $ts;
        if ($age < 0) {
            $age = 0;
        }
        $ageLabel = $this->_humanizeAge($age);
        if ($age >= 86400) {
            return array(
                'warn',
                $ageLabel,
                sprintf(__('Cached %s ago — stale. '), $ageLabel),
            );
        }
        return array(
            'info',
            $ageLabel,
            sprintf(__('Cached %s ago. '), $ageLabel),
        );
    }

    /**
     * Humanise an age in seconds to the two-largest-units form
     * ("2d 4h", "5h 30m", "45m 12s"). Shape lifted from
     * `IndexTable/Fields/caching.ctp` for visual consistency with the
     * existing Server / Feed list views.
     */
    private function _humanizeAge($seconds)
    {
        $seconds = (int)$seconds;
        if ($seconds < 60) {
            return $seconds . 's';
        }
        $days = (int)floor($seconds / 86400);
        $remAfterDays = $seconds - $days * 86400;
        $hours = (int)floor($remAfterDays / 3600);
        $remAfterHours = $remAfterDays - $hours * 3600;
        $minutes = (int)floor($remAfterHours / 60);
        $secs = $remAfterHours - $minutes * 60;

        if ($days > 0) {
            return $hours > 0 ? sprintf('%dd %dh', $days, $hours) : sprintf('%dd', $days);
        }
        if ($hours > 0) {
            return $minutes > 0 ? sprintf('%dh %dm', $hours, $minutes) : sprintf('%dh', $hours);
        }
        return $secs > 0 ? sprintf('%dm %ds', $minutes, $secs) : sprintf('%dm', $minutes);
    }
}
