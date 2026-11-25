<?php

/**
 * The workspace: the collection a user works in, and the graph of their
 * organisation on it that lays it out. Kept in two internal user settings,
 * out of both logs: `active_workspace` {collection_uuid, graph_uuid}, and
 * `recent_workspaces`, the collections used last, newest first.
 */
class ActiveWorkspaceTool
{
    const SETTING = 'active_workspace';
    const RECENT_SETTING = 'recent_workspaces';
    const RECENT_CAP = 20;

    /** Collections the chooser lists besides the recently used ones. */
    const LIST_LIMIT = 200;

    const SCOPES = ['mine', 'org'];

    /**
     * @param array $user
     * @return array{collection_uuid: string, graph_uuid: string|null}|null
     */
    public static function stored(array $user)
    {
        $stored = ClassRegistry::init('UserSetting')->getValueForUser($user['id'], self::SETTING);
        if (!is_array($stored) || !self::isUuid($stored['collection_uuid'] ?? null)) {
            return null;
        }
        $graph = $stored['graph_uuid'] ?? null;
        return [
            'collection_uuid' => strtolower($stored['collection_uuid']),
            'graph_uuid' => self::isUuid($graph) ? strtolower($graph) : null,
        ];
    }

    /**
     * The user's workspace, as long as it still is one. A collection that is
     * gone or that they can no longer edit ends it; a graph that is gone or
     * that is no longer their organisation's on that collection leaves the
     * collection without one. Either is written back.
     *
     * @param array $user
     * @return array{Collection: array|null, Graph: array|null}
     */
    public static function forUser(array $user)
    {
        $stored = self::stored($user);
        if ($stored === null) {
            return ['Collection' => null, 'Graph' => null];
        }
        list($collection, $graph, $refusal) = self::lookUp($user, $stored['collection_uuid'], $stored['graph_uuid']);
        if ($refusal === 'collection' || $refusal === 'edit') {
            self::write($user, self::SETTING, ['collection_uuid' => null, 'graph_uuid' => null]);
            return ['Collection' => null, 'Graph' => null];
        }
        if ($refusal === 'graph') {
            self::write($user, self::SETTING, ['collection_uuid' => $collection['uuid'], 'graph_uuid' => null]);
        }
        return ['Collection' => $collection, 'Graph' => $graph];
    }

    /**
     * @param array $user
     * @param string $collectionUuid
     * @param string|null $graphUuid
     * @return array [collection|null, graph|null, refusal|null]: 'collection'
     *               when it is not there for this user, 'edit' when they may
     *               not edit it, 'graph' when the graph is not their
     *               organisation's on it
     */
    public static function lookUp(array $user, $collectionUuid, $graphUuid = null)
    {
        if (!self::isUuid($collectionUuid)) {
            return [null, null, 'collection'];
        }
        $found = ClassRegistry::init('Collection')->workspaceSummaries($user, [
            'Collection.uuid' => self::spellings($collectionUuid),
        ], 1);
        if (empty($found)) {
            return [null, null, 'collection'];
        }
        $collection = $found[0];
        if (!$collection['_canEdit']) {
            return [$collection, null, 'edit'];
        }
        if ($graphUuid === null) {
            return [$collection, null, null];
        }
        $graph = self::isUuid($graphUuid) ? self::graphOn($user, $collection, $graphUuid) : null;
        return [$collection, $graph, $graph === null ? 'graph' : null];
    }

    /**
     * Make it the workspace, or end it with a null collection. Refusals are
     * lookUp()'s; nothing is written then.
     *
     * @param array $user
     * @param string|null $collectionUuid
     * @param string|null $graphUuid
     * @param bool $graphNamed False when the caller named no graph: the
     *             newest of the organisation's graphs on it lays it out
     * @return array [{Collection, Graph}, refusal|null]
     */
    public static function choose(array $user, $collectionUuid, $graphUuid = null, $graphNamed = true)
    {
        if ($collectionUuid === null) {
            self::write($user, self::SETTING, ['collection_uuid' => null, 'graph_uuid' => null]);
            return [['Collection' => null, 'Graph' => null], null];
        }
        if (!$graphNamed && self::isUuid($collectionUuid)) {
            $graphUuid = self::newestGraphOn($user, $collectionUuid);
        }
        list($collection, $graph, $refusal) = self::lookUp($user, $collectionUuid, $graphUuid);
        if ($refusal !== null) {
            return [['Collection' => $refusal === 'collection' ? null : $collection, 'Graph' => null], $refusal];
        }
        self::write($user, self::SETTING, [
            'collection_uuid' => $collection['uuid'],
            'graph_uuid' => $graph ? $graph['uuid'] : null,
        ]);
        self::used($user, $collection['uuid']);
        return [['Collection' => $collection, 'Graph' => $graph], null];
    }

    /**
     * @param array $user
     * @return array lowercase collection uuid => when last used, newest first
     */
    public static function recent(array $user)
    {
        $stored = ClassRegistry::init('UserSetting')->getValueForUser($user['id'], self::RECENT_SETTING);
        $recent = [];
        foreach (is_array($stored) ? $stored : [] as $entry) {
            if (!is_array($entry) || !self::isUuid($entry['collection_uuid'] ?? null) || !is_numeric($entry['at'] ?? null)) {
                continue;
            }
            $uuid = strtolower($entry['collection_uuid']);
            if (!isset($recent[$uuid])) {
                $recent[$uuid] = (int)$entry['at'];
            }
            if (count($recent) >= self::RECENT_CAP) {
                break;
            }
        }
        return $recent;
    }

    /**
     * Put the collection first among those used last. A failed write is
     * dropped: the list is a convenience, never worth failing the request.
     *
     * @param array $user
     * @param string $collectionUuid
     * @return void
     */
    public static function used(array $user, $collectionUuid)
    {
        $uuid = strtolower((string)$collectionUuid);
        $entries = [['collection_uuid' => $uuid, 'at' => time()]];
        foreach (self::recent($user) as $other => $at) {
            if ($other !== $uuid && count($entries) < self::RECENT_CAP) {
                $entries[] = ['collection_uuid' => $other, 'at' => $at];
            }
        }
        try {
            self::write($user, self::RECENT_SETTING, $entries);
        } catch (Exception $e) {
            CakeLog::write('warning', 'ActiveWorkspaceTool::used — ' . $e->getMessage());
        }
    }

    /**
     * The collections the user may make their workspace: those they may
     * edit, the ones used last first, newest use first, then the rest,
     * newest first. Each carries `used`, when it was last used, or null.
     *
     * @param array $user
     * @param string $scope 'mine', created by the user, or 'org', by their
     *                      organisation
     * @return array
     */
    public static function editable(array $user, $scope)
    {
        if (empty($user['Role']['perm_site_admin']) && empty($user['Role']['perm_modify'])) {
            return [];
        }
        $condition = $scope === 'mine'
            ? ['Collection.user_id' => $user['id']]
            : ['Collection.orgc_id' => $user['org_id']];
        $Collection = ClassRegistry::init('Collection');
        $recent = self::recent($user);
        $rows = [];
        if (!empty($recent)) {
            $spellings = [];
            foreach (array_keys($recent) as $uuid) {
                $spellings = array_merge($spellings, self::spellings($uuid));
            }
            $rows = $Collection->workspaceSummaries($user, [$condition, ['Collection.uuid' => $spellings]]);
        }
        $rows = array_merge($rows, $Collection->workspaceSummaries($user, [$condition], self::LIST_LIMIT));
        $listed = [];
        $used = [];
        $rest = [];
        foreach ($rows as $row) {
            if (isset($listed[$row['uuid']]) || !$row['_canEdit']) {
                continue;
            }
            $listed[$row['uuid']] = true;
            $row['used'] = $recent[$row['uuid']] ?? null;
            if ($row['used'] === null) {
                $rest[] = $row;
            } else {
                $used[] = $row;
            }
        }
        usort($used, function ($a, $b) {
            return $b['used'] <=> $a['used'];
        });
        return array_merge($used, $rest);
    }

    /**
     * @param array $user
     * @param string $collectionUuid
     * @return string|null The newest of the organisation's graphs on it
     */
    private static function newestGraphOn(array $user, $collectionUuid)
    {
        $graphs = ClassRegistry::init('Graph')->summaries($user, [
            'Graph.object_type' => 'Collection',
            'Graph.object_uuid' => self::spellings($collectionUuid),
            'Graph.orgc_uuid' => $user['Organisation']['uuid'] ?? '',
        ], ['targets' => false, 'counts' => false, 'limit' => 1]);
        return $graphs[0]['uuid'] ?? null;
    }

    /**
     * A graph of the user's organisation on this collection, that they may read.
     *
     * @param array $user
     * @param array $collection workspaceSummaries()'s
     * @param string $graphUuid
     * @return array|null The graph's summary
     */
    private static function graphOn(array $user, array $collection, $graphUuid)
    {
        // Read on every page: the stored count is enough
        $graphs = ClassRegistry::init('Graph')->summaries($user, [
            'Graph.uuid' => self::spellings($graphUuid),
        ], ['targets' => false, 'counts' => false]);
        $graph = $graphs[0] ?? null;
        if (
            $graph === null
            || $graph['object_type'] !== 'Collection'
            || strtolower((string)$graph['object_uuid']) !== $collection['uuid']
            || strtolower((string)$graph['orgc_uuid']) !== strtolower((string)($user['Organisation']['uuid'] ?? ''))
        ) {
            return null;
        }
        return $graph;
    }

    /**
     * The legacy log is suppressed: its full-change entry would record the
     * choice.
     *
     * @param array $user
     * @param string $setting
     * @param mixed $value
     * @return bool
     */
    private static function write(array $user, $setting, $value)
    {
        $UserSetting = ClassRegistry::init('UserSetting');
        $logged = $UserSetting->Behaviors->enabled('SysLogLogable.SysLogLogable');
        $UserSetting->Behaviors->disable('SysLogLogable.SysLogLogable');
        try {
            return (bool)$UserSetting->setSettingInternal($user['id'], $setting, $value);
        } finally {
            if ($logged) {
                $UserSetting->Behaviors->enable('SysLogLogable.SysLogLogable');
            }
        }
    }

    /**
     * Stored as each creator spelled it.
     *
     * @param string $uuid
     * @return string[]
     */
    private static function spellings($uuid)
    {
        return array_values(array_unique([$uuid, strtolower($uuid), strtoupper($uuid)]));
    }

    /**
     * @param mixed $value
     * @return bool
     */
    private static function isUuid($value)
    {
        return is_string($value) && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $value) === 1;
    }
}
