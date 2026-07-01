<?php
App::uses('AppModel', 'Model');
App::uses('ServerSyncTool', 'Tools');

class Collection extends AppModel
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable'
    );

    public $belongsTo = [
        'Orgc' => array(
            'className' => 'Organisation',
            'foreignKey' => 'orgc_id',
            'fields' => [
                'Orgc.id',
                'Orgc.uuid',
                'Orgc.name'
            ]
        ),
        'Org' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
            'fields' => [
                'Org.id',
                'Org.uuid',
                'Org.name'
            ]
        ),
        'User' => array(
            'className' => 'User',
            'foreignKey' => 'user_id',
            'fields' => [
                'User.id',
                'User.email'
            ]
        ),
        'SharingGroup' => [
            'className' => 'SharingGroup',
            'foreignKey' => 'sharing_group_id',
            'fields' => [
                'SharingGroup.id',
                'SharingGroup.uuid',
                'SharingGroup.name'
            ]
        ]
    ];

    public $hasMany = [
        'CollectionElement' => [
            'dependent' => true
        ]
    ];
 
    public $valid_targets = [
        'Attribute',
        'Event',
        'GalaxyCluster',
        'Galaxy',
        'Object',
        'Note',
        'Opinion',
        'Relationship',
        'Organisation',
        'SharingGroup'
    ];

    public $current_user = null;

    public $validate = [
        'uuid' => [
            'rule' => 'uuid',
            'message' => 'Please provide a valid RFC 4122 UUID',
        ]
    ];


    public function beforeValidate($options = array())
    {
        if (empty($this->data['Collection'])) {
            $this->data = ['Collection' => $this->data];
        }
        if (empty($this->id) && empty($this->data['Collection']['uuid'])) {
            $this->data['Collection']['uuid'] = CakeText::uuid();
        }
        if (empty($this->id)) {
            $this->data['Collection']['user_id'] = $this->current_user['id'];
            if (empty($this->data['Collection']['orgc_id']) || empty($this->current_user['Role']['perm_sync'])) {
                $this->data['Collection']['orgc_id'] = $this->current_user['Organisation']['id'];
            }
            $this->data['Collection']['org_id'] = $this->current_user['Organisation']['id'];
            $this->data['Collection']['user_id'] = $this->current_user['id'];
            // A locally created collection is never locked; only the sync-capture path
            // (running as a perm_sync user) may set locked=1 to mark a synced-in original.
            // Force it to 0 for everyone else so a web user cannot self-set locked via
            // mass assignment (mirrors the perm_sync exemption on orgc_id above).
            if (empty($this->current_user['Role']['perm_sync'])) {
                $this->data['Collection']['locked'] = 0;
            }
        }
        return true;
    }

    public function mayModify($user_id, $collection_id)
    {
        $user = $this->User->getAuthUser($user_id);
        $collection = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Collection.id' => $collection_id]
        ]);
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (empty($user['Role']['perm_modify'])) {
            return false;
        }
        if (!empty($user['Role']['perm_modify_org'])) {
            if ($user['org_id'] == $collection['Collection']['orgc_id']) {
                return true;
            }
            if ($user['Role']['perm_sync'] && $user['org_id'] == $collection['Collection']['org_id']) {
                return true;
            }            
        }
        if (!empty($user['Role']['perm_modify']) && $user['id'] === $collection['Collection']['user_id']) {
            return true;
        }
        return false;
    }

    public function mayView($user_id, $collection_id)
    {
        $user = $this->User->getAuthUser($user_id);
        $collection = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Collection.id' => $collection_id]
        ]);
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($collection['Collection']['org_id'] == $user['org_id']) {
            return true;
        }
        if (in_array($collection['Collection']['distribution'], [1,2,3])) {
            return true;
        }
        if ($collection['Collection']['distribution'] === 4) {
            $SharingGroup = ClassRegistry::init('SharingGroup');
            $sgs = $this->SharingGroup->fetchAllAuthorised($user, 'uuid');
            if (isset($sgs[$collection['Collection']['sharing_group_id']])) {
                return true;
            } else {
                return false;
            }
        }
        return false;
    }

    public function buildConditions($user_id)
    {
        $user = $this->User->getAuthUser($user_id);
        $SharingGroup = ClassRegistry::init('SharingGroup');
        $sgids = $SharingGroup->authorizedIds($user);
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            $conditions['OR'] = [
                [
                    'Collection.orgc_id' => $user['org_id'],
                    'Collection.org_id' => $user['org_id']
                ],
                [
                    'Collection.distribution IN' => [1,2,3]
                ],
                [
                    'AND' => [
                        'Collection.distribution' => 4,
                        'Collection.sharing_group_id' => $sgids
                    ]
                ]
            ];
        }
        return $conditions;
    }

    /**
     * Minimal index for sync pull: returns [uuid => modified] for every collection the
     * caller may see and distribute (filtered via buildConditions), optionally narrowed
     * by $filters (e.g. the orgc_id OR/NOT pull-rules the controller builds from
     * orgc_name). Mirrors AnalystData::indexMinimal, flattened — a collection has no
     * analyst-data-style type dimension, so the shape is a single [uuid => modified] map.
     * The remote side dedups against this by comparing `modified` (D6).
     *
     * @param array $user The requesting sync user.
     * @param array $filters Extra conditions ANDed onto the visibility gate.
     * @return array uuid => modified (datetime string)
     */
    public function indexMinimal(array $user, array $filters = []): array
    {
        $conditions = [$this->buildConditions($user['id'])];
        if (!empty($filters)) {
            $conditions[] = $filters;
        }
        $entries = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['AND' => $conditions],
            'fields' => ['Collection.uuid', 'Collection.modified'],
        ]);
        $allData = [];
        foreach ($entries as $entry) {
            $allData[$entry['Collection']['uuid']] = $entry['Collection']['modified'];
        }
        return $allData;
    }

    /**
     * Sync pull entry point. Fetches the remote collection index ({uuid: modified}),
     * dedups it against local copies by `modified` (D6 skip-on-equal), then chunk-fetches
     * and captures every winner. Mirrors AnalystData::pull + pullInChunks, flattened —
     * collections have no analyst-data-style `type` dimension, so the remote index is a
     * single [uuid => modified] map rather than [type][uuid => modified].
     *
     * The shared sink captureCollection() OWNS the distribution downgrade, locked=1 and
     * the D6 conflict rule, so each RAW remote collection is passed through untouched —
     * pre-downgrading here would double-downgrade (T2.1 carry-forward).
     *
     * @param array $user The local sync user driving the capture.
     * @param ServerSyncTool $serverSync Negotiated connection to the remote instance.
     * @return int Number of collections imported (created or updated).
     */
    public function pull(array $user, ServerSyncTool $serverSync)
    {
        // Real negotiation gate: skip silently against a peer without the feature (the
        // ServerSyncTool method throws are pure defense-in-depth on top of this).
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_COLLECTION_SYNC)) {
            return 0;
        }

        try {
            $filterRules = $this->buildPullFilterRules($serverSync->server());
            $remoteData = $serverSync->collectionIndexMinimal($filterRules)->json();
        } catch (Exception $e) {
            $this->logException("Could not fetch collection index from server {$serverSync->server()['Server']['name']}", $e);
            return 0;
        }

        if (empty($remoteData)) {
            return 0;
        }

        $remoteUUIDs = array_keys($remoteData);
        $localRows = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['Collection.uuid' => $remoteUUIDs],
            'fields' => ['Collection.uuid', 'Collection.modified'],
        ]);
        $localModified = [];
        foreach ($localRows as $localRow) {
            $localModified[$localRow['Collection']['uuid']] = $localRow['Collection']['modified'];
        }

        $uuidsToFetch = [];
        foreach ($remoteData as $remoteUUID => $remoteModified) {
            if (!isset($localModified[$remoteUUID])) {
                // Missing locally — fetch it.
                $uuidsToFetch[] = $remoteUUID;
            } elseif (strtotime($localModified[$remoteUUID]) < strtotime($remoteModified)) {
                // Strictly newer remote wins (skip-on-equal — D6).
                $uuidsToFetch[] = $remoteUUID;
            }
        }
        unset($remoteData, $remoteUUIDs, $localRows, $localModified);

        if (empty($uuidsToFetch)) {
            return 0;
        }

        return $this->pullCollectionsInChunks($user, $uuidsToFetch, $serverSync);
    }

    /**
     * Chunk-fetch the deduped UUID list and hand each RAW remote collection to the shared
     * capture sink. Mirrors AnalystData::pullInChunks (100/chunk); no type layer.
     *
     * @param array $user
     * @param array $uuids UUIDs already deduped by Collection::pull.
     * @param ServerSyncTool $serverSync
     * @return int Number of collections imported.
     */
    private function pullCollectionsInChunks(array $user, array $uuids, ServerSyncTool $serverSync)
    {
        $saved = 0;
        // The sink applies the downgrade unless internal + this flag (mirrors pullInChunks).
        $remotePermSyncInternal = !empty($serverSync->cachedUserInfo()['Role']['perm_sync_internal']);

        foreach (array_chunk($uuids, 100) as $uuidChunk) {
            try {
                $chunkedCollections = $serverSync->fetchCollections($uuidChunk)->json();
            } catch (Exception $e) {
                $this->logException("Failed downloading the chunked collections from {$serverSync->server()['Server']['name']}.", $e);
                continue;
            }

            foreach ($chunkedCollections as $collection) {
                // RAW payload straight to the sink — it owns downgrade + locked=1 + D6.
                $savedResult = $this->captureCollection($user, $collection, $serverSync->server(), $remotePermSyncInternal);
                if ($savedResult['success']) {
                    $saved += $savedResult['imported'];
                }
            }
        }

        return $saved;
    }

    /**
     * Translate a server's org pull-rules into the orgc_name OR/NOT filter the
     * indexMinimal endpoint expects (it resolves names -> orgc_id). Mirrors
     * AnalystData::buildPullFilterRules verbatim.
     */
    private function buildPullFilterRules(array $server): array
    {
        $filterRules = ['orgc_name' => []];
        $pullRules = $this->jsonDecode($server['Server']['pull_rules']);
        if (!empty($pullRules['orgs']['OR'])) {
            $filterRules['orgc_name'] = $pullRules['orgs']['OR'];
        }
        if (!empty($pullRules['orgs']['NOT'])) {
            $filterRules['orgc_name'] = array_merge($filterRules['orgc_name'], array_map(function ($orgName) {
                return '!' . $orgName;
            }, $pullRules['orgs']['NOT']));
        }
        return $filterRules;
    }

    /**
     * Push-receive dedup: given the pushing peer's {uuid: modified} candidates, return
     * only the subset this (receiving) instance actually wants — the receive-side mirror
     * of the pull dedup in Collection::pull. Flattened analogue of
     * AnalystData::filterAnalystDataForPush (no analyst-data `type` dimension).
     *
     * A candidate is wanted when it is either missing locally, OR strictly newer than a
     * local copy that is itself synced-in (locked=1). A locally-created (locked=0)
     * collection is authoritative and is never overwritten by a push (D6), so its uuid is
     * dropped from the wanted set even if the candidate looks newer.
     *
     * @param array $candidates {uuid: modified} offered by the pushing peer.
     * @return array The {uuid: modified} subset the local side wants captured.
     */
    public function filterCollectionsForPush($candidates): array
    {
        $incoming = $candidates;
        $incomingUuids = array_keys($incoming);
        if (empty($incomingUuids)) {
            return [];
        }
        $localRows = $this->find('all', [
            'recursive' => -1,
            'conditions' => ['Collection.uuid' => $incomingUuids],
            'fields' => ['uuid', 'modified', 'locked'],
        ]);
        foreach ($localRows as $localRow) {
            $local = $localRow['Collection'];
            if (empty($incoming[$local['uuid']])) {
                continue;
            }
            if (!$this->isCandidateValidForPush($incoming[$local['uuid']], $local)) {
                unset($incoming[$local['uuid']]);
            }
        }
        return $incoming;
    }

    /**
     * D6 gate shared by filterCollectionsForPush: a candidate only wins against an existing
     * local row when that row is synced-in (locked=1) AND the candidate is strictly newer.
     * Mirrors AnalystData::isCandidateValidForPush.
     */
    private function isCandidateValidForPush($candidateModified, array $existingEntry): bool
    {
        if ($existingEntry['locked'] == 0) {
            return false;
        }
        if (strtotime($existingEntry['modified']) >= strtotime($candidateModified)) {
            return false;
        }
        return true;
    }

    /**
     * Shared sync capture sink for Collections — the single ingest point for BOTH the
     * pull path and the push-receive controller action (mirrors
     * GalaxyCluster::captureCluster / AnalystData::captureAnalystData). Centralising
     * every enforcement rule here means both sync directions are covered once:
     *  - D5 corpus authoritative: the incoming element set replaces the local one
     *    wholesale via CollectionElement::captureElements() (which self-suppresses the
     *    parent `modified` bump, T1.3, so the remote `modified` we write stays
     *    authoritative for `{uuid: modified}` dedup).
     *  - D6 last-writer-wins guarded by `locked`: a locally-created (locked=0) collection
     *    is never overwritten by a non-internal remote; otherwise the strictly-newer
     *    `modified` wins (equal/older is skipped). Accepted captures are marked locked=1.
     *  - D7 creator neutralised: `user_id` is pinned to the sync user, `org_id` to the
     *    sync user's org; `orgc_id`/`sharing_group_id` are resolved by UUID.
     *  - Distribution is downgraded on incoming (1->0, 2->1) unless the server is internal
     *    and the remote sync user has perm_sync_internal.
     *
     * All identity/security fields (uuid, org, orgc, user_id, locked) are pinned from
     * server-derived context, never honoured from the payload; the payload `id` is
     * dropped (capture keys on `uuid` only) — PRD §7 mass-assignment discipline.
     *
     * NB for the pull (T3.3) and push (T4.x) wiring: the downgrade + locked=1 live HERE,
     * so callers must pass the raw remote collection and must NOT pre-downgrade it
     * (avoids a double downgrade). Pull passes $remotePermSyncInternal from the remote
     * user info; push-receive passes !empty($user['Role']['perm_sync_internal']).
     *
     * @param array $user The sync user performing/authorising the capture.
     * @param array $collection Remote collection (with Orgc / SharingGroup / CollectionElement).
     * @param array|false $server The server the capture originates from (internal/locked rules).
     * @param bool $remotePermSyncInternal Whether the remote sync user has perm_sync_internal.
     * @return array ['success', 'imported', 'ignored', 'failed', 'errors']
     */
    public function captureCollection(array $user, array $collection, $server = false, $remotePermSyncInternal = false): array
    {
        $results = ['success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 0, 'errors' => []];

        // Normalise: hoist related data under the Collection key, tolerating both raw
        // find() output (siblings) and an already-rearranged payload (nested).
        if (!isset($collection['Collection'])) {
            $collection = ['Collection' => $collection];
        }
        foreach (['Orgc', 'Org', 'SharingGroup', 'CollectionElement'] as $child) {
            if (isset($collection[$child]) && !isset($collection['Collection'][$child])) {
                $collection['Collection'][$child] = $collection[$child];
                unset($collection[$child]);
            }
        }

        // No server context ⇒ treat as external + non-internal (downgrade + locked
        // protection both apply — the safe default; also avoids null offset warnings).
        if (empty($server)) {
            $server = ['Server' => ['internal' => 0, 'org_id' => 0]];
        }

        if (empty($collection['Collection']['uuid'])) {
            $collection['Collection']['uuid'] = CakeText::uuid();
        }

        // Resolve creator org (orgc_id) by UUID and, for distribution=4, the sharing
        // group by UUID (create-if-missing) — mirrors GalaxyCluster::captureOrganisationAndSG.
        $collection = $this->captureOrganisationAndSG($collection, $user);

        // Server-derived, never attacker-controlled: owner org = the sync user's org;
        // creator user neutralised to the sync user (D7); mark as synced-in (locked=1).
        $collection['Collection']['org_id'] = $user['Organisation']['id'];
        $collection['Collection']['user_id'] = $user['id'];
        $collection['Collection']['locked'] = 1;

        // Distribution downgrade on incoming, unless internal + remote perm_sync_internal
        // (mirrors AnalystData/GalaxyCluster updatePulled*BeforeInsert).
        if (
            empty(Configure::read('MISP.host_org_id')) ||
            empty($server['Server']['internal']) ||
            Configure::read('MISP.host_org_id') != $server['Server']['org_id'] ||
            !$remotePermSyncInternal
        ) {
            switch ((int)($collection['Collection']['distribution'] ?? 0)) {
                case 1:
                    $collection['Collection']['distribution'] = 0; // community -> org only
                    break;
                case 2:
                    $collection['Collection']['distribution'] = 1; // connected -> community only
                    break;
            }
        }
        if ((int)($collection['Collection']['distribution'] ?? 0) !== 4) {
            $collection['Collection']['sharing_group_id'] = null;
        }

        // D5: the incoming element corpus is authoritative — pull it aside for a wholesale
        // replace after the parent is saved (present-but-empty ⇒ cull all local elements).
        $elements = null;
        if (array_key_exists('CollectionElement', $collection['Collection'])) {
            $elements = $collection['Collection']['CollectionElement'];
            unset($collection['Collection']['CollectionElement']);
        }

        $fieldList = [
            'uuid', 'name', 'type', 'description', 'distribution',
            'sharing_group_id', 'org_id', 'orgc_id', 'user_id', 'locked', 'modified'
        ];

        $existing = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Collection.uuid' => $collection['Collection']['uuid']],
        ]);

        // current_user drives beforeValidate on the create branch (owner org / user_id /
        // orgc fallback); its perm_sync exemption lets our locked=1 stand.
        $this->current_user = $user;
        if (empty($existing)) {
            unset($collection['Collection']['id']);
            $this->create();
            $saveSuccess = $this->save($collection, true, $fieldList);
        } else {
            // D6: never let a non-internal remote overwrite a locally-created original.
            if (empty($existing['Collection']['locked']) && empty($server['Server']['internal'])) {
                $results['errors'][] = __('Blocked an edit to a collection that was created locally. This can happen if a synchronised collection that was created on this instance was modified by an administrator on the remote side.');
                $results['failed']++;
                return $results;
            }
            // Last-writer-wins: only a strictly-newer remote version wins.
            if (isset($collection['Collection']['modified']) && $collection['Collection']['modified'] > $existing['Collection']['modified']) {
                $collection['Collection']['id'] = $existing['Collection']['id'];
                $saveSuccess = $this->save($collection, true, $fieldList);
            } else {
                $results['errors'][] = __('Remote version is not newer than local one for collection (%s)', $collection['Collection']['uuid']);
                $results['ignored']++;
                return $results;
            }
        }

        if ($saveSuccess) {
            $results['imported']++;
            $saved = $this->find('first', [
                'recursive' => -1,
                'conditions' => ['Collection.uuid' => $collection['Collection']['uuid']],
            ]);
            if ($elements !== null) {
                // captureElements() replaces the corpus authoritatively and suppresses the
                // Collection.modified bump itself, preserving the remote `modified` (T1.3).
                $this->CollectionElement->captureElements([
                    'Collection' => [
                        'id' => $saved['Collection']['id'],
                        'CollectionElement' => $elements,
                    ],
                ]);
            }
        } else {
            $results['failed']++;
            foreach ($this->validationErrors as $validationError) {
                $results['errors'][] = is_array($validationError) ? $validationError[0] : $validationError;
            }
        }
        $results['success'] = $results['imported'] > 0;
        return $results;
    }

    /**
     * Resolve the creator organisation (orgc_id) by UUID and, for distribution=4, the
     * sharing group by UUID (create-if-missing). Mirrors
     * GalaxyCluster::captureOrganisationAndSG — Collection keys org/SG by integer id.
     */
    private function captureOrganisationAndSG($collection, $user)
    {
        $this->Event = ClassRegistry::init('Event');
        if (isset($collection['Collection']['distribution']) && $collection['Collection']['distribution'] == 4) {
            $collection['Collection'] = $this->Event->captureSGForElement($collection['Collection'], $user);
        }
        if (isset($collection['Collection']['Orgc'])) {
            $collection['Collection']['orgc_id'] = $this->Orgc->captureOrg($collection['Collection']['Orgc'], $user);
            unset($collection['Collection']['Orgc']);
        } else {
            // No creator org travelled with the payload — default to the sync user's org.
            $collection['Collection']['orgc_id'] = $user['org_id'];
        }
        return $collection;
    }

    public function rearrangeCollection(array $collection, $user = null) {
        foreach ($collection as $key => $elements) {
            if ($key !== 'Collection') {
                $collection['Collection'][$key] = $elements;
                unset($collection[$key]);
            }
        }
        if (empty($user) || empty($user['Role']['perm_site_admin'])) {
            unset($collection['Collection']['User']);
        }
        return $collection;
    }
}
