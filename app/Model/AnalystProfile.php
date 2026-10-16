<?php

App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('ShippedProfileTool', 'Tools/AnalystProfile');

/**
 * The Analyst Profile — the configuration object the value assessment is
 * computed from.
 *
 * One row holds one JSON document of named sections: signal weights,
 * thresholds, escalations, exclusions, relevance TTLs, source trust and
 * enrichment defaults. Three scopes own them — a user, an organisation, or
 * the instance — and exactly one profile is in force for any viewer, which
 * is what lets the page name the profile that produced a number.
 *
 * prd/analyst-profile/02-store.md is the specification. This phase treats
 * `parameters` as opaque beyond "it parses"; phases 2-7 give each section
 * its contract.
 */
class AnalystProfile extends AppModel
{
    public $actsAs = array('Containable');

    /** Where a shipped default profile is read from. */
    const DEFAULT_PROFILE_PATH = APP . 'files/analyst-profiles/';

    /**
     * `default-v1`'s uuid — what the instance runs when it names nothing.
     *
     * The site setting `ValueIntelligence_instance_profile` is what actually
     * decides (D44), and this is only its fall-back: an instance that
     * takes the upgrade and sets nothing resolves the same profile it
     * resolved before six of them shipped. Any other value there wins,
     * including one naming a profile that is gone — which falls through
     * and is reported, rather than quietly snapping back to this.
     */
    const SHIPPED_DEFAULT_UUID = '6e2679bc-ebb0-417f-90d8-16cb1d0144ba';

    /**
     * Resolution cache, keyed by "user_id:org_id".
     *
     * resolveFor() is called once per panel and the value page loads up to
     * twenty-seven of them, so the profile is resolved once per request.
     *
     * @var array
     */
    private $resolutionCache = array();

    /**
     * Why the last `selectProfile()` refused, as a sentence for the form.
     *
     * Not `validationErrors`: a refused selection is not a refused save of
     * *this* model's row — the profile named is usually fine and the
     * problem is that this scope may not point at it.
     *
     * @var string|null
     */
    public $selectionError = null;

    /**
     * Why the last `setShared()` refused, as a sentence for the form.
     *
     * @var string|null
     */
    public $shareError = null;

    public $validate = array(
        'name' => array(
            'notBlank' => array('rule' => 'notBlank'),
            'maxLength' => array('rule' => array('maxLength', 191)),
        ),
        'uuid' => array(
            'uuid' => array('rule' => 'uuid', 'allowEmpty' => true),
            'unique' => array('rule' => 'isUnique'),
        ),
    );

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $v) {
            if (!isset($v[$this->alias]['parameters'])) {
                continue;
            }
            $raw = $v[$this->alias]['parameters'];
            if ($raw === null || $raw === '') {
                $results[$k][$this->alias]['parameters'] = array();
                continue;
            }
            $decoded = json_decode($raw, true);
            if ($decoded === null || !is_array($decoded)) {
                /*
                 * Deliberately not substituted with an empty array, which is
                 * what DecayingModel::afterFind does. A profile whose
                 * parameters will not parse has to reach the engine as
                 * broken, because the hero names the profile it scored with
                 * and silently scoring under a different one — the empty one
                 * — would make that name a lie. 02-store.md §3.1.
                 */
                $results[$k][$this->alias]['parameters'] = array();
                $results[$k][$this->alias]['parameters_unparseable'] = true;
            } else {
                $results[$k][$this->alias]['parameters'] = $decoded;
            }
        }
        return $results;
    }

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        $data = &$this->data[$this->alias];

        /*
         * Seed columns on create only. CakePHP saves the fields it is
         * handed, so defaulting these on an update writes them: a partial
         * save of the shipped default — a rename, or phase 8's edit form —
         * would set `default` to 0 and stop it being the default at all.
         * Found by the live probe (02-store.md §7.6), which the stubbed
         * harness could not see because its save() always succeeded.
         */
        if (empty($data['id'])) {
            if (empty($data['uuid'])) {
                $data['uuid'] = CakeText::uuid();
            }
            if (!isset($data['default'])) {
                $data['default'] = 0;
            }
            if (!isset($data['enabled'])) {
                $data['enabled'] = 1;
            }
            foreach (array('version', 'revision') as $counter) {
                if (!isset($data[$counter])) {
                    $data[$counter] = 1;
                }
            }
        }
        if (isset($data['parameters']) && is_array($data['parameters'])) {
            $data['parameters'] = json_encode($data['parameters']);
        }
        if (isset($data['parameters'])
            && !$this->validateParameters($data['parameters'])) {
            $this->invalidate(
                'parameters',
                __('The parameters are not a JSON object.')
            );
            return false;
        }
        if (!$this->__validateOwnership($data)) {
            return false;
        }
        return $this->__validateOneEnabledPerOwner($data);
    }

    /**
     * Exactly one of user_id, org_id and `default` is set.
     *
     * Enforced here rather than by a constraint because MySQL cannot express
     * "exactly one of three is non-null" portably. An ambiguous triple would
     * make resolveFor()'s ordering meaningless.
     *
     * @param array $data
     * @return bool
     */
    private function __validateOwnership(array $data)
    {
        $columns = array('user_id', 'org_id', 'default');
        $touched = array();
        foreach ($columns as $column) {
            if (array_key_exists($column, $data)) {
                $touched[$column] = $data[$column];
            }
        }

        /*
         * An update is validated against the row as it will be, not against
         * the fields this save happens to carry. A save that names none of
         * the three is not changing ownership and must pass; one that names
         * some is checked merged with what is stored. Without this, every
         * partial update of an existing profile fails — which is how the
         * shipped default's own update path was silently doing nothing.
         */
        if (!empty($data['id'])) {
            if (empty($touched)) {
                return true;
            }
            $stored = $this->find('first', array(
                'conditions' => array('AnalystProfile.id' => $data['id']),
                'fields' => array(
                    'AnalystProfile.user_id',
                    'AnalystProfile.org_id',
                    'AnalystProfile.default',
                ),
                'recursive' => -1,
            ));
            if (!empty($stored)) {
                $touched = array_merge($stored['AnalystProfile'], $touched);
            }
        }

        $scopes = 0;
        foreach ($columns as $column) {
            if (!empty($touched[$column])) {
                $scopes++;
            }
        }
        if ($scopes !== 1) {
            $this->invalidate(
                'user_id',
                __('A profile is owned by exactly one of a user, an'
                    . ' organisation, or the instance.')
            );
            return false;
        }
        return true;
    }

    /**
     * A user, and an organisation, holds at most one enabled profile.
     *
     * resolveFor() takes the nearest owner and would otherwise have two
     * equally near rows to choose between. A partial unique index would say
     * this in the schema but is not portable.
     *
     * @param array $data
     * @return bool
     */
    private function __validateOneEnabledPerOwner(array $data)
    {
        if (empty($data['enabled']) || $this->__isShared($data)) {
            return true;
        }
        $owner = array();
        if (!empty($data['user_id'])) {
            $owner['AnalystProfile.user_id'] = $data['user_id'];
        } elseif (!empty($data['org_id'])) {
            $owner['AnalystProfile.org_id'] = $data['org_id'];
        } else {
            return true;
        }
        $owner['AnalystProfile.enabled'] = 1;
        $owner['AnalystProfile.shared'] = 0;
        if (!empty($data['id'])) {
            $owner['AnalystProfile.id !='] = $data['id'];
        }
        $existing = $this->find('first', array(
            'conditions' => $owner,
            'fields' => array('AnalystProfile.id'),
            'recursive' => -1,
        ));
        if (!empty($existing)) {
            $this->invalidate(
                'enabled',
                __(
                    'This owner already holds an enabled profile (#%s).',
                    $existing['AnalystProfile']['id']
                )
            );
            return false;
        }
        return true;
    }

    public function beforeSave($options = array())
    {
        $data = &$this->data[$this->alias];
        if (!empty($data['id'])
            && ((array_key_exists('enabled', $data) && empty($data['enabled']))
                || (array_key_exists('shared', $data) && empty($data['shared'])))
            && $this->__namedByInstance($data['id'])
        ) {
            $this->invalidate('enabled', $this->__instanceGuardMessage());
            return false;
        }
        $now = date('Y-m-d H:i:s');
        if (empty($data['id'])) {
            $data['created'] = $now;
        }
        $data['modified'] = $now;
        return true;
    }

    /**
     * Any write invalidates the resolution cache.
     *
     * `resolveFor()` memoises per request because the value page calls
     * it once per panel and there are twenty-seven of them. That is a
     * read-only assumption, and phase 8's editor breaks it: enabling one
     * profile disables another *in the same request*, and the response
     * then has to say which one is in force. `forkProfile()` cleared the
     * cache by hand; `saveField('enabled', …)` did not, so the swap's own
     * answer came back from before the swap.
     *
     * Cleared here rather than at each call site, because a cache whose
     * correctness depends on every future caller remembering is a cache
     * that will be wrong.
     *
     * @param bool $created
     * @param array $options
     * @return void
     */
    public function afterSave($created, $options = array())
    {
        $this->resolutionCache = array();
        $this->__clearSupersededSelection();
    }

    /**
     * An owner who enables a profile of their own stops selecting.
     *
     * The other half of D45's *one answer per scope*. `selectProfile()`
     * disables the owned row when a selection is saved; this is the
     * reverse, and it lives here for the same reason the cache flush
     * does — the paths that enable a row are the editor's enable action,
     * a fork, and an import, and a rule whose correctness depends on
     * three callers remembering is a rule that will be broken by the
     * fourth.
     *
     * A save that does not leave the row enabled changes nothing: a
     * disable is how a reader goes *back* to their selection, so it must
     * not take the selection away on the way past.
     *
     * @return void
     */
    private function __clearSupersededSelection()
    {
        $data = isset($this->data[$this->alias])
            ? $this->data[$this->alias]
            : array();
        if (!array_key_exists('enabled', $data) || empty($data['enabled'])) {
            return;
        }
        /*
         * A shipped profile has no owner, so there is no selection of
         * its owner's to clear. Named rather than reached through the
         * lookup below, because `updateDefaults()` takes this path once
         * per shipped file on a fresh instance.
         */
        if (!empty($data['default'])) {
            return;
        }
        if ($this->__isShared($data + array('id' => $this->id))) {
            return;
        }
        $userId = isset($data['user_id']) ? $data['user_id'] : null;
        $orgId = isset($data['org_id']) ? $data['org_id'] : null;
        if (!array_key_exists('user_id', $data)
            && !array_key_exists('org_id', $data)
            && !empty($this->id)
        ) {
            $stored = $this->find('first', array(
                'conditions' => array('AnalystProfile.id' => $this->id),
                'fields' => array(
                    'AnalystProfile.user_id',
                    'AnalystProfile.org_id',
                ),
                'recursive' => -1,
            ));
            if (!empty($stored)) {
                $userId = $stored['AnalystProfile']['user_id'];
                $orgId = $stored['AnalystProfile']['org_id'];
            }
        }
        if (!empty($userId)) {
            ClassRegistry::init('UserSetting')->deleteAll(array(
                'UserSetting.user_id' => $userId,
                'UserSetting.setting' => 'analyst_profile',
            ), false, true);
        } elseif (!empty($orgId)) {
            ClassRegistry::init('AnalystProfileSelection')->clearFor($orgId);
        }
    }

    public function beforeDelete($cascade = true)
    {
        if ($this->__namedByInstance($this->id)) {
            $this->invalidate('enabled', $this->__instanceGuardMessage());
            return false;
        }
        return true;
    }

    /**
     * Is this row the shared profile the instance setting puts in force?
     * Switching it off would end assessment scoring for every reader who
     * selected nothing, so it is refused until the setting names another.
     *
     * @param int|string $id
     * @return bool
     */
    private function __namedByInstance($id)
    {
        $row = $this->find('first', array(
            'conditions' => array('AnalystProfile.id' => $id),
            'fields' => array('AnalystProfile.uuid', 'AnalystProfile.shared'),
            'recursive' => -1,
        ));
        if (empty($row) || empty($row['AnalystProfile']['shared'])) {
            return false;
        }
        $instance = trim((string)Configure::read(
            'Plugin.ValueIntelligence_instance_profile'
        ));
        return $instance === $row['AnalystProfile']['uuid'];
    }

    private function __instanceGuardMessage()
    {
        return __(
            'This shared profile is the instance profile. Name another one'
            . ' in Plugin.ValueIntelligence_instance_profile first.'
        );
    }

    /**
     * Whether the row being saved is shared, read from the save or, for a
     * partial update, from what is stored.
     *
     * @param array $data
     * @return bool
     */
    private function __isShared(array $data)
    {
        if (array_key_exists('shared', $data)) {
            return !empty($data['shared']);
        }
        if (empty($data['id'])) {
            return false;
        }
        return (bool)$this->field('shared', array('AnalystProfile.id' => $data['id']));
    }

    /**
     * @param bool $cascade
     * @return void
     */
    public function afterDelete()
    {
        $this->resolutionCache = array();
    }

    /**
     * Forget what is in force, for a caller that changed it elsewhere.
     *
     * Writes to this model clear the cache themselves; a selection can
     * also move because a site setting or a row in another table did,
     * and those have no `afterSave` here to hang it on.
     *
     * @return void
     */
    public function resetResolution()
    {
        $this->resolutionCache = array();
    }

    /**
     * The one function every reader calls: the profile in force for a viewer.
     *
     * Nearest scope wins (D3) — the viewer's, else their organisation's,
     * else the instance's. Each scope answers with an owned profile *or* a
     * selection (D45) and never both, so there are still three candidates
     * to rank and not six.
     *
     * **Returns null when nothing matches**, which happens when a site admin
     * has disabled the instance default and the viewer owns no profile. That
     * is the honest reading of "verdict scoring is switched off here", not an
     * error: 01-profile.md §5.3 has the page render no score and name no
     * profile. Callers must handle null.
     *
     * @param array $user
     * @return array|null The AnalystProfile row, unwrapped
     */
    public function resolveFor(array $user)
    {
        $resolution = $this->resolutionFor($user);
        return $resolution['profile'];
    }

    /**
     * What a Pivot Explorer sidebar orders tags and clusters by: the
     * viewer's label plan, and which of its pinned taxonomies and galaxies
     * the instance has enabled, so a pin the node lacks is only named when
     * it could be there.
     *
     * @param array $user
     * @param array|null $plan An already resolved plan; resolved when null
     * @return array `plan`, `permitted` (`taxonomies`, `galaxies`)
     */
    public function pivotLabels(array $user, $plan = null)
    {
        App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
        if ($plan === null) {
            $plan = ValueLabelPriority::planFor($this->resolveFor($user));
        }
        $permitted = ['taxonomies' => [], 'galaxies' => []];
        $taxonomies = ValueLabelPriority::keys(
            $plan, ValueLabelPriority::TAXONOMIES, ValueLabelPriority::PINNED
        );
        if (!empty($taxonomies)) {
            $permitted['taxonomies'] = array_values(ClassRegistry::init('Taxonomy')->find('list', [
                'conditions' => [
                    'LOWER(Taxonomy.namespace)' => $taxonomies,
                    'Taxonomy.enabled' => 1,
                ],
                'fields' => ['Taxonomy.id', 'Taxonomy.namespace'],
                'recursive' => -1,
            ]));
        }
        $galaxies = ValueLabelPriority::keys(
            $plan, ValueLabelPriority::GALAXIES, ValueLabelPriority::PINNED
        );
        if (!empty($galaxies)) {
            $permitted['galaxies'] = array_values(array_unique(ClassRegistry::init('Galaxy')->find('list', [
                'conditions' => [
                    'LOWER(Galaxy.type)' => $galaxies,
                    'Galaxy.enabled' => 1,
                ],
                'fields' => ['Galaxy.id', 'Galaxy.type'],
                'recursive' => -1,
            ])));
        }
        return ['plan' => $plan, 'permitted' => $permitted];
    }

    /**
     * Resolution, with its reasoning — what won, how it was reached, and
     * what each scope declared that did not resolve.
     *
     * `resolveFor()` answers the question every reader asks and nothing
     * more; this answers the one the profile index asks, which is *why*.
     * A selection whose target has been deleted, disabled or is no longer
     * readable falls through silently to the next scope (§5), and silently
     * is exactly what a reader must not be left with when they go looking
     * for the profile that scored their page.
     *
     * Both share one cache entry and one query, because the value page
     * resolves twenty-seven times per request and the index once.
     *
     * @param array $user
     * @return array `profile`, `via`, `selections`, `unresolved`
     */
    public function resolutionFor(array $user)
    {
        $userId = isset($user['id']) ? $user['id'] : null;
        $orgId = isset($user['org_id']) ? $user['org_id'] : null;
        $cacheKey = $userId . ':' . $orgId;
        if (array_key_exists($cacheKey, $this->resolutionCache)) {
            return $this->resolutionCache[$cacheKey];
        }

        $selections = $this->selectionsFor($user);

        /*
         * One statement, still. §3.1 forbids three sequential queries
         * walking the scopes, and this is not that: the three selections
         * are read first — two cheap single-row lookups and a
         * `Configure::read()` — and then *one* statement fetches every row
         * they could possibly name alongside the owned ones.
         *
         * The old query said `default = 1` for the instance branch and
         * carried a comment claiming at most three rows could match,
         * justified by `__validateOneEnabledPerOwner()`. That validation
         * returns true for instance scope — it caps users and orgs only —
         * and `updateDefaults()` marks every shipped file `default = 1`.
         * With six shipped profiles six rows matched, `limit 3` read three
         * of them in no defined order, and a reader's own row could fall
         * outside the three that were read (§5.1). Every row is now named:
         * the user's, the organisation's, and the three uuids the
         * selections carry. Six is a true bound rather than an assumed one.
         *
         * Named rows are fetched whether or not they are enabled, so that
         * a selection pointing at something switched off can be reported
         * as switched off rather than as absent. Owned rows keep the
         * `enabled = 1` filter, because an owner may hold any number of
         * disabled profiles and only the enabled one is a candidate.
         */
        $named = array();
        foreach ($selections as $uuid) {
            if ($uuid !== null && !in_array($uuid, $named, true)) {
                $named[] = $uuid;
            }
        }
        $ownership = array();
        if ($userId !== null) {
            $ownership[] = array('AnalystProfile.user_id' => $userId);
        }
        if ($orgId !== null) {
            $ownership[] = array('AnalystProfile.org_id' => $orgId);
        }
        $branches = array();
        if (!empty($ownership)) {
            $branches[] = array(
                'AnalystProfile.enabled' => 1,
                'AnalystProfile.shared' => 0,
                'OR' => $ownership,
            );
        }
        if (!empty($named)) {
            $branches[] = array('AnalystProfile.uuid' => $named);
        }

        $candidates = array();
        if (!empty($branches)) {
            $candidates = $this->find('all', array(
                'conditions' => array('OR' => $branches),
                'recursive' => -1,
                'limit' => 6,
            ));
        }

        $byUuid = array();
        $owned = array();
        foreach ($candidates as $candidate) {
            $row = $candidate['AnalystProfile'];
            $byUuid[$row['uuid']] = $row;
            if (empty($row['enabled']) || !empty($row['shared'])) {
                continue;
            }
            if ($userId !== null && $row['user_id'] == $userId) {
                $owned['user'] = $row;
            } elseif ($orgId !== null && $row['org_id'] == $orgId) {
                $owned['org'] = $row;
            }
        }

        $resolution = array(
            'profile' => null,
            'via' => null,
            'selections' => $selections,
            'unresolved' => array(),
        );
        foreach (array('user', 'org', 'instance') as $scope) {
            if (isset($owned[$scope]) && $resolution['profile'] === null) {
                $resolution['profile'] = $owned[$scope];
                $resolution['via'] = $scope;
                continue;
            }
            if ($selections[$scope] === null) {
                continue;
            }
            $refused = $this->__refuseSelection(
                $user,
                $scope,
                $selections[$scope],
                isset($byUuid[$selections[$scope]])
                    ? $byUuid[$selections[$scope]]
                    : null
            );
            if ($refused !== null) {
                $resolution['unresolved'][$scope] = $refused;
                continue;
            }
            if ($resolution['profile'] === null) {
                $resolution['profile'] = $byUuid[$selections[$scope]];
                /*
                 * `user_selection` and `org_selection` distinguish a
                 * scope's two possible answers. The instance has only
                 * one — it owns no profile, it names one — so there is
                 * nothing there to distinguish it from, and `instance`
                 * is what it was called before selections existed.
                 */
                $resolution['via'] = $scope === 'instance'
                    ? 'instance'
                    : $scope . '_selection';
            }
        }

        $this->resolutionCache[$cacheKey] = $resolution;
        return $resolution;
    }

    /**
     * The uuid each scope has declared, before any of them is resolved.
     *
     * Three stores, because each scope already had or needed a different
     * one (D45): a user writes to `user_settings`, an organisation to
     * `analyst_profile_selections`, and the instance to a site setting.
     * A missing site setting reads as the shipped default's uuid, so an
     * instance that takes the upgrade and sets nothing resolves exactly
     * what it resolved before.
     *
     * @param array $user
     * @return array `user`, `org`, `instance`, each a uuid or null
     */
    public function selectionsFor(array $user)
    {
        $selections = array(
            'user' => null,
            'org' => null,
            'instance' => null,
        );
        if (!empty($user['id'])) {
            $stored = ClassRegistry::init('UserSetting')
                ->getValueForUser($user['id'], 'analyst_profile');
            if (is_string($stored) && Validation::uuid(trim($stored))) {
                $selections['user'] = trim($stored);
            }
        }
        if (!empty($user['org_id'])) {
            $stored = ClassRegistry::init('AnalystProfileSelection')
                ->forOrg($user['org_id']);
            if (is_string($stored) && Validation::uuid($stored)) {
                $selections['org'] = $stored;
            }
        }
        $instance = Configure::read(
            'Plugin.ValueIntelligence_instance_profile'
        );
        if (!is_string($instance) || !Validation::uuid(trim($instance))) {
            $instance = self::SHIPPED_DEFAULT_UUID;
        }
        $selections['instance'] = trim($instance);
        return $selections;
    }

    /**
     * Why a declared selection is not the answer, or null when it is.
     *
     * The three refusals are kept apart because the index prints them:
     * *the profile you chose has been deleted* and *the profile you chose
     * is switched off* send a reader to different places.
     *
     * @param array $user
     * @param string $scope
     * @param string $uuid
     * @param array|null $row
     * @return array|null
     */
    private function __refuseSelection(array $user, $scope, $uuid, $row)
    {
        if ($row === null) {
            return array('uuid' => $uuid, 'reason' => 'missing');
        }
        if (empty($row['enabled'])) {
            return array(
                'uuid' => $uuid,
                'reason' => 'disabled',
                'name' => $row['name'],
            );
        }
        if (!$this->isSelectableAt($user, $scope, $row)) {
            return array(
                'uuid' => $uuid,
                'reason' => 'unreadable',
                'name' => $row['name'],
            );
        }
        return null;
    }

    /**
     * May this scope point at this profile?
     *
     * Narrower than `isReadableByCurrentUser()` on purpose, in two ways.
     * A site admin reads every profile on the instance, and if that let
     * their *selection* resolve to another organisation's row then
     * `resolveFor()` would return a row whose owner is not the reader —
     * breaking the one assumption that lets `scopeOf()` describe the
     * profile in force from its columns alone, with no `$user` to compare
     * against (10-wiring.md §11.1). And the instance scope may name only
     * a shipped profile, for the same reason: every other row belongs to
     * somebody, and nobody's profile should score a stranger's page.
     *
     * @param array $user
     * @param string $scope `user`, `org` or `instance`
     * @param array $row The unwrapped row
     * @return bool
     */
    public function isSelectableAt(array $user, $scope, array $row)
    {
        if (!empty($row['default']) || !empty($row['shared'])) {
            return true;
        }
        if ($scope === 'instance') {
            return false;
        }
        if (!empty($row['user_id'])) {
            return $scope === 'user'
                && !empty($user['id'])
                && $row['user_id'] == $user['id'];
        }
        if (!empty($row['org_id'])) {
            return !empty($user['org_id'])
                && $row['org_id'] == $user['org_id'];
        }
        return false;
    }

    /**
     * Point a scope at a profile, and take that scope's other answer away.
     *
     * D45's rule is *one answer per scope*: an owner holds an enabled
     * owned profile **or** a selection, never both. Saving a selection
     * therefore disables the owned row rather than losing to it or
     * racing it, and the caller is handed what was displaced so the form
     * can say so — nothing is deleted, exactly as replacing an enabled
     * profile with another one already behaves.
     *
     * @param array $user
     * @param string $scope `user` or `org`
     * @param string $uuid
     * @return array|null `profile` and `displaced`, or null with
     *                    `selectionError` set
     */
    public function selectProfile(array $user, $scope, $uuid)
    {
        $this->selectionError = null;
        if (!in_array($scope, array('user', 'org'), true)) {
            $this->selectionError = __(
                'The instance profile is a site setting, not a selection.'
            );
            return null;
        }
        if (!Validation::uuid($uuid)) {
            $this->selectionError = __('That is not a profile uuid.');
            return null;
        }
        $row = $this->find('first', array(
            'conditions' => array('AnalystProfile.uuid' => $uuid),
            'recursive' => -1,
        ));
        if (empty($row)) {
            $this->selectionError = __(
                'No profile on this instance carries that uuid.'
            );
            return null;
        }
        $row = $row['AnalystProfile'];
        if (!$this->isSelectableAt($user, $scope, $row)) {
            $this->selectionError = __(
                'That profile is not one this scope may select.'
            );
            return null;
        }
        if (empty($row['enabled'])) {
            $this->selectionError = __(
                'That profile is switched off. Selecting it would leave'
                . ' this scope scored by the next one.'
            );
            return null;
        }

        $displaced = $this->__enabledOwnedBy($user, $scope);
        /*
         * Own it or choose it. Without this, a scope choosing the very
         * profile it owns would disable that row — the displacement step
         * below — and then point a selection at a switched-off profile,
         * which resolves to nothing and falls through to the next scope.
         * The reader's answer would silently become somebody else's.
         */
        if ($displaced !== null
            && (int)$displaced['id'] === (int)$row['id']
        ) {
            $this->selectionError = __(
                'This scope already owns that profile, and an owned'
                . ' profile is already the answer. There is nothing to'
                . ' choose.'
            );
            return null;
        }
        if ($displaced !== null) {
            $this->id = $displaced['id'];
            if (!$this->saveField('enabled', 0)) {
                $this->selectionError = __(
                    'The profile this scope owns could not be disabled, so'
                    . ' the selection was not saved.'
                );
                return null;
            }
        }

        if ($scope === 'user') {
            $saved = $this->__writeUserSelection($user, $uuid);
        } else {
            $saved = ClassRegistry::init('AnalystProfileSelection')
                ->selectFor($user['org_id'], $uuid);
        }
        if (!$saved) {
            if ($displaced !== null) {
                $this->id = $displaced['id'];
                $this->saveField('enabled', 1);
            }
            if ($this->selectionError === null) {
                $this->selectionError = __(
                    'The selection could not be saved.'
                );
            }
            return null;
        }

        $this->resolutionCache = array();
        return array('profile' => $row, 'displaced' => $displaced);
    }

    /**
     * Stop selecting, at one scope. The next scope answers.
     *
     * @param array $user
     * @param string $scope `user` or `org`
     * @return bool
     */
    public function clearSelection(array $user, $scope)
    {
        if ($scope === 'user') {
            $this->__writeUserSelection($user, '');
        } elseif ($scope === 'org') {
            ClassRegistry::init('AnalystProfileSelection')
                ->clearFor($user['org_id']);
        } else {
            return false;
        }
        $this->resolutionCache = array();
        return true;
    }

    /**
     * @param array $user
     * @param string $uuid Empty string clears it.
     * @return bool
     */
    private function __writeUserSelection(array $user, $uuid)
    {
        $UserSetting = ClassRegistry::init('UserSetting');
        if ($uuid === '') {
            $UserSetting->deleteAll(array(
                'UserSetting.user_id' => $user['id'],
                'UserSetting.setting' => 'analyst_profile',
            ), false, true);
            return true;
        }
        /*
         * Written through `setSetting()` rather than
         * `setSettingInternal()`, so that a selection goes through the
         * same permission check, the same validator and the same audit
         * entry as any other user setting — the point of D45 being that
         * this *is* a user setting. It refuses by exception; the caller
         * wants a sentence, so the refusal is caught and becomes one.
         */
        try {
            return (bool)$UserSetting->setSetting($user, array(
                'UserSetting' => array(
                    'user_id' => $user['id'],
                    'setting' => 'analyst_profile',
                    'value' => $uuid,
                ),
            ));
        } catch (Exception $e) {
            $this->selectionError = $e->getMessage();
            return false;
        }
    }

    /**
     * The enabled profile a scope owns, if it holds one.
     *
     * @param array $user
     * @param string $scope
     * @return array|null
     */
    private function __enabledOwnedBy(array $user, $scope)
    {
        $conditions = array(
            'AnalystProfile.enabled' => 1,
            'AnalystProfile.shared' => 0,
        );
        if ($scope === 'user') {
            if (empty($user['id'])) {
                return null;
            }
            $conditions['AnalystProfile.user_id'] = $user['id'];
        } else {
            if (empty($user['org_id'])) {
                return null;
            }
            $conditions['AnalystProfile.org_id'] = $user['org_id'];
        }
        $row = $this->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1,
        ));
        return empty($row) ? null : $row['AnalystProfile'];
    }

    /**
     * Which of D3's three scopes owns a profile.
     *
     * The columns say it and no lookup is needed, which is what lets a
     * caller holding only the row — `ValueIntelligence::verdictPanels()`,
     * which takes no `$user` on purpose — state how far the profile in
     * force reaches. It is safe there because `resolveFor()` returns
     * only rows that already match the viewer: a `user` answer is
     * *this* reader's, an `org` answer is *their* organisation's.
     *
     * Ownership is read in resolution order rather than by checking
     * `default` first, so a row that somehow carries both an owner and
     * the default flag is described by its owner — the narrower and
     * therefore the more careful reading.
     *
     * @param array $row The unwrapped row
     * @return string `shared`, `user`, `org` or `default`
     */
    public function scopeOf(array $row)
    {
        if (!empty($row['shared'])) {
            return 'shared';
        }
        if (!empty($row['user_id'])) {
            return 'user';
        }
        if (!empty($row['org_id'])) {
            return 'org';
        }
        return 'default';
    }

    /**
     * The profiles a viewer may see: their own, their organisation's, the
     * shipped ones and the enabled shared ones. A site admin sees every
     * profile on the instance.
     *
     * @param array $user
     * @param array $filters
     * @return array
     */
    public function fetchProfiles(array $user, array $filters = array())
    {
        $conditions = array();
        if (empty($user['Role']['perm_site_admin'])) {
            $conditions['OR'] = array(
                array('AnalystProfile.user_id' => $user['id']),
                array('AnalystProfile.org_id' => $user['org_id']),
                array('AnalystProfile.default' => 1),
                array(
                    'AnalystProfile.shared' => 1,
                    'AnalystProfile.enabled' => 1,
                ),
            );
        }
        if (isset($filters['enabled'])) {
            $conditions['AnalystProfile.enabled'] = $filters['enabled'];
        }
        return $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'order' => array(
                'AnalystProfile.default DESC',
                'AnalystProfile.name ASC',
            ),
        ));
    }

    /**
     * @param array $user
     * @param int|string $id id or uuid
     * @return array|null
     */
    public function fetchProfile(array $user, $id)
    {
        $conditions = Validation::uuid($id)
            ? array('AnalystProfile.uuid' => $id)
            : array('AnalystProfile.id' => $id);
        $profile = $this->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1,
        ));
        if (empty($profile)) {
            return null;
        }
        if (!$this->isReadableByCurrentUser($user, $profile)) {
            return null;
        }
        return $profile;
    }

    /**
     * @param array $user
     * @param array $profile
     * @return bool
     */
    public function isReadableByCurrentUser(array $user, array $profile)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        $row = isset($profile['AnalystProfile'])
            ? $profile['AnalystProfile']
            : $profile;
        if (!empty($row['default'])) {
            return true;
        }
        if (!empty($row['shared']) && !empty($row['enabled'])) {
            return true;
        }
        if (!empty($row['user_id']) && $row['user_id'] == $user['id']) {
            return true;
        }
        return !empty($row['org_id']) && $row['org_id'] == $user['org_id'];
    }

    /**
     * Who may edit a profile.
     *
     * Mirrors DecayingModel::isEditableByCurrentUser() and answers Q7 the way
     * 02-store.md §3.3 recommended: **no new permission flag.** A user
     * profile changes only its owner's own page, so it needs no grant — the
     * same reasoning that leaves user_settings ungated. An organisation
     * profile changes what colleagues read, so it is an org-admin action.
     * The shipped default stays site-admin only.
     *
     * Chosen partly because it is the reversible direction: adding a
     * perm_analyst_profile flag later is additive, whereas shipping one and
     * withdrawing it is a migration and a role-seed change.
     *
     * @param array $user
     * @param array $profile
     * @return bool
     */
    public function isEditableByCurrentUser(array $user, array $profile)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        $row = isset($profile['AnalystProfile'])
            ? $profile['AnalystProfile']
            : $profile;
        if (!empty($row['default']) || !empty($row['shared'])) {
            return false;
        }
        if (!empty($row['user_id'])) {
            return $row['user_id'] == $user['id'];
        }
        if (!empty($row['org_id'])) {
            return $row['org_id'] == $user['org_id']
                && !empty($user['Role']['perm_admin']);
        }
        return false;
    }

    /**
     * Copy a profile into one the caller owns.
     *
     * A fork carries no lineage (D5): new uuid, counters reset, no
     * parent_uuid. Forking exists so an analyst can get started, and every
     * reference map in a profile is an override set — so a fork that
     * overrides nothing keeps tracking whatever the underlying source says.
     *
     * @param array $user
     * @param int|string $id The source profile
     * @param string|null $name
     * @param bool $forOrg Fork to the caller's organisation rather than to
     *                     the caller. Requires perm_admin.
     * @return array|null The saved fork, or null with validationErrors set
     */
    public function forkProfile(array $user, $id, $name = null, $forOrg = false)
    {
        $source = $this->fetchProfile($user, $id);
        if (empty($source)) {
            return null;
        }
        if ($forOrg && empty($user['Role']['perm_admin'])
            && empty($user['Role']['perm_site_admin'])) {
            $this->invalidate(
                'org_id',
                __('Forking to the organisation requires an org admin.')
            );
            return null;
        }
        $fork = array(
            'uuid' => CakeText::uuid(),
            'name' => $name !== null
                ? $name
                : sprintf('%s (copy)', $source['AnalystProfile']['name']),
            'description' => $this->forkDescription(
                $source['AnalystProfile']
            ),
            'parameters' => $source['AnalystProfile']['parameters'],
            'user_id' => $forOrg ? null : $user['id'],
            'org_id' => $forOrg ? $user['org_id'] : null,
            'default' => 0,
            'enabled' => 1,
            'version' => 1,
            'revision' => 1,
        );
        $this->create();
        if (!$this->save(array('AnalystProfile' => $fork))) {
            return null;
        }
        $this->resolutionCache = array();
        return $this->find('first', array(
            'conditions' => array('AnalystProfile.id' => $this->id),
            'recursive' => -1,
        ));
    }

    /**
     * Share a site admin's own profile with the instance, or withdraw it.
     *
     * A shared profile is readable, forkable and selectable by everyone, at
     * every scope including the instance setting. It stops being its owner's
     * own answer and only a site admin edits it. Withdrawn, it goes back to
     * its owner disabled, so it cannot clash with the profile they already
     * have enabled.
     *
     * @param array $user
     * @param int|string $id
     * @param bool $shared
     * @return array|null The saved row, or null with `shareError` set
     */
    public function setShared(array $user, $id, $shared)
    {
        $this->shareError = null;
        if (empty($user['Role']['perm_site_admin'])) {
            $this->shareError = __('Only a site admin can share a profile.');
            return null;
        }
        $row = $this->fetchProfile($user, $id);
        if (empty($row)) {
            $this->shareError = __('Invalid analyst profile.');
            return null;
        }
        $row = $row['AnalystProfile'];
        if (empty($row['user_id']) || $row['user_id'] != $user['id']) {
            $this->shareError = __(
                'Only a profile you own personally can be shared.'
            );
            return null;
        }
        if ((bool)$shared === !empty($row['shared'])) {
            return $row;
        }
        $saved = $this->save(array('AnalystProfile' => array(
            'id' => $row['id'],
            'shared' => $shared ? 1 : 0,
            'enabled' => $shared ? 1 : 0,
        )), array('fieldList' => array('shared', 'enabled', 'modified')));
        if (!$saved) {
            $errors = Hash::flatten($this->validationErrors);
            $this->shareError = empty($errors)
                ? __('The profile could not be saved.')
                : reset($errors);
            return null;
        }
        $this->resolutionCache = array();
        $stored = $this->find('first', array(
            'conditions' => array('AnalystProfile.id' => $row['id']),
            'recursive' => -1,
        ));
        return $stored['AnalystProfile'];
    }

    /**
     * The index board: every profile this reader may see, the one in
     * force, and per row the reason it is not.
     *
     * **In the model rather than the controller**, and moved here in 8a
     * while writing the live probe. The commonest confusion this
     * feature can create is an analyst editing a profile that is not
     * weighting their pages, and the answer to it — `overridden`,
     * naming the profile that won — is an *ownership* statement, made
     * out of exactly what `resolveFor()` and `isEditableByCurrentUser()`
     * already decide. Left in the controller it was unreachable except
     * over HTTP, so the one thing 8c most needs to get right could only
     * be checked by looking at a page.
     *
     * @param array $user
     * @return array `profiles` and `in_force`
     */
    public function indexFor(array $user)
    {
        $resolution = $this->resolutionFor($user);
        $inForce = $resolution['profile'];
        $rows = array();
        foreach ($this->fetchProfiles($user) as $profile) {
            $rows[] = $this->__decorate($user, $profile[$this->alias],
                $inForce, $resolution);
        }
        /*
         * The one in force leads, then the reader's own, their
         * organisation's, and the instance default — nearest owner
         * first, which is the order resolution walks.
         */
        usort($rows, function ($a, $b) {
            if ($a['in_force'] !== $b['in_force']) {
                return $a['in_force'] ? -1 : 1;
            }
            if ($a['scope_rank'] !== $b['scope_rank']) {
                return $b['scope_rank'] - $a['scope_rank'];
            }
            return strcasecmp($a['name'], $b['name']);
        });
        return array(
            'profiles' => $rows,
            'in_force' => $inForce,
            'resolution' => $resolution,
        );
    }

    /**
     * The columns every caller names a profile by.
     *
     * @param array $row The unwrapped row
     * @return array
     */
    public function summarise(array $row)
    {
        return array(
            'id' => (int)$row['id'],
            'uuid' => $row['uuid'],
            'name' => $row['name'],
            'description' => isset($row['description'])
                ? $row['description']
                : null,
            'enabled' => !empty($row['enabled']),
            'default' => !empty($row['default']),
            'shared' => !empty($row['shared']),
            'version' => (int)$row['version'],
            'revision' => (int)$row['revision'],
            'modified' => isset($row['modified']) ? $row['modified'] : null,
            /*
             * A profile whose document will not parse reaches every
             * reader as broken rather than as empty (§3.1), and the
             * editor is where somebody can do something about it.
             */
            'unparseable' => !empty($row['parameters_unparseable']),
        );
    }

    /**
     * What the index needs to say about one row beyond its columns.
     *
     * @param array $user
     * @param array $row
     * @param array|null $inForce
     * @param array $resolution
     * @return array
     */
    private function __decorate(array $user, array $row, $inForce,
        array $resolution = array()
    ) {
        $shared = !empty($row['shared']);
        $mine = !$shared && !empty($row['user_id'])
            && $row['user_id'] == $user['id'];
        $ours = !empty($row['org_id']) && $row['org_id'] == $user['org_id'];
        if ($shared) {
            $scopeRank = 0;
        } elseif (!empty($row['user_id'])) {
            $scopeRank = $mine ? 3 : 1;
        } elseif (!empty($row['org_id'])) {
            $scopeRank = $ours ? 2 : 1;
        } else {
            $scopeRank = 0;
        }
        /*
         * Which scopes point at this row, and whether this reader could
         * make one point at it. A selection is not ownership — the row is
         * still the instance's — so it is reported beside the owner label
         * rather than folded into it.
         */
        $selections = isset($resolution['selections'])
            ? $resolution['selections']
            : array('user' => null, 'org' => null, 'instance' => null);
        $selectedBy = array();
        foreach ($selections as $scope => $uuid) {
            if ($uuid !== null && $uuid === $row['uuid']) {
                $selectedBy[] = $scope;
            }
        }
        $inForceHere = $inForce !== null
            && (int)$inForce['id'] === (int)$row['id'];
        $decorated = $this->summarise($row) + array(
            'owner' => $this->__ownerLabel($user, $row),
            'scope_rank' => $scopeRank,
            'editable' => $this->isEditableByCurrentUser($user, $row),
            'in_force' => $inForceHere,
            'signals' => $this->__signalCount($row),
            'selected_by' => $selectedBy,
            /*
             * Offered only where choosing would change something. A row
             * already in force for this reader has nothing to choose,
             * and a row a scope *owns* must not be offered to that same
             * scope: choosing disables the owned profile first, so a
             * scope selecting its own would switch the row off and then
             * point at it, and the selection would fall through to the
             * next scope. Own it or choose it — that is D45's rule seen
             * from the button.
             */
            'selectable' => !empty($row['enabled'])
                && !$inForceHere
                && !$mine
                && $this->isSelectableAt($user, 'user', $row),
            'selectable_for_org' => !empty($row['enabled'])
                && !$ours
                && !empty($user['Role']['perm_admin'])
                && $this->isSelectableAt($user, 'org', $row),
            'can_share' => !empty($user['Role']['perm_site_admin'])
                && !empty($row['user_id'])
                && $row['user_id'] == $user['id'],
        );
        $decorated['standing'] = $this->__standing($user, $row, $inForce,
            $decorated);
        return $decorated;
    }

    /**
     * Why a profile is not the one weighting this reader's pages.
     *
     * @param array $user
     * @param array $row
     * @param array|null $inForce
     * @param array $decorated
     * @return array
     */
    private function __standing(array $user, array $row, $inForce,
        array $decorated
    ) {
        if ($decorated['in_force']) {
            return array('state' => 'in_force');
        }
        $mine = !empty($row['user_id']) && $row['user_id'] == $user['id'];
        $ours = !empty($row['org_id']) && $row['org_id'] == $user['org_id'];
        $reference = !empty($row['default']) || !empty($row['shared']);
        if (!$mine && !$ours && !$reference) {
            // A site admin looking at somebody else's. It could never
            // have been in force for this reader.
            return array('state' => 'other_owner');
        }
        if (empty($decorated['enabled'])) {
            return array('state' => 'disabled');
        }
        /*
         * MISP ships six profiles and puts none of them in force by
         * itself (D44). Five of them are therefore enabled, readable by
         * everyone, and doing nothing — which is not *overridden*, it is
         * *not chosen*, and the difference is the whole of what the
         * selection UI is for.
         */
        if ($reference && empty($decorated['selected_by'])) {
            return array('state' => 'not_selected');
        }
        if ($inForce === null) {
            /*
             * Enabled, applies to this reader, and yet nothing is in
             * force — which resolution cannot produce. Rather than
             * assert one of them, say what is observable.
             */
            return array('state' => 'unresolved');
        }
        return array(
            'state' => 'overridden',
            'winner' => array(
                'id' => (int)$inForce['id'],
                'name' => $inForce['name'],
            ),
        );
    }

    /**
     * @param array $user
     * @param array $row
     * @return string
     */
    private function __ownerLabel(array $user, array $row)
    {
        if (!empty($row['default'])) {
            /*
             * `default` is written in one place only —
             * `updateDefaults()`, once per shipped file — and import
             * always creates a user- or organisation-owned row, so the
             * column means *MISP ships this* and nothing else.
             *
             * It used to read *Instance default*, which is the name of
             * the third resolution scope, and MISP ships six of these:
             * six rows each claiming to be the instance default, beside
             * a rail whose third step names the one that actually is.
             */
            return __('Shipped by MISP');
        }
        if (!empty($row['user_id'])) {
            if ($row['user_id'] == $user['id']) {
                return empty($row['shared']) ? __('You') : __('Shared by you');
            }
            $owner = ClassRegistry::init('User')->find('first', array(
                'conditions' => array('User.id' => $row['user_id']),
                'fields' => array('User.email'),
                'recursive' => -1,
            ));
            $name = empty($owner)
                ? sprintf(__('User #%s'), $row['user_id'])
                : $owner['User']['email'];
            return empty($row['shared'])
                ? $name
                : sprintf(__('Shared by %s'), $name);
        }
        if (!empty($row['org_id'])) {
            $org = ClassRegistry::init('Organisation')->find('first', array(
                'conditions' => array('Organisation.id' => $row['org_id']),
                'fields' => array('Organisation.name'),
                'recursive' => -1,
            ));
            $name = empty($org)
                ? sprintf(__('Organisation #%s'), $row['org_id'])
                : $org['Organisation']['name'];
            return $row['org_id'] == $user['org_id']
                ? sprintf(__('%s (yours)'), $name)
                : $name;
        }
        return __('Nobody');
    }

    /**
     * Enabled signals over configured ones — the one number that says
     * how much of a profile is switched on without opening it.
     *
     * @param array $row
     * @return array
     */
    private function __signalCount(array $row)
    {
        $signals = isset($row['parameters']['signals'])
            && is_array($row['parameters']['signals'])
            ? $row['parameters']['signals']
            : array();
        $enabled = 0;
        foreach ($signals as $signal) {
            if (!is_array($signal)) {
                continue;
            }
            if (!array_key_exists('enabled', $signal)
                || !empty($signal['enabled'])
            ) {
                $enabled++;
            }
        }
        return array('enabled' => $enabled, 'configured' => count($signals));
    }

    /**
     * A fork's description: what it is, then what it was copied from.
     *
     * The first implementation copied the source's description verbatim,
     * and forking the shipped default produced a profile whose own page
     * read *"The instance default Analyst Profile…"* — a claim that was
     * true of the source and false of the copy, on the one field a
     * colleague reads to decide whether to adopt it. Found in the phase
     * 8a live probe, where the fork's description came back three times
     * saying it was the default (09-editor.md §7a).
     *
     * A dated prose note, not lineage. D5 forbids **tracked** lineage —
     * no `parent_uuid`, nothing an update walks — because override maps
     * are what keep a fork current. A sentence saying where a document
     * came from is a changelog line: nothing reads it, nothing resolves
     * through it, and it stays true if the source is later renamed or
     * deleted, which is exactly what a tracked pointer would not.
     *
     * @param array $source The unwrapped source row
     * @return string
     */
    private function forkDescription(array $source)
    {
        $note = sprintf(
            __('Forked from “%1$s” on %2$s.'),
            $source['name'],
            date('Y-m-d')
        );
        $description = isset($source['description'])
            ? trim((string)$source['description'])
            : '';
        return $description === ''
            ? $note
            : $note . "\n\n" . $description;
    }

    /**
     * The name `Server::updateJSON()` calls on every model that loads
     * shipped JSON into a table — Galaxy, Noticelist, Warninglist, Taxonomy,
     * ObjectTemplate, ObjectRelationship, and now this one.
     *
     * @param bool $force
     * @return array
     */
    public function update($force = false)
    {
        return $this->updateDefaults($force);
    }

    /**
     * Load the shipped default profiles from app/files/analyst-profiles/.
     *
     * Follows DecayingModel::update() with its version-comparison bug fixed:
     * `version` is an int column here, so `10 > 9` rather than
     * `'1.10' > '1.9'` being false.
     *
     * Three things it must not do, each a rule rather than an omission: it
     * never touches a fork, because a fork has its own uuid and this loop
     * only knows the shipped ones; it never re-enables a disabled default,
     * because disabling it is how an admin switches assessment scoring off;
     * and it never deletes a default whose file has gone, because an org may
     * have forked from it and the page may still name it.
     *
     * @param bool $force Overwrite regardless of version
     * @return array Per-uuid outcome: created|updated|skipped|overwrote_edits
     */
    public function updateDefaults($force = false)
    {
        $shipped = $this->__loadShippedProfiles();
        if (empty($shipped)) {
            return array();
        }
        $existing = array();
        $rows = $this->find('all', array(
            'conditions' => array('AnalystProfile.default' => 1),
            'recursive' => -1,
        ));
        foreach ($rows as $row) {
            $existing[$row['AnalystProfile']['uuid']] = $row['AnalystProfile'];
        }

        $outcome = array();
        foreach ($shipped as $profile) {
            $uuid = $profile['uuid'];
            if (!isset($existing[$uuid])) {
                $this->create();
                $profile['default'] = 1;
                $profile['enabled'] = 1;
                $profile['revision'] = 1;
                $this->save(array('AnalystProfile' => $profile));
                $outcome[$uuid] = 'created';
                continue;
            }
            $current = $existing[$uuid];
            $shippedVersion = (int)$profile['version'];
            if (!$force && $shippedVersion <= (int)$current['version']) {
                $outcome[$uuid] = 'skipped';
                continue;
            }
            /*
             * A revision above 1 means the default was edited locally, and
             * this overwrite discards those edits. That is the rule — the
             * default tracks upstream and fork is the path to durable
             * divergence — but it is named rather than absorbed silently, so
             * the caller can log it.
             */
            $hadLocalEdits = (int)$current['revision'] > 1;
            /*
             * No create() here, deliberately. Model::create() seeds
             * $this->data from the column defaults, so `default` arrives as
             * 0 and, merged over the stored row, un-owns the profile that is
             * being updated. create() is for inserts; an update carries its
             * id and nothing else.
             */
            $this->id = $current['id'];
            $saved = $this->save(array('AnalystProfile' => array(
                'id' => $current['id'],
                'uuid' => $uuid,
                'name' => $profile['name'],
                'description' => $profile['description'],
                'parameters' => $profile['parameters'],
                'version' => $profile['version'],
                'revision' => (int)$current['revision'] + 1,
            )));
            if (empty($saved)) {
                /*
                 * Reported rather than swallowed. This branch returned
                 * 'updated' unconditionally until the live probe found the
                 * save failing validation and the caller believing it.
                 */
                $this->log(sprintf(
                    'AnalystProfile: could not update shipped default %s: %s',
                    $uuid,
                    json_encode($this->validationErrors)
                ));
                $outcome[$uuid] = 'failed';
                continue;
            }
            $outcome[$uuid] = $hadLocalEdits ? 'overwrote_edits' : 'updated';
        }
        $this->resolutionCache = array();
        return $outcome;
    }

    /**
     * @return array
     */
    private function __loadShippedProfiles()
    {
        if (!is_dir(self::DEFAULT_PROFILE_PATH)) {
            return array();
        }
        $dir = new Folder(self::DEFAULT_PROFILE_PATH);
        $files = $dir->find('.*\.json', true);
        $documents = array();
        foreach ($files as $filename) {
            $file = new File(self::DEFAULT_PROFILE_PATH . $filename);
            $decoded = json_decode($file->read());
            $file->close();
            if (!is_object($decoded) || empty($decoded->uuid)
                || empty($decoded->name) || !isset($decoded->parameters)) {
                $this->log(sprintf(
                    'AnalystProfile: shipped profile %s is missing uuid,'
                        . ' name or parameters.',
                    $filename
                ));
                continue;
            }
            $documents[basename($filename, '.json')] = $decoded;
        }
        $resolved = ShippedProfileTool::resolve($documents);
        foreach ($resolved['errors'] as $slug => $error) {
            $this->log(sprintf(
                'AnalystProfile: shipped profile %s.json skipped: %s.',
                $slug,
                $error
            ));
        }
        $profiles = array();
        foreach ($resolved['profiles'] as $profile) {
            $profile['parameters'] = json_encode($profile['parameters']);
            $profiles[] = $profile;
        }
        return $profiles;
    }

    /**
     * Phase 1 asks only whether the document parses into an object. Each
     * section's contract belongs to the phase that owns it — signals to
     * phase 2, relevance to phase 5, and so on.
     *
     * @param string|array $parameters
     * @return bool
     */
    public function validateParameters($parameters)
    {
        if (is_array($parameters)) {
            return true;
        }
        if ($parameters === null || $parameters === '') {
            return true;
        }
        $decoded = json_decode($parameters, true);
        return is_array($decoded);
    }

    /**
     * The grades a page shows beside organisations, and where a grade
     * written from that page would land.
     *
     * @param array $user
     * @return array OrgGradeTool::reading()
     */
    public function gradingFor(array $user)
    {
        App::uses('OrgGradeTool', 'Tools/AnalystProfile');
        return OrgGradeTool::reading($this->resolutionFor($user));
    }

    /**
     * Grade one organisation in the reader's own profile, forking the
     * profile in force first when it is not theirs.
     *
     * @param array $user
     * @param string $orgUuid
     * @param string|null $grade A…G, null for no opinion
     * @param bool $fork Whether the caller agreed to a fork
     * @return array `ok`; on success `previous`, `changed`, `forked`,
     *               `profile` (the row written); on refusal `error` and
     *               `needs_fork`
     */
    public function gradeOrganisation(array $user, $orgUuid, $grade, $fork)
    {
        App::uses('OrgGradeTool', 'Tools/AnalystProfile');
        $target = OrgGradeTool::target($this->resolutionFor($user));
        if ($target['mode'] === OrgGradeTool::MODE_NONE) {
            return [
                'ok' => false,
                'needs_fork' => false,
                'error' => __('No analyst profile is in force for you, so there is nothing to grade in.'),
            ];
        }
        $forked = false;
        if ($target['mode'] === OrgGradeTool::MODE_FORK) {
            if (!$fork) {
                return [
                    'ok' => false,
                    'needs_fork' => true,
                    'target' => $target,
                    'error' => __('The profile in force is not yours. Grading makes your own copy of it first.'),
                ];
            }
            $copy = $this->forkProfile($user, $target['profile']['id']);
            if (empty($copy)) {
                return [
                    'ok' => false,
                    'needs_fork' => false,
                    'error' => __('Your copy of the profile could not be saved.'),
                ];
            }
            $row = $copy['AnalystProfile'];
            $forked = true;
        } else {
            $row = $this->find('first', [
                'conditions' => ['AnalystProfile.id' => $target['profile']['id']],
                'recursive' => -1,
            ])['AnalystProfile'];
        }
        $parameters = is_array($row['parameters']) ? $row['parameters'] : [];
        $applied = OrgGradeTool::apply($parameters, $orgUuid, $grade);
        if ($applied['changed']) {
            $this->id = $row['id'];
            if (!$this->save(['AnalystProfile' => [
                'id' => $row['id'],
                'parameters' => $applied['parameters'],
            ]])) {
                return [
                    'ok' => false,
                    'needs_fork' => false,
                    'error' => __('The grade could not be saved.'),
                ];
            }
            $this->bumpRevision($row['id']);
        }
        $saved = $this->find('first', [
            'conditions' => ['AnalystProfile.id' => $row['id']],
            'recursive' => -1,
        ]);
        return [
            'ok' => true,
            'previous' => $applied['previous'],
            'changed' => $applied['changed'],
            'forked' => $forked,
            'profile' => $saved['AnalystProfile'],
        ];
    }

    /**
     * `revision` is the local edit counter and `version` the upstream match
     * key, and the two are separate columns on purpose: a site admin editing
     * the default moves `revision` while `version` keeps tracking the shipped
     * file, so a shipped update still applies and the local edit is still
     * visible. Phase 10's materialised assessments key on `revision`.
     *
     * Renaming a profile does not move it. Only `parameters` does.
     *
     * @param int|string $id
     * @return bool
     */
    public function bumpRevision($id)
    {
        $profile = $this->find('first', array(
            'conditions' => array('AnalystProfile.id' => $id),
            'fields' => array('AnalystProfile.id', 'AnalystProfile.revision'),
            'recursive' => -1,
        ));
        if (empty($profile)) {
            return false;
        }
        $this->id = $id;
        return (bool)$this->saveField(
            'revision',
            (int)$profile['AnalystProfile']['revision'] + 1
        );
    }
}
