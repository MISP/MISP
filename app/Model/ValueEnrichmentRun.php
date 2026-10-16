<?php

App::uses('AppModel', 'Model');
App::uses('RedisTool', 'Tools');
App::uses('ValueEnrichmentTool', 'Tools/ValueIntelligence');

/**
 * What a module last answered about a value, per organisation.
 *
 * Phase 11 of prd/analyst-profile/ (`13-auto-run.md` §4). D15 named a
 * per-value per-module last-run store as the thing auto-run could not
 * be built without, and nothing built it: `Module` is
 * `useTable = false`, so until this table nothing anywhere in MISP
 * recorded that a module had been asked about anything.
 *
 * ## It is not only auto-run's store (D25)
 *
 * Every run writes here — a press as much as an auto — and every
 * module row on the Enrichment tab reads it. `max_age_hours` was
 * always defined as *the reuse window*, not as an automation window,
 * and the auto-run gate defaults off, so a store that served only
 * `auto` would hand every instance a migration and no benefit. What
 * this buys instead is memory on a tab whose own docblock apologised
 * for having none.
 *
 * A press still always re-runs (§5). The window governs what happens
 * *without* a press.
 *
 * ## One row per (org, value, module, type)
 *
 * UPSERTed, so a module asked a thousand times about one value is one
 * row. The table therefore grows with the breadth of investigation
 * rather than with its depth, and §4.4's retention is about values
 * nobody returned to rather than about runaway writes.
 *
 * **Per organisation**, because that is exactly how far MISP's own
 * ACL reaches: `MispAttribute::buildConditions()` caches on
 * `perm_site_admin . '-' . org_id` and nothing finer, and
 * `Module::canUse()` reserves a module with `_restrict` against
 * `org_id`. Instance-wide storage would surface a reserved module's
 * output to an organisation the instance withheld it from; per-user
 * storage would spend the quota once per analyst.
 *
 * The site-admin half of that ACL key is deliberately **not** here,
 * because the one reader-dependent thing in a run — the *already in
 * MISP* chips — is recomputed on read rather than stored (§8.1).
 *
 * ## What is stored, and what is not
 *
 * The shaped run, post-cap and pre-chips. Post-cap because
 * `ValueIntelligence::ENRICHMENT_ELEMENT_CAP` already bounds a result at
 * 200 elements while preserving `total`, and that cap is the
 * difference between a bounded row and the 1,374 objects
 * `circl_passivedns` returns for `8.8.8.8`. Pre-chips because
 * `enrichmentKnown()` answers *"already in MISP **and** you can see
 * it"* about the database as it is right now, and a frozen answer
 * becomes an answer about the database an hour ago.
 *
 * **`user_id` is stored and never rendered (D27).** Who asked is
 * useful for an audit and for diagnosing a purge; showing it tells the
 * organisation which colleague is looking at which value.
 */
class ValueEnrichmentRun extends AppModel
{
    public $actsAs = array('Containable');

    /**
     * How long a row is kept once nothing has re-run it.
     *
     * A constant rather than a setting: the Value Intelligence page ships
     * one instance setting as of this phase — the auto-run gate — and
     * a retention knob is the kind nobody tunes. `purgeOlderThan()`
     * raises this floor to fit any profile declaring a longer reuse
     * window, so the number is a minimum rather than a promise.
     */
    const RUN_RETENTION_DAYS = 90;

    /**
     * How often a write also purges.
     *
     * One in this many, so the sweep costs nothing amortised and no
     * instance depends on a cron entry it never added. Paired with
     * `PURGE_LIMIT` so that the unlucky request stays short.
     */
    const PURGE_EVERY = 200;

    /** The most rows one opportunistic sweep will delete. */
    const PURGE_LIMIT = 500;

    /**
     * The identity of a value for this table: the SHA-256 of its text,
     * the digest analyst data and collections name a value by.
     * **No normalisation of its own** — a store that
     * normalised differently from the page would disagree with the
     * page about which value is on screen, and §14.3 of the main PRD
     * reserves that decision for one function nobody has written.
     *
     * @param string $value
     * @return string
     */
    public static function hashFor($value)
    {
        return hash('sha256', (string)$value);
    }

    /**
     * How many answers this store holds for one organisation.
     *
     * `/values/index`'s one sentence about the store
     * (`value-index.md` §7.7): a reader whose Enrichment tab replied
     * instantly, or whose press on a fresh answer changed nothing, has
     * met the reuse window without anything on the page naming it. The
     * count says the memory exists and `max_age_hours` says how long
     * it lasts.
     *
     * **A number and nothing else.** No values, no module names, no
     * dates — the survey asked for *recently enriched values* and D27
     * refuses exactly that one level down: a list of what an
     * organisation just enriched is a list of what it is currently
     * investigating. A count cannot identify anything.
     *
     * **Scoped to the reader's organisation, because the store is.**
     * An instance-wide count is a smaller version of the same
     * disclosure — a hint about other organisations' activity — and
     * the org scope is also the only one that answers the reader's
     * actual question, since a row another organisation wrote will
     * never serve this one's tab.
     *
     * One statement over the unique key's leading column.
     *
     * @param array $user
     * @return int
     */
    public function countFor(array $user)
    {
        if (empty($user['org_id'])) {
            return 0;
        }
        return (int)$this->find('count', array(
            'recursive' => -1,
            'conditions' => array(
                'ValueEnrichmentRun.org_id' => (int)$user['org_id'],
            ),
        ));
    }

    /**
     * How many answers this organisation holds about one value.
     *
     * The Enrichment tab's badge. **Answers, not runs**: a module that
     * errored or was asked and had nothing to say is a row here and is
     * not a result, and a badge counting those would send a reader to
     * a tab to read failures.
     *
     * One statement over the unique key's two leading columns, no
     * payload touched — which is what makes it a page-load price. The
     * count phase 28 dropped was the *eligible-module* count, and it
     * was dropped because computing it means asking the modules
     * service on every page load; this asks nothing outside MISP.
     *
     * Scoped to the reader's organisation because the store is, so two
     * organisations read two numbers off one tab bar — the same
     * property the Occurrences and Sightings badges already have.
     *
     * @param array $user
     * @param string $value
     * @return int
     */
    public function heldCountFor(array $user, $value)
    {
        if (empty($user['org_id'])) {
            return 0;
        }
        return (int)$this->find('count', array(
            'recursive' => -1,
            'conditions' => array(
                'ValueEnrichmentRun.org_id' => (int)$user['org_id'],
                'ValueEnrichmentRun.value_hash' => self::hashFor($value),
                'ValueEnrichmentRun.state' => 'ok',
            ),
        ));
    }

    /**
     * Every stored run for one value, keyed `module|type`.
     *
     * One statement over the unique key's leading columns, which is
     * what makes D25 affordable: the catalogue is already building a
     * row per module and this is the only extra read the whole tab
     * pays for having a memory.
     *
     * **Without the payload.** `result` is the one big column and the
     * catalogue needs none of it — it needs to know that an answer
     * exists and how old it is. Selecting the blob for a dozen modules
     * to render a dozen *"asked 2 h ago"* lines would make the memory
     * cost more than the queries it saves. `one()` fetches it, for the
     * single module actually being shown.
     *
     * @param array $user
     * @param string $value
     * @return array
     */
    public function forValue(array $user, $value)
    {
        if (empty($user['org_id'])) {
            return array();
        }
        $rows = $this->find('all', array(
            'recursive' => -1,
            'fields' => array(
                'ValueEnrichmentRun.module',
                'ValueEnrichmentRun.type',
                'ValueEnrichmentRun.state',
                'ValueEnrichmentRun.last_run',
                'ValueEnrichmentRun.took',
                'ValueEnrichmentRun.total',
                'ValueEnrichmentRun.shown',
                'ValueEnrichmentRun.capped',
                'ValueEnrichmentRun.message',
            ),
            'conditions' => array(
                'ValueEnrichmentRun.org_id' => (int)$user['org_id'],
                'ValueEnrichmentRun.value_hash' => self::hashFor($value),
            ),
        ));
        $out = array();
        foreach ($rows as $row) {
            $row = $row['ValueEnrichmentRun'];
            $out[$row['module'] . '|' . $row['type']] = $row;
        }
        return $out;
    }

    /**
     * One stored run, payload included.
     *
     * @param array $user
     * @param string $value
     * @param string $module
     * @param string $type
     * @return array|null
     */
    public function one(array $user, $value, $module, $type)
    {
        if (empty($user['org_id'])) {
            return null;
        }
        $row = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'ValueEnrichmentRun.org_id' => (int)$user['org_id'],
                'ValueEnrichmentRun.value_hash' => self::hashFor($value),
                'ValueEnrichmentRun.module' => (string)$module,
                'ValueEnrichmentRun.type' => (string)$type,
            ),
        ));
        return empty($row) ? null : $row['ValueEnrichmentRun'];
    }

    /**
     * Claim the row before the module is asked (§7.3).
     *
     * The claim *is* the row: `state = running` with `last_run` now,
     * replaced by the answer when one arrives. A Redis `SET NX` was
     * the alternative and loses exactly when Redis is unavailable,
     * which is when the page is slowest and a duplicate outbound query
     * costs most.
     *
     * @param array $user
     * @param string $value
     * @param string $module
     * @param string $type
     * @return void
     */
    public function claim(array $user, $value, $module, $type)
    {
        if (empty($user['org_id'])) {
            return;
        }
        $this->upsert(array(
            'org_id' => (int)$user['org_id'],
            'value_hash' => self::hashFor($value),
            'value' => (string)$value,
            'module' => (string)$module,
            'type' => (string)$type,
            'state' => ValueEnrichmentTool::RUN_RUNNING,
            'user_id' => isset($user['id']) ? (int)$user['id'] : null,
            'last_run' => time(),
            'took' => 0,
            'total' => 0,
            'shown' => 0,
            'capped' => 0,
            'message' => null,
            'result' => null,
        ));
    }

    /**
     * Record what the module said.
     *
     * `$run` is `ValueIntelligence::enrichmentRun()`'s array **before**
     * `enrichmentKnown()` has marked it up, which is the boundary
     * §8.1 argues for. The payload is serialised and compressed
     * through `RedisTool`'s helpers because they are the codebase's
     * one pair for this and the column is a blob either way.
     *
     * @param array $user
     * @param string $value
     * @param array $run
     * @return void
     */
    public function record(array $user, $value, array $run)
    {
        if (empty($user['org_id']) || empty($run['module'])) {
            return;
        }
        $this->upsert(array(
            'org_id' => (int)$user['org_id'],
            'value_hash' => self::hashFor($value),
            'value' => (string)$value,
            'module' => (string)$run['module'],
            'type' => (string)$run['type'],
            'state' => (string)$run['state'],
            'user_id' => isset($user['id']) ? (int)$user['id'] : null,
            'last_run' => time(),
            'took' => (int)$run['took'],
            'total' => (int)$run['total'],
            'shown' => (int)$run['shown'],
            'capped' => !empty($run['capped']) ? 1 : 0,
            'message' => isset($run['message']) ? $run['message'] : null,
            'result' => self::pack($run),
        ));
        $this->maybePurge();
    }

    /**
     * The stored run, unpacked, or null if the payload cannot be read.
     *
     * A row whose blob will not inflate is not an error worth raising:
     * the caller falls back to *"asked, nothing held"*, which is a
     * state the tab draws anyway once a payload has been purged.
     *
     * @param array $row
     * @return array|null
     */
    public static function unpack(array $row)
    {
        if (empty($row['result'])) {
            return null;
        }
        $run = RedisTool::deserialize(
            RedisTool::decompress($row['result'])
        );
        return is_array($run) ? $run : null;
    }

    /**
     * Delete rows nothing has re-run in a long time.
     *
     * **The floor is derived, because `max_age_hours` is unbounded.**
     * `ValueEnrichmentTool::maxAgeHours()` rejects only non-numeric
     * and non-positive values, so a profile may legitimately declare a
     * year — and a fixed 90-day sweep would then delete rows still
     * inside their own reuse window and cause exactly the re-runs this
     * table exists to prevent. One small read of `analyst_profiles`
     * makes that case correct by construction rather than by
     * documentation.
     *
     * @param int|null $days Override; the derived floor when null
     * @param int|null $limit Rows at most; unbounded when null
     * @return int Rows deleted
     */
    public function purgeOlderThan($days = null, $limit = null)
    {
        $seconds = $days === null
            ? $this->retentionSeconds()
            : ((int)$days * 86400);
        $before = time() - $seconds;

        $conditions = array(
            'ValueEnrichmentRun.last_run <' => $before,
        );
        if ($limit === null) {
            $this->deleteAll($conditions, false);
            return $this->getAffectedRows();
        }
        /*
         * `deleteAll` takes no limit, so the capped sweep selects the
         * ids first. That is the point of the cap: the unlucky request
         * that triggers a purge must not become a long one.
         */
        $rows = $this->find('all', array(
            'recursive' => -1,
            'fields' => array('ValueEnrichmentRun.id'),
            'conditions' => $conditions,
            'order' => array('ValueEnrichmentRun.last_run ASC'),
            'limit' => (int)$limit,
        ));
        if (empty($rows)) {
            return 0;
        }
        $ids = array();
        foreach ($rows as $row) {
            $ids[] = $row['ValueEnrichmentRun']['id'];
        }
        $this->deleteAll(
            array('ValueEnrichmentRun.id' => $ids),
            false
        );
        return count($ids);
    }

    /** Every row, for the one-shot in `AdminShell`. @return int */
    public function purgeAll()
    {
        $count = $this->find('count');
        $this->deleteAll(array('ValueEnrichmentRun.id >' => 0), false);
        return $count;
    }

    /**
     * Every organisation's runs of one value, exactly as spelled: its
     * erasure from the value dictionary takes this cache with it.
     *
     * @param string $value
     * @return int Rows deleted
     */
    public function purgeValue($value)
    {
        $this->deleteAll(
            array('ValueEnrichmentRun.value_hash' => self::hashFor($value)),
            false
        );
        return $this->getAffectedRows();
    }

    /**
     * `RUN_RETENTION_DAYS`, raised to fit the longest reuse window any
     * enabled profile declares.
     *
     * @return int Seconds
     */
    private function retentionSeconds()
    {
        $floor = self::RUN_RETENTION_DAYS * 86400;
        $profiles = ClassRegistry::init('AnalystProfile')->find('all', array(
            'recursive' => -1,
            'fields' => array('AnalystProfile.parameters'),
            'conditions' => array('AnalystProfile.enabled' => 1),
        ));
        foreach ($profiles as $profile) {
            $plan = ValueEnrichmentTool::planFor(
                array('parameters' => $profile['AnalystProfile']['parameters'])
            );
            $window = (int)$plan['max_age_hours'] * 3600;
            if ($window > $floor) {
                $floor = $window;
            }
        }
        return $floor;
    }

    /**
     * One write in `PURGE_EVERY` also sweeps.
     *
     * Opportunistic rather than scheduled because an instance that
     * never adds a cron entry is the common case, and the table would
     * otherwise grow forever on exactly those instances.
     *
     * @return void
     */
    private function maybePurge()
    {
        if (mt_rand(1, self::PURGE_EVERY) !== 1) {
            return;
        }
        try {
            $this->purgeOlderThan(null, self::PURGE_LIMIT);
        } catch (Exception $e) {
            /*
             * A sweep is housekeeping on somebody else's request. It
             * must never be the reason their run failed to record.
             */
            $this->logException('Enrichment run purge failed', $e);
        }
    }

    /**
     * Insert or replace one row, addressed by the unique key.
     *
     * @param array $row
     * @return void
     */
    private function upsert(array $row)
    {
        $existing = $this->find('first', array(
            'recursive' => -1,
            'fields' => array('ValueEnrichmentRun.id'),
            'conditions' => array(
                'ValueEnrichmentRun.org_id' => $row['org_id'],
                'ValueEnrichmentRun.value_hash' => $row['value_hash'],
                'ValueEnrichmentRun.module' => $row['module'],
                'ValueEnrichmentRun.type' => $row['type'],
            ),
        ));
        $this->create();
        if (!empty($existing)) {
            $row['id'] = $existing['ValueEnrichmentRun']['id'];
        }
        $this->save(array('ValueEnrichmentRun' => $row), array(
            'validate' => false,
            'callbacks' => false,
        ));
    }

    /**
     * The stored payload: the shaped run without the chips.
     *
     * @param array $run
     * @return string
     */
    private static function pack(array $run)
    {
        /*
         * Three fields describe the reading rather than the answer:
         * the instance's timeout at the moment it was asked, whether
         * this copy came from the store, and how old it was. Keeping
         * any of them would have a served row claim it came from a
         * store it is the store of.
         */
        unset($run['timeout'], $run['from_store'], $run['age']);
        return RedisTool::compress(RedisTool::serialize($run));
    }
}
