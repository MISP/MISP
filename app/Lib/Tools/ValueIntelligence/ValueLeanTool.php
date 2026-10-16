<?php

App::uses('ValueSignalLoader', 'Tools/ValueIntelligence');
App::uses('ValueTrustTool', 'Tools/ValueIntelligence');
App::uses('ValueStatementTool', 'Tools/ValueIntelligence');
App::uses('ValueEscalationBase', 'Model/ValueEscalations');

/**
 * The categorical half of an assessment: what does the record assert
 * this value is?
 *
 * Three axes make up an assessment — what the record says the value is,
 * whether that still matters, and how much of it can be trusted. This
 * file owns the first. It is deliberately not a number: an engine
 * reading MISP's own tables can say *"four organisations flagged this
 * as an indicator and nobody contradicted them"*, and that is a
 * statement about the record rather than about the value. The signal strength
 * ledger says how thin or thick that record is; the lean says which way
 * it points.
 *
 * ## Stances are voices: one per organisation, at its grade
 *
 * One organisation putting the same value in forty events with `to_ids`
 * set is one voice, not forty. Counting occurrences would let a single
 * prolific reporter outvote everyone else on the instance, and it is
 * the same independence argument the reporting signal already makes
 * about corroboration.
 *
 * **A dispute is a voice too, and never a veto.** A false positive
 * or an outside verdict used to decide the lean alone through the
 * lean-disputed check, so one false positive outvoted ten
 * reporters. It is now weighed in the same count:
 *
 * ```
 * threat voices  Σ factor of orgs asserting it (to_ids = 1)
 *                + Σ weight of graded verdicts arguing threat
 * benign voices  Σ factor of orgs that filed a false positive and
 *                  do not themselves assert it
 *                + Σ factor × weight of reporters' own
 *                  false-positive warnings
 *                + Σ weight of graded verdicts arguing benign
 * threat_share   threat / (threat + benign)
 * ```
 *
 * **`to_ids = 0` is no voice.**
 * MISP defines the flag as *use this for detection*; leaving it off
 * says the value is context, noisy, a victim's or simply the type's
 * default — never that it is harmless. Benign comes only from
 * somebody saying so.
 *
 * A reporter that asserts the value and also tags its own report with
 * a false-positive warning keeps one voice, split: `high` or a
 * confirmation moves all of it to benign, `medium` half. A reporter
 * that only recorded it as context gets a benign voice from its
 * warning and nothing else.
 *
 * The factor is the organisation's reliability grade once the
 * profile grades anybody, and `1` until then: `G` abstains, `E`
 * is a quarter voice. A verdict weighs its module's grade, halved
 * where it hedges — the same weight its ledger row is paid.
 *
 * **An organisation's latest statement wins.** A reporter filing a
 * false positive after its own newest `to_ids = 1` row has changed its
 * stance: one benign voice, not a threat voice and a benign one.
 *
 * **An old dispute counts less.** A false positive older than another
 * organisation's newest standing assertion counts at
 * `thresholds.dispute_stale_factor` — the reporters reasserting the
 * value after the dispute is information.
 *
 * ## The rules, first match wins
 *
 * ```
 * 1. nothing this viewer can see                      → none
 * 2. an enabled conflict rule fires                   → contested, named
 * 3. a false_positive list matched and the stances
 *    are not a supermajority the other way            → benign
 *    no voice either way                              → unflagged
 * 4. threat_share ≥ lean_supermajority                → threat
 * 5. threat_share ≤ 1 − lean_supermajority            → benign
 * 6. otherwise                                        → contested
 * ```
 *
 * `unflagged` sits after rules 2 and 3 so a conflict rule still names
 * a contradiction and a resolver address still reads benign through
 * its list.
 *
 * **Rule 3 sits before rule 4 on purpose**, and it is what makes a
 * value's history legible. The day an address lands on the
 * public-resolver warninglist, its lean flips from a rule-6 muddle to
 * rule-3 benign on exactly the same evidence — the profile's knowledge
 * changed, not the rows. A summed score could not have flipped on one
 * new list hit; a rule ahead of the stance count can.
 *
 * Rule 2 sits before rule 3 because precedence needs a guard: a
 * `false_positive` list against nearly unanimous threat stances is a
 * collision of two deliberate judgements, and the conflict rule that
 * names it has to get there before either one wins quietly.
 *
 * A record flagged only by organisations graded to count for nothing
 * has nothing to lean on either, and answers `none` with
 * `decided_by = 'no_voice'`.
 *
 * There is a seventh rule, and it lives with the ledger rather than
 * here: a lean whose anchored lean rows **that are not voices** sum
 * below zero becomes contested, because the record is then disputing
 * its own assertion. On the shipped catalogue that is the warninglist
 * hit. That one cannot be decided before scoring, so
 * `ValueVerdictTool` applies it, and it writes
 * `decided_by = 'lean_disputed'` so the band stops naming the lean the
 * rule discarded.
 *
 * **The lean rows and not the signal strength**: weighed against the whole
 * ledger the rule would fire on thin records rather than contradictory
 * ones — a value with no galaxy, no first-seen, no sighting and
 * nothing recent would trip it on absence penalties alone.
 *
 * ## Why a rule that could not run is reported
 *
 * A signal that fails to load is named in the ledger's `not_counted`
 * list. A conflict rule has no ledger row to be missing from — it
 * contributes nothing to the signal strength — so a rule that could not run
 * would leave the lean unescalated with no trace anywhere the reader
 * looks. That is a silent change of answer, so `rule_errors` comes back
 * beside the lean and is rendered with it.
 */
class ValueLeanTool
{
    /** The five states a lean can take. */
    const LEANS = array('threat', 'benign', 'contested', 'unflagged',
        'none');

    /**
     * How close to a share threshold counts as reaching it.
     *
     * Not defensive rounding — a fencepost that a strict comparison
     * gets wrong. A threshold written as `0.66` is not `0.66` in
     * binary, and neither is `1 - 0.66`: a value held by 34 of 100
     * organisations computes a share very slightly *above* the mirror
     * of the shipped supermajority, so a strict `<=` reads the mirror
     * boundary as a stance split and the derivation stops being
     * symmetric. The threshold an analyst typed has to mean what it
     * says on both sides, so the comparison carries a tolerance far
     * smaller than one organisation can move any real share.
     */
    const SHARE_TOLERANCE = 1e-9;

    /** What an old dispute counts for when the profile does not say. */
    const DISPUTE_STALE_FACTOR = 0.5;

    /**
     * Whether a share reaches a threshold, at the boundary as well as
     * past it.
     *
     * @param float $share
     * @param float $threshold
     * @return bool
     */
    public static function atLeast($share, $threshold)
    {
        return (float)$share >= (float)$threshold - self::SHARE_TOLERANCE;
    }

    /**
     * The whole derivation for one value.
     *
     * @param array $context From the context builder, ACL-scoped
     * @param array|null $profile An `AnalystProfile` row, unwrapped, or
     *                            null when no profile is in force
     * @return array `lean`, `rule`, `stances` and `rule_errors`
     */
    public function leanFor(array $context, $profile = null)
    {
        $stances = $this->stancesFor($context, $profile);
        $errors = $this->ruleErrors($profile);

        /*
         * Rule 1. Stated as a fact about the context rather than about
         * the value: a value with no occurrence *this viewer can see*
         * has no record to lean on, and an engine that read its own
         * blindness as evidence would call every invisible value
         * benign.
         */
        if ($this->nothingVisible($context, $stances)) {
            return $this->answer('none', null, $stances, $errors,
                'nothing_visible');
        }
        /*
         * Something visible, flagged, and nobody counted: every
         * organisation flagging it is graded to count for nothing and
         * no dispute or verdict has weight either. Not a share of zero,
         * which rule 5 would read as a benign supermajority.
         */
        if ($stances['voices'] <= 0.0 && $stances['flagging_orgs'] > 0) {
            return $this->answer('none', null, $stances, $errors,
                'no_voice');
        }

        // Rule 2.
        $fired = $this->firstRuleFiring($context, $profile, $stances);
        if ($fired !== null) {
            return $this->answer(
                'contested',
                $fired,
                $stances,
                $errors,
                'escalation'
            );
        }

        $supermajority = $stances['supermajority'];
        $share = $stances['threat_share'];

        // Rule 3.
        if ($this->falsePositiveListed($context)) {
            if (!self::atLeast($share, $supermajority)) {
                return $this->answer('benign', null, $stances, $errors,
                    'false_positive_listed');
            }
            /*
             * A supermajority too few to fire the conflict rule: the
             * list still decides, or one flagger beside it would read
             * as a threat.
             */
            $floor = $stances['listed_floor'];
            if ($floor !== null && $stances['threat_orgs'] < $floor) {
                return $this->answer('benign', null, $stances, $errors,
                    'false_positive_floor');
            }
        }
        /*
         * Nobody flagged it for detection and nobody said it is
         * harmless: the record holds it as context.
         */
        if ($stances['voices'] <= 0.0) {
            return $this->answer('unflagged', null, $stances, $errors,
                'unflagged');
        }
        /*
         * Rules 4 and 5. Stated as *a supermajority on either side*
         * rather than as one comparison and its arithmetic mirror,
         * because that is what the rule means and it is the form that
         * cannot come out asymmetric.
         */
        if (self::atLeast($share, $supermajority)) {
            return $this->answer('threat', null, $stances, $errors,
                'threat_supermajority');
        }
        if (self::atLeast(1 - $share, $supermajority)) {
            return $this->answer('benign', null, $stances, $errors,
                'benign_supermajority');
        }
        // Rule 6.
        return $this->answer('contested', null, $stances, $errors,
            'no_supermajority');
    }

    /**
     * The stance count, and the threshold it is read against.
     *
     * Public because it is the input to every conflict rule and to the
     * lean's own falsifiability line, and because a caller that has
     * already derived a lean should not have to count the stances
     * again to explain it.
     *
     * `threat_orgs` and `benign_orgs` stay headcounts — of the
     * organisations whose voice carries weight — because the prose
     * names organisations; `threat_share` is read off the voices.
     *
     * @param array $context
     * @param array|null $profile
     * @return array
     */
    public function stancesFor(array $context, $profile = null)
    {
        $orgs = isset($context['orgs']) && is_array($context['orgs'])
            ? $context['orgs']
            : array();
        $sightings = isset($context['sightings'])
            && is_array($context['sightings'])
            ? $context['sightings']
            : array();
        $trust = ValueTrustTool::blockFrom($context);
        $weighted = !empty($trust['in_force']);
        $staleFactor = self::disputeStaleFactor($profile);
        $fpLast = $this->falsePositiveStamps($sightings);

        /*
         * Who still asserts it, and since when. Settled before any
         * dispute is weighed, because whether a false positive is old
         * is a question about the assertions that stand — not about
         * one a reporter has since withdrawn.
         */
        $reporters = array();
        $reporterIds = array();
        $standing = array();
        foreach ($orgs as $index => $org) {
            $id = (int)($org['id'] ?? 0);
            $yes = !empty($org['to_ids_yes']);
            /*
             * An organisation whose stance columns are both zero holds
             * no occurrence and so casts no vote. It cannot happen from
             * the context builder's own query; it can happen to a
             * caller assembling a context by hand, and counting it in
             * the denominator would dilute everybody else's vote with
             * a row that says nothing.
             */
            if (!$yes && empty($org['to_ids_no'])) {
                continue;
            }
            /*
             * Keyed by position, not id: an organisation this viewer
             * cannot name arrives as `0`, and so does every
             * organisation a probe appends.
             */
            $reporters[$index] = $org;
            $reporterIds[$id] = true;
            if (!$yes) {
                continue;
            }
            $flagged = isset($org['newest_flagged'])
                ? (int)$org['newest_flagged']
                : (int)($org['newest'] ?? 0);
            $withdrawnAt = $fpLast[$id] ?? null;
            if ($id > 0 && $withdrawnAt !== null
                && $withdrawnAt > $flagged
            ) {
                continue;
            }
            $standing[$index] = array('id' => $id, 'at' => $flagged);
        }

        $threat = 0.0;
        $benign = 0.0;
        $threatOrgs = 0;
        $benignOrgs = 0;
        $unflaggedOrgs = 0;
        $flaggingOrgs = 0;
        $abstained = array();
        $disputes = array();
        $graded = false;
        $factor = function ($id) use ($context, $weighted, &$graded) {
            if (!$weighted) {
                return 1.0;
            }
            if (ValueTrustTool::gradeFor($context, $id) !== null) {
                $graded = true;
            }
            return ValueTrustTool::factor($context, $id);
        };

        $warnings = $this->warnings($context, $profile);
        foreach ($reporters as $index => $org) {
            $id = (int)($org['id'] ?? 0);
            $f = $factor($id);
            if ($f <= 0.0) {
                $abstained[] = (string)($org['name'] ?? '');
            }
            if (!empty($org['to_ids_yes'])) {
                $flaggingOrgs++;
            }
            $warn = $id > 0 && isset($warnings[$id])
                ? $warnings[$id]['weight']
                : 0.0;
            if (isset($standing[$index]) && $warn > 0.0) {
                // Its own warning splits its one voice.
                $threat += $f * (1.0 - $warn);
                $benign += $f * $warn;
                if ($warn >= 1.0) {
                    $benignOrgs += $f > 0.0 ? 1 : 0;
                } else {
                    $threatOrgs += $f > 0.0 ? 1 : 0;
                }
                $disputes[] = array(
                    'kind' => 'warning',
                    'side' => 'benign',
                    'org_id' => $id,
                    'name' => $org['name'] ?? null,
                    'tag' => $warnings[$id]['tag'],
                    'stamp' => $warnings[$id]['at'],
                    'weight' => $f * $warn,
                    'stale' => false,
                    'withdrawn' => false,
                );
                continue;
            }
            if (isset($standing[$index])) {
                $threat += $f;
                $threatOrgs += $f > 0.0 ? 1 : 0;
                continue;
            }
            if (!empty($org['to_ids_yes'])) {
                // Withdrawn: its own later false positive is its voice.
                $disputes[] = $this->dispute($id, $org['name'] ?? null,
                    $fpLast[$id], $f, $standing, $staleFactor, true);
                $last = end($disputes);
                $benign += $last['weight'];
                $benignOrgs += $last['weight'] > 0.0 ? 1 : 0;
                continue;
            }
            /*
             * Recorded with `to_ids = 0` only: context, not a claim
             * that the value is harmless. Its own false-positive
             * warning or its own false positive is the way it gets a
             * voice; the filing, the stronger statement, wins.
             */
            if ($id > 0 && array_key_exists($id, $fpLast)) {
                $disputes[] = $this->dispute($id, $org['name'] ?? null,
                    $fpLast[$id], $f, $standing, $staleFactor, false);
                $last = end($disputes);
                $benign += $last['weight'];
                $benignOrgs += $last['weight'] > 0.0 ? 1 : 0;
                continue;
            }
            if ($warn > 0.0) {
                $benign += $f * $warn;
                $benignOrgs += $f > 0.0 ? 1 : 0;
                $disputes[] = array(
                    'kind' => 'warning',
                    'side' => 'benign',
                    'org_id' => $id,
                    'name' => $org['name'] ?? null,
                    'tag' => $warnings[$id]['tag'],
                    'stamp' => $warnings[$id]['at'],
                    'weight' => $f * $warn,
                    'stale' => false,
                    'withdrawn' => false,
                );
                continue;
            }
            $unflaggedOrgs++;
        }

        $names = isset($sightings['fp_org_list'])
            && is_array($sightings['fp_org_list'])
            ? array_column($sightings['fp_org_list'], 'name', 'id')
            : array();
        foreach ($fpLast as $id => $stamp) {
            if ($id === 0 || isset($reporterIds[$id])) {
                continue;
            }
            $f = $factor($id);
            $disputes[] = $this->dispute($id, $names[$id] ?? null,
                $stamp, $f, $standing, $staleFactor, false);
            $last = end($disputes);
            $benign += $last['weight'];
            $benignOrgs += $last['weight'] > 0.0 ? 1 : 0;
        }
        /*
         * Anonymised filings are one unrated voice between them: the
         * filers cannot be told apart, so they cannot be counted as
         * several, and one of them may be a reporter.
         */
        if (array_key_exists(0, $fpLast)) {
            $disputes[] = $this->dispute(0, null, $fpLast[0],
                $factor(0), $standing, $staleFactor, false);
            $last = end($disputes);
            $benign += $last['weight'];
        }

        $modules = array('threat' => 0, 'benign' => 0);
        foreach ($this->moduleVoices($context, $profile) as $voice) {
            if ($voice['side'] === 'threat') {
                $threat += $voice['weight'];
            } else {
                $benign += $voice['weight'];
            }
            $modules[$voice['side']]++;
            $disputes[] = array(
                'kind' => 'enrichment',
                'side' => $voice['side'],
                'module' => $voice['module'],
                'grade' => $voice['grade'],
                'word' => $voice['word'],
                'stamp' => $voice['ran_at'],
                'weight' => $voice['weight'],
                'stale' => false,
                'withdrawn' => false,
            );
        }

        $voices = $threat + $benign;
        return array(
            'threat_orgs' => $threatOrgs,
            'benign_orgs' => $benignOrgs,
            'orgs' => $threatOrgs + $benignOrgs,
            'reporters' => count($reporters),
            'unflagged_orgs' => $unflaggedOrgs,
            'flagging_orgs' => $flaggingOrgs,
            'threat_voices' => $threat,
            'benign_voices' => $benign,
            'voices' => $voices,
            'threat_modules' => $modules['threat'],
            'benign_modules' => $modules['benign'],
            'threat_share' => $voices <= 0.0 ? 0.0 : $threat / $voices,
            'supermajority' => self::supermajority($profile),
            'listed_floor' => $this->listedFloor($profile),
            'weighted' => $graded,
            'abstained' => array_values(array_filter($abstained,
                'strlen')),
            'disputes' => $disputes,
        );
    }

    /**
     * One false-positive voice: its weight, and whether it is old.
     *
     * @param int $id The filer, `0` when anonymised
     * @param string|null $name
     * @param int|null $stamp Its newest false positive, null when the
     *                        context does not carry one
     * @param float $factor The filer's grade factor
     * @param array $standing `id` and `at` of each standing assertion
     * @param float $staleFactor
     * @param bool $withdrawn A reporter withdrawing its own assertion
     * @return array
     */
    private function dispute($id, $name, $stamp, $factor,
        array $standing, $staleFactor, $withdrawn
    ) {
        $stale = false;
        if ($stamp !== null) {
            foreach ($standing as $assertion) {
                if (($id === 0 || $assertion['id'] !== $id)
                    && $assertion['at'] > $stamp
                ) {
                    $stale = true;
                    break;
                }
            }
        }
        return array(
            'kind' => 'false_positive',
            'side' => 'benign',
            'org_id' => $id,
            'name' => $name,
            'stamp' => $stamp,
            'weight' => $factor * ($stale ? $staleFactor : 1.0),
            'stale' => $stale,
            'withdrawn' => $withdrawn,
        );
    }

    /**
     * Each filer's newest false positive, anonymised filings under `0`.
     *
     * A context carrying counts but no stamps — built before the
     * stamps existed, or by hand — reads each filing as current: a
     * date nobody recorded cannot make a dispute old, or a reporter's
     * assertion withdrawn.
     *
     * @param array $sightings
     * @return array orgId => stamp|null
     */
    private function falsePositiveStamps(array $sightings)
    {
        $stamps = isset($sightings['by_org_fp_last'])
            && is_array($sightings['by_org_fp_last'])
            ? $sightings['by_org_fp_last']
            : array();
        $out = array();
        $byOrg = isset($sightings['by_org_fp'])
            && is_array($sightings['by_org_fp'])
            ? $sightings['by_org_fp']
            : array();
        foreach ($byOrg as $id => $count) {
            if ((int)$count > 0 && (int)$id > 0) {
                $out[(int)$id] = isset($stamps[$id])
                    ? (int)$stamps[$id]
                    : null;
            }
        }
        $anonymous = (int)($sightings['anonymous_fp'] ?? 0);
        if (empty($byOrg) && $anonymous === 0
            && (int)($sightings['fp'] ?? 0) > 0
        ) {
            $anonymous = (int)$sightings['fp'];
        }
        if ($anonymous > 0) {
            $out[0] = isset($sightings['anonymous_fp_last'])
                ? (int)$sightings['anonymous_fp_last']
                : (isset($sightings['fp_last_stamp'])
                    ? (int)$sightings['fp_last_stamp']
                    : null);
        }
        return $out;
    }

    /**
     * The outside verdicts the profile counts, read through the signal
     * that scores them, so the lean and the ledger cannot disagree
     * about which verdicts count.
     *
     * None when the profile does not enable the signal: an analyst
     * who switched enrichment off has switched off its voices too.
     *
     * @param array $context
     * @param array|null $profile
     * @return array
     */
    private function moduleVoices(array $context, $profile)
    {
        $entry = null;
        foreach (self::section($profile, 'signals') as $candidate) {
            if (is_array($candidate)
                && ($candidate['id'] ?? null) === 'enrichment.answer'
            ) {
                $entry = $candidate;
                break;
            }
        }
        if ($entry === null || (array_key_exists('enabled', $entry)
            && empty($entry['enabled']))
        ) {
            return array();
        }
        $signal = ValueSignalLoader::get('enrichment.answer');
        if ($signal === null || !method_exists($signal, 'voices')) {
            return array();
        }
        try {
            return $signal->voices($context, $entry);
        } catch (Throwable $e) {
            return array();
        }
    }

    /**
     * Each reporter's own false-positive warning, when the profile
     * counts them — the same switch as the ledger row that draws them.
     *
     * @param array $context
     * @param array|null $profile
     * @return array org id => `weight`, `tag`, `at`
     */
    private function warnings(array $context, $profile)
    {
        foreach (self::section($profile, 'signals') as $entry) {
            if (!is_array($entry) || ($entry['id'] ?? null)
                !== 'reporting.false_positive_risk'
            ) {
                continue;
            }
            if (array_key_exists('enabled', $entry)
                && empty($entry['enabled'])
            ) {
                return array();
            }
            return ValueStatementTool::warningsByOrg($context);
        }
        return array();
    }

    /**
     * What a false positive counts for once the reporters have
     * reasserted the value after it.
     *
     * @param array|null $profile
     * @return float
     */
    public static function disputeStaleFactor($profile)
    {
        $thresholds = self::section($profile, 'thresholds');
        if (isset($thresholds['dispute_stale_factor'])
            && is_numeric($thresholds['dispute_stale_factor'])
        ) {
            $given = (float)$thresholds['dispute_stale_factor'];
            if ($given >= 0.0 && $given <= 1.0) {
                return $given;
            }
        }
        return self::DISPUTE_STALE_FACTOR;
    }

    /**
     * Whether the context has anything to lean on.
     *
     * Two ways it may not, and they are the same answer: no occurrence
     * at all, or occurrences whose stances could not be read. The
     * second is only reachable from a hand-built context, and treating
     * it as `none` is the conservative reading — a share computed from
     * a zero denominator would be a number with no evidence under it.
     *
     * @param array $context
     * @param array $stances
     * @return bool
     */
    private function nothingVisible(array $context, array $stances)
    {
        $occurrences = isset($context['occurrences']['total'])
            ? (int)$context['occurrences']['total']
            : 0;
        return $occurrences === 0 || $stances['reporters'] === 0;
    }

    /**
     * Whether any list that matched resolved to `false_positive`.
     *
     * The resolved category is read off the individual hits rather than
     * off the summary, because a value can hit a resolver list and a
     * CDN list at once and each rule is entitled to see its own.
     *
     * @param array $context
     * @return bool
     */
    private function falsePositiveListed(array $context)
    {
        $hits = isset($context['warninglist']['hits'])
            ? $context['warninglist']['hits']
            : array();
        foreach ($hits as $hit) {
            if (($hit['category'] ?? null) === 'false_positive') {
                return true;
            }
        }
        return false;
    }

    /**
     * The listed rule's headcount floor, when the profile has that rule
     * enabled over a false-positive list.
     *
     * @param array|null $profile
     * @return int|null
     */
    private function listedFloor($profile)
    {
        foreach ($this->ruleEntries($profile) as $entry) {
            if ($entry['id'] !== 'conflict:listed-vs-asserted') {
                continue;
            }
            $rule = ValueSignalLoader::get(
                $entry['id'],
                ValueSignalLoader::SUBJECT_ESCALATION
            );
            return $rule !== null && method_exists($rule, 'floor')
                ? $rule->floor($entry)
                : null;
        }
        return null;
    }

    /**
     * The first enabled conflict rule that fires, in the profile's own
     * order.
     *
     * **List order decides**, and it is the profile author's to
     * arrange. Two rules can be true of the same value — a value on
     * both a CDN list and a resolver list, reported by a supermajority,
     * satisfies both shipped rules — and picking the one that reads
     * best on that instance is an editorial call, not something to
     * derive from the rules themselves.
     *
     * @param array $context
     * @param array|null $profile
     * @param array $stances
     * @return array|null
     */
    private function firstRuleFiring(array $context, $profile,
        array $stances
    ) {
        $context['stances'] = $stances;
        foreach ($this->ruleEntries($profile) as $entry) {
            $id = $entry['id'];
            $rule = ValueSignalLoader::get(
                $id,
                ValueSignalLoader::SUBJECT_ESCALATION
            );
            if ($rule === null) {
                continue;
            }
            if (!$this->usable($rule, $entry, $context)) {
                continue;
            }
            $outcome = $this->run($rule, $entry, $context);
            if ($outcome === null) {
                continue;
            }
            return array(
                'id' => $id,
                'prose' => $outcome['prose'],
                'evidence' => isset($outcome['evidence'])
                    ? $outcome['evidence']
                    : '',
                'tab' => $rule->tab,
                /*
                 * `id` and `prose` again, under the keys the templates
                 * read a rule block by.
                 */
                'name' => $id,
                'text' => $outcome['prose'],
            );
        }
        return null;
    }

    /**
     * Run one rule, treating a throw as *did not fire*.
     *
     * A dropped file whose `fires()` throws must not take the page
     * down; the loader's error list is where the admin's copy of the
     * problem goes, and `ruleErrors()` is where the reader's does.
     *
     * @param object $rule
     * @param array $entry
     * @param array $context
     * @return array|null
     */
    private function run($rule, array $entry, array $context)
    {
        try {
            $outcome = $rule->fires($context, $entry);
        } catch (Throwable $e) {
            return null;
        }
        if (!is_array($outcome) || empty($outcome['prose'])
            || !is_string($outcome['prose'])
        ) {
            return null;
        }
        return $outcome;
    }

    /**
     * Whether a rule may run at all: its evidence readable, and its
     * profile entry legal.
     *
     * @param object $rule
     * @param array $entry
     * @param array $context
     * @return bool
     */
    private function usable($rule, array $entry, array $context)
    {
        if (!empty($entry['emits'])
            && $entry['emits'] !== ValueEscalationBase::EMITS
        ) {
            return false;
        }
        if (empty($context['missing'])) {
            return true;
        }
        foreach ($rule->reads as $key) {
            if (isset($context['missing'][$key])) {
                return false;
            }
        }
        return true;
    }

    /**
     * Every reason the reader deserves for a rule that did not get to
     * decide: a profile weighting a rule this instance does not have, a
     * file that would not load, an entry asking for a lean a conflict
     * rule may not emit.
     *
     * All three are the same kind of problem — the lean on screen was
     * derived without a rule the profile said to apply — and all three
     * are invisible unless something says so.
     *
     * @param array|null $profile
     * @return array `id` and `note`
     */
    private function ruleErrors($profile)
    {
        $loaderErrors = ValueSignalLoader::errors(
            ValueSignalLoader::SUBJECT_ESCALATION
        );
        $errors = array();
        foreach ($this->ruleEntries($profile) as $entry) {
            $id = $entry['id'];
            if (!empty($entry['emits'])
                && $entry['emits'] !== ValueEscalationBase::EMITS
            ) {
                $errors[] = array(
                    'id' => $id,
                    'note' => sprintf(
                        __('The profile asks this conflict rule to'
                            . ' emit `%1$s`; a conflict rule may only'
                            . ' emit `%2$s`, so it did not run.'),
                        (string)$entry['emits'],
                        ValueEscalationBase::EMITS
                    ),
                );
                continue;
            }
            if (ValueSignalLoader::get(
                $id,
                ValueSignalLoader::SUBJECT_ESCALATION
            ) !== null) {
                continue;
            }
            $errors[] = array(
                'id' => $id,
                'note' => $this->missingReason($id, $loaderErrors),
            );
        }
        return $errors;
    }

    /**
     * A rule this instance does not have at all, against one it has but
     * could not load — the same distinction the ledger draws for a
     * signal, and the same two sentences.
     *
     * @param string $id
     * @param array $loaderErrors
     * @return string
     */
    private function missingReason($id, array $loaderErrors)
    {
        foreach ($loaderErrors as $file => $reason) {
            if (strpos($reason, '`' . $id . '`') !== false) {
                return sprintf(
                    __('The rule did not load (%1$s): %2$s'),
                    $file,
                    $reason
                );
            }
        }
        return __('This instance has no implementation for that'
            . ' conflict rule, so a contradiction the profile wanted'
            . ' named could not be checked.');
    }

    /**
     * The profile's enabled `escalations` entries, in order.
     *
     * A disabled rule is not an error and not reported: the analyst
     * turned it off, which is the whole point of the section.
     *
     * @param array|null $profile
     * @return array
     */
    private function ruleEntries($profile)
    {
        $entries = array();
        foreach (self::section($profile, 'escalations') as $entry) {
            if (!is_array($entry) || empty($entry['id'])) {
                continue;
            }
            if (array_key_exists('enabled', $entry)
                && empty($entry['enabled'])
            ) {
                continue;
            }
            $entries[] = $entry;
        }
        return $entries;
    }

    /**
     * The share of organisations that makes a stance decisive.
     *
     * Public because the editor asks the same question: a rule whose
     * threshold *follows the profile* has to say in its own box which
     * number it is following, and a second copy of this rule in the
     * form would be a placeholder that lies the day somebody stores
     * `0.4`.
     *
     * @param array|null $profile
     * @return float
     */
    public static function supermajority($profile)
    {
        $thresholds = self::section($profile, 'thresholds');
        if (isset($thresholds['lean_supermajority'])
            && is_numeric($thresholds['lean_supermajority'])
        ) {
            $given = (float)$thresholds['lean_supermajority'];
            /*
             * A threshold at or below a half would make rules 4 and 5
             * both true of the same value and the first one win, which
             * is a coin toss wearing a threshold's clothes. Above 1 it
             * can never be met. Either way the profile is asking for
             * something the derivation cannot express, so the shipped
             * meaning of *supermajority* stands.
             */
            if ($given > 0.5 && $given <= 1.0) {
                return $given;
            }
        }
        return 0.66;
    }

    /**
     * One `parameters` section, whichever shape the profile arrived in.
     *
     * @param array|null $profile
     * @param string $name
     * @return array
     */
    private static function section($profile, $name)
    {
        if (!is_array($profile)) {
            return array();
        }
        if (isset($profile['parameters'][$name])
            && is_array($profile['parameters'][$name])
        ) {
            return $profile['parameters'][$name];
        }
        if (isset($profile[$name]) && is_array($profile[$name])) {
            return $profile[$name];
        }
        return array();
    }

    /**
     * The return shape, in one place so the eight exits cannot drift
     * apart.
     *
     * **`decided_by` names the exit**, because the alternative is a
     * reader of this array re-deriving which rule fired from the lean
     * and the stances — and the derivation has a precedence that is
     * invisible from outside. Rules 3 and 5 both answer `benign`, and
     * a value that is false-positive listed *and* benign by
     * supermajority takes rule 3 because it is written first. Anything
     * composing prose about *why* has to know that, and asking it to
     * work it out again is how two implementations of one rule drift
     * apart.
     *
     * @param string $lean
     * @param array|null $rule
     * @param array $stances
     * @param array $errors
     * @param string $decidedBy Which of the nine exits this is
     * @return array
     */
    private function answer($lean, $rule, array $stances,
        array $errors, $decidedBy
    ) {
        return array(
            'lean' => $lean,
            'rule' => $rule,
            'stances' => $stances,
            'rule_errors' => $errors,
            'decided_by' => $decidedBy,
        );
    }
}
