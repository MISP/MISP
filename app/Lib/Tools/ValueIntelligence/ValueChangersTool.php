<?php

App::uses('ValueLeanTool', 'Tools/ValueIntelligence');
App::uses('ValueSignalLoader', 'Tools/ValueIntelligence');
App::uses('ValueVerdictTool', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

/**
 * What would change this — derived, one line per axis.
 *
 * An assessment that cannot say what would move it is an opinion. A
 * hand-written falsifier would be useless as a claim: it is a promise
 * nobody checked against the arithmetic that would have to honour it.
 *
 * So each line is computed, and computed the honest way — by asking the
 * derivation itself. The lean line appends organisations to a copy of
 * the context and re-runs the lean rules until the answer changes, so
 * the sentence is true by construction rather than by a second
 * implementation of the same precedence. The signal-strength line asks the
 * banding what a hypothetical signal strength would band as, so a clamp or a
 * minimum-signal count cannot be quietly ignored by the prose.
 *
 * **The cheapest changer per axis, not all of them.** A reader wants
 * the nearest edge, and three lines of *"and also, 40 more
 * organisations"* is noise. Where two changes are equally cheap the one
 * that firms the record's own assertion is preferred, because that is
 * the direction a reader is usually checking.
 *
 * **Nothing here knows a signal by name.** The signal-strength line needs a
 * unit a reader can supply more of — an organisation, a sighting, a
 * galaxy cluster — and it gets it from the signal's own `$unit`
 * declaration, so a rule dropped into an instance's own signal
 * directory can be named in a falsifiability line without this file
 * changing.
 */
class ValueChangersTool
{
    /**
     * How many organisations the lean probe is willing to imagine.
     *
     * A value 30 organisations deep genuinely needs 15 more to shift a
     * two-thirds share, and saying so is useful. Past this the sentence
     * stops being a falsifier and starts being a way of saying *"this
     * will not change"*, which the absence of a line already says more
     * briefly.
     */
    const MAX_ORGS = 25;

    /** Above any real organisation id: a probe's made-up filer. */
    const PROBE_ORG_ID = 2000000000;

    /**
     * How many of a signal's own units the signal-strength probe will imagine.
     *
     * Every shipped unit is capped well inside this, so the bound only
     * ever stops a profile whose cap is enormous and whose per-unit
     * points are tiny — a shape whose falsifier is better stated as a
     * points gap anyway.
     */
    const MAX_UNITS = 40;

    /** @var ValueLeanTool */
    private $lean;

    public function __construct($lean = null)
    {
        $this->lean = $lean === null ? new ValueLeanTool() : $lean;
    }

    /**
     * The falsifiability lines for one assessment.
     *
     * @param array $verdict What the accumulator returned
     * @param array $context The context it was scored from
     * @param array|null $profile The profile in force
     * @return array `axis`, `direction` and `text`
     */
    public function changersFor(array $verdict, array $context,
        $profile = null
    ) {
        $changers = array();
        $lean = $this->leanChanger($verdict, $context, $profile);
        if ($lean !== null) {
            $changers[] = $lean;
        }
        /*
         * The relevance line, in axis order and derived where the axis
         * is rather than here. It is the one falsifier that can be
         * solved rather than probed — the boundary is `elapsed = ttl`,
         * so the answer is arithmetic on the runway and re-running the
         * derivation would tell nobody anything the subtraction does
         * not. `ValueRelevanceTool::changerFor` owns it for the same
         * reason `signalStrengthChanger` asks the banding: the sentence must
         * come from whatever would have to honour it.
         */
        $relevance = isset($verdict['relevance'])
            ? ValueRelevanceTool::changerFor($verdict['relevance'])
            : null;
        if ($relevance !== null) {
            $changers[] = $relevance;
        }
        $signalStrength = $this->signalStrengthChanger($verdict, $context,
            $profile);
        if ($signalStrength !== null) {
            $changers[] = $signalStrength;
        }
        return $changers;
    }

    /**
     * What would move the lean.
     *
     * Two cases, and they are different questions. A lean the
     * categorical rules reached moves when the stances move, and the
     * probe finds out how far. A lean that became contested *because
     * the ledger came out against the record's own assertion* moves
     * when the ledger does, so the line is about points rather than
     * organisations — and it is the one place where the lean axis and
     * the signal-strength axis are the same sentence.
     *
     * @param array $verdict
     * @param array $context
     * @param array|null $profile
     * @return array|null
     */
    private function leanChanger(array $verdict, array $context,
        $profile
    ) {
        if ($verdict['lean'] === 'none'
            && ($verdict['decided_by'] ?? null) !== 'no_voice'
        ) {
            return null;
        }
        if ($this->disputedByLedger($verdict)) {
            return array(
                'axis' => 'lean',
                'direction' => $verdict['derived_lean'] === 'threat'
                    ? 'up'
                    : 'down',
                /*
                 * `lean_weight` and not `signal_strength`, which are separate
                 * sums: the lean-disputed check weighs the rows that
                 * read the value, so the gap a reader would have to
                 * close is on that axis. Off the signal strength it would name
                 * a number nothing is measuring against — and on a
                 * record whose every row weighs rather than reads, a
                 * number no amount of evidence about the value could
                 * move.
                 */
                'text' => sprintf(
                    __('%1$d more points backing what the record'
                        . ' asserts — %2$s'),
                    abs((int)(isset($verdict['lean_weight'])
                        ? $verdict['lean_weight']
                        : 0)) + 1,
                    $this->leanPhrase($verdict['derived_lean'])
                ),
            );
        }
        $best = null;
        foreach (array('threat', 'benign') as $stance) {
            $found = $this->probeStance(
                $verdict['derived_lean'],
                $context,
                $profile,
                $stance
            );
            if ($found === null) {
                continue;
            }
            if ($best === null || $found['cost'] < $best['cost']) {
                $best = $found;
            }
        }
        foreach ($this->probeDelisting($verdict, $context, $profile)
            as $found
        ) {
            if ($best === null || $found['cost'] < $best['cost']) {
                $best = $found;
            }
        }
        if ($best === null) {
            return null;
        }
        return array(
            'axis' => 'lean',
            'direction' => $best['lean'] === 'threat' ? 'up' : 'down',
            'text' => sprintf(
                __('%1$s — %2$s'),
                $best['phrase'],
                $this->leanPhrase($best['lean'])
            ),
        );
    }

    /**
     * What a warninglist letting go of the value would do to the lean.
     *
     * The probe the two shipped conflict rules need: a resolver list
     * gaining an address can flip its lean without a single row
     * changing, and the list losing it would flip it back. Neither is a
     * change in the stances, so the stance probe cannot see it.
     *
     * Counted as one change however many lists carry the category,
     * because a category ceasing to apply is a single fact about the
     * value — which is also what makes it usually the cheapest thing
     * on the card.
     *
     * @param array $verdict
     * @param array $context
     * @param array|null $profile
     * @return array
     */
    private function probeDelisting(array $verdict, array $context,
        $profile
    ) {
        $hits = isset($context['warninglist']['hits'])
            ? $context['warninglist']['hits']
            : array();
        $categories = array();
        foreach ($hits as $hit) {
            if (!empty($hit['category'])) {
                $categories[$hit['category']] = true;
            }
        }
        $found = array();
        foreach (array_keys($categories) as $category) {
            $probe = $context;
            $probe['warninglist']['hits'] = array();
            foreach ($hits as $hit) {
                if (($hit['category'] ?? null) !== $category) {
                    $probe['warninglist']['hits'][] = $hit;
                }
            }
            $derived = $this->lean->leanFor($probe, $profile);
            if ($derived['lean'] === $verdict['derived_lean']) {
                continue;
            }
            $found[] = array(
                'cost' => 1,
                'lean' => $derived['lean'],
                'phrase' => sprintf(
                    __('Removed from every matching `%s` list'),
                    $category
                ),
            );
        }
        return $found;
    }

    /**
     * The fewest organisations of one stance that change the lean.
     *
     * The probe appends organisations to a copy of the context and asks
     * the lean rules again, which is what makes the sentence honest
     * about precedence: a value on a false-positive list whose stances
     * reach a supermajority does not become a threat, it trips the
     * conflict rule and becomes contested, and the probe reports
     * exactly that because it ran the same rules the page did.
     *
     * @param string $lean The lean the rules reached
     * @param array $context
     * @param array|null $profile
     * @param string $stance `threat` or `benign`
     * @return array|null `cost`, `lean`, `phrase`
     */
    private function probeStance($lean, array $context, $profile,
        $stance
    ) {
        $probe = $context;
        $now = isset($context['now']) ? (int)$context['now'] : time();
        for ($added = 1; $added <= self::MAX_ORGS; $added++) {
            if ($stance === 'threat') {
                $probe['orgs'][] = array(
                    'id' => 0,
                    'name' => __('Another organisation'),
                    'occurrences' => 1,
                    'to_ids_yes' => 1,
                    'to_ids_no' => 0,
                    'newest' => $now,
                );
                $probe['occurrences']['total'] =
                    (int)$context['occurrences']['total'] + $added;
                $probe['occurrences']['orgs'] =
                    (int)$context['occurrences']['orgs'] + $added;
            } else {
                /*
                 * `to_ids = 0` is no voice, so the benign side
                 * moves only when somebody says so: an organisation
                 * outside the record filing a false positive. Its id
                 * is past any real one, so it reads as unrated.
                 */
                $id = self::PROBE_ORG_ID + $added;
                $probe['sightings']['by_org_fp'][$id] = 1;
                $probe['sightings']['by_org_fp_last'][$id] = $now;
                $probe['sightings']['fp_org_list'][] = array(
                    'id' => $id,
                    'name' => __('Another organisation'),
                );
            }
            $derived = $this->lean->leanFor($probe, $profile);
            if ($derived['lean'] !== $lean) {
                return array(
                    'cost' => $added,
                    'lean' => $derived['lean'],
                    'phrase' => $this->stancePhrase($stance, $added),
                );
            }
        }
        return null;
    }

    /**
     * What would move the signal-strength band.
     *
     * Three cases, in the order they are worth reading. A band held
     * down by the thin-record clamp is not short of points and saying
     * *"18 more points"* would be a lie — what it is short of is a
     * second source, so the line says so. A band below the top asks
     * what reaches the next one. A band already at the top asks what
     * would lose it, because *nothing will change this* is not a
     * falsifier.
     *
     * @param array $verdict
     * @param array $context
     * @param array|null $profile
     * @return array|null
     */
    private function signalStrengthChanger(array $verdict, array $context,
        $profile
    ) {
        if ($verdict['band'] === 'none' || empty($verdict['ledger'])) {
            return null;
        }
        if ($verdict['band'] === 'high') {
            return $this->signalStrengthDrop($verdict, $profile);
        }
        $clamped = $this->clampPhrase($verdict, $context, $profile);
        if ($clamped !== null) {
            return $clamped;
        }
        return $this->signalStrengthClimb($verdict, $profile);
    }

    /**
     * The line for a record the clamp will not let past this band
     * whatever it scores.
     *
     * This has to be checked before the points line, not after it: a
     * record two points short of `medium` with one source and no
     * sightings can close those two points and still be `low`,
     * so *"9 more points and the record reaches the medium band"* would
     * be a falsifier that fails when a reader acts on it. What the
     * record is actually short of is a second source.
     *
     * Detected rather than assumed. The banding is asked what the next
     * band's own floor would band as, under this value's context and
     * with signals enough to satisfy the minimum — so the only thing
     * that can hold it below the target is the clamp. An analyst who
     * edits the clamp out of their profile stops seeing this line
     * without anything here changing.
     *
     * @param array $verdict
     * @param array $context
     * @param array|null $profile
     * @return array|null
     */
    private function clampPhrase(array $verdict, array $context,
        $profile
    ) {
        $clamp = $this->clamp($profile);
        if ($clamp === null) {
            return null;
        }
        $target = $verdict['band'] === 'medium' ? 'high' : 'medium';
        $enough = max(
            (int)$this->thresholds($profile,
                'signal_strength_high_min_signals', 4),
            (int)$verdict['signals']['fired']
        );
        $reachable = ValueVerdictTool::signalStrengthBand(
            $this->bandFloor($profile, $target),
            array('fired' => $enough, 'supporting' => $enough),
            $profile,
            $context
        );
        if ($reachable === $target) {
            return null;
        }
        $ceiling = ValueVerdictTool::clampCeiling(
            $this->section($profile, 'thresholds'),
            $context
        );
        if ($ceiling !== null) {
            $clamp = $ceiling['band'];
        }
        /*
         * The sighting half is offered only where a sighting could be
         * read. On an over-correlating value the sightings signals are
         * never evaluated — the rail says so, one card away, in *Not
         * counted* — so *or a sighting from an organisation that did
         * not* would name an act that moves nothing, with the reason it
         * moves nothing printed directly above it.
         */
        if ($this->gradesAModule($context)) {
            return array(
                'axis' => 'signal_strength',
                'direction' => 'up',
                'text' => sprintf(
                    __('A second source: one more organisation'
                        . ' reporting it, a sighting from an organisation'
                        . ' that did not, or a graded enrichment module'
                        . ' agreeing. More from the same source cannot'
                        . ' lift it past %s.'),
                    $clamp
                ),
            );
        }
        return array(
            'axis' => 'signal_strength',
            'direction' => 'up',
            'text' => sprintf(
                $this->sightingsReadable($context)
                    ? __('A second source: one more organisation'
                        . ' reporting it, or a sighting from an'
                        . ' organisation that did not. More from the same'
                        . ' source cannot lift it past %s.')
                    : __('A second source: one more organisation'
                        . ' reporting it. More from the same source'
                        . ' cannot lift it past %s.'),
                $clamp
            ),
        );
    }

    /**
     * Whether the profile grades any enrichment module, so that an
     * agreeing verdict would count as outside corroboration.
     *
     * @param array $context
     * @return bool
     */
    private function gradesAModule(array $context)
    {
        foreach ($context['enrichment']['trust']['factors'] ?? array()
            as $factor
        ) {
            if ((float)$factor > 0.0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a sighting filed today would reach the assessment.
     *
     * Two ways it would not: the value is flagged over-correlating, so
     * the row-evidence signals are not evaluated at all, or the
     * sightings fact could not be read and is carried in `missing`.
     * Either way the falsifiability card must not offer one.
     *
     * @param array $context
     * @return bool
     */
    private function sightingsReadable(array $context)
    {
        if (!empty($context['budget']['hot'])) {
            return false;
        }
        return empty($context['missing']['sightings']);
    }

    /**
     * The line for a band that could climb.
     *
     * @param array $verdict
     * @param array|null $profile
     * @return array|null
     */
    private function signalStrengthClimb(array $verdict, $profile)
    {
        $target = $verdict['band'] === 'medium' ? 'high' : 'medium';
        $floor = $this->bandFloor($profile, $target);
        $gap = $floor - (int)$verdict['signal_strength'];
        if ($gap <= 0) {
            /*
             * The points are already there and something else is
             * holding the band — the minimum fired-signal count, which
             * is a count of independent readings rather than a total,
             * so it is its own sentence.
             */
            return $this->minSignalsPhrase($verdict, $profile, $target);
        }
        $lever = $this->cheapestLever($verdict, $profile, $gap);
        if ($lever === null) {
            return array(
                'axis' => 'signal_strength',
                'direction' => 'up',
                'text' => sprintf(
                    __('%1$d more points would take it to the %2$s'
                        . ' band.'),
                    $gap,
                    $target
                ),
            );
        }
        return array(
            'axis' => 'signal_strength',
            'direction' => 'up',
            'text' => sprintf(
                __('%1$s — the record reaches the %2$s band.'),
                $lever,
                $target
            ),
        );
    }

    /**
     * The line for a band that could be lost.
     *
     * Expressed as the withdrawal of the rows carrying it, heaviest
     * first, because that is the shape the loss actually takes: an
     * organisation retracting an event, a galaxy cluster being
     * detached. The count is exact — the rows are removed from the sum
     * one at a time until the band drops.
     *
     * @param array $verdict
     * @param array|null $profile
     * @return array|null
     */
    private function signalStrengthDrop(array $verdict, $profile)
    {
        $rows = $this->supportingRows($verdict);
        if (empty($rows)) {
            return null;
        }
        $signalStrength = (int)$verdict['signal_strength'];
        $signals = array(
            'fired' => (int)$verdict['signals']['fired'],
            'supporting' => (int)($verdict['signals']['supporting'] ?? 0),
        );
        $removed = 0;
        foreach ($rows as $row) {
            $signalStrength -= $row['contribution'];
            $signals['fired']--;
            $signals['supporting']--;
            $removed++;
            $band = ValueVerdictTool::signalStrengthBand($signalStrength,
                $signals, $profile);
            if ($band !== 'high') {
                return array(
                    'axis' => 'signal_strength',
                    'direction' => 'down',
                    'text' => $removed === 1
                        ? sprintf(
                            __('Without "%1$s" (%2$s), it drops to the'
                                . ' %3$s band.'),
                            $rows[0]['signal'],
                            $this->signed($rows[0]['contribution']),
                            $band
                        )
                        : sprintf(
                            __('Without its %1$d heaviest rows, starting'
                                . ' with "%2$s", it drops to the %3$s'
                                . ' band.'),
                            $removed,
                            $rows[0]['signal'],
                            $band
                        ),
                );
            }
        }
        return null;
    }

    /**
     * The line for a band held back by the minimum number of signals
     * that must agree.
     *
     * @param array $verdict
     * @param array|null $profile
     * @param string $target
     * @return array|null
     */
    private function minSignalsPhrase(array $verdict, $profile,
        $target
    ) {
        if ($target !== 'high') {
            return null;
        }
        $minimum = $this->thresholds($profile,
            'signal_strength_high_min_signals', 4);
        $short = (int)$minimum
            - (int)($verdict['signals']['supporting'] ?? 0);
        if ($short <= 0) {
            return null;
        }
        return array(
            'axis' => 'signal_strength',
            'direction' => 'up',
            'text' => sprintf(
                __('The points are already there; %1$d more of the'
                    . ' profile\'s signals have to add points. A high'
                    . ' band means %2$d independent readings agree, not'
                    . ' one generous one.'),
                $short,
                (int)$minimum
            ),
        );
    }

    /**
     * The signals this assessment could not run, keyed by id.
     *
     * `not_counted` carries two kinds of entry — a signal that could
     * not run, and a budget or policy note — and only the first has an
     * id that matches a profile entry. The others simply never match.
     *
     * @param array $verdict
     * @return array id => true
     */
    private function setAsideIds(array $verdict)
    {
        $ids = array();
        $notCounted = isset($verdict['not_counted'])
            && is_array($verdict['not_counted'])
            ? $verdict['not_counted']
            : array();
        foreach ($notCounted as $entry) {
            if (!empty($entry['id'])) {
                $ids[$entry['id']] = true;
            }
        }
        return $ids;
    }

    /**
     * The cheapest declared unit that closes a points gap on its own.
     *
     * A signal declares what a reader can supply more of and what each
     * one is worth; this works out how many, in the lean's own
     * direction, and refuses to name a signal whose cap it would have
     * to exceed. Where a signal is currently firing on *absence* —
     * *"no galaxy on any occurrence"* — the first unit both removes
     * that penalty and adds its own points, and the arithmetic here
     * accounts for it rather than understating the change.
     *
     * @param array $verdict
     * @param array|null $profile
     * @param int $gap
     * @return string|null
     */
    private function cheapestLever(array $verdict, $profile, $gap)
    {
        $polarity = (int)$verdict['polarity'];
        $current = $this->contributions($verdict);
        $setAside = $this->setAsideIds($verdict);
        $best = null;
        foreach ($this->signalEntries($profile) as $entry) {
            $signal = ValueSignalLoader::get($entry['id']);
            if ($signal === null || empty($signal->unit)
                || !isset($signal->unit['points'])
                || !isset($signal->unit['cap'])
            ) {
                continue;
            }
            /*
             * A signal the engine could not run cannot be a lever. On
             * an over-correlating value the sightings signals are not
             * evaluated at all, so offering *or one sighting from
             * anyone* would name an act that moves nothing. The reason
             * is on the page one card away, in *Not counted*; this is
             * the half that stops the two cards contradicting each
             * other.
             */
            if (isset($setAside[$entry['id']])) {
                continue;
            }
            /*
             * And a lean signal cannot close a *signal strength* gap, since
             * the two are separate sums: a false-positive sighting
             * moves what the record says the value is, not how much
             * record there is.
             */
            if (isset($signal->axis)
                && $signal->axis === ValueVerdictTool::AXIS_LEAN
            ) {
                continue;
            }
            $units = $this->unitsToClose(
                $signal,
                $entry,
                isset($current[$entry['id']])
                    ? $current[$entry['id']]
                    : 0,
                $polarity,
                $gap
            );
            if ($units === null) {
                continue;
            }
            if ($best === null || $units < $best['units']) {
                $best = array(
                    'units' => $units,
                    'unit' => $signal->unit,
                );
            }
        }
        if ($best === null) {
            return null;
        }
        return $best['units'] === 1
            ? $best['unit']['one']
            : sprintf($best['unit']['many'], $best['units']);
    }

    /**
     * How many units of one signal close a points gap, or null when
     * that signal cannot close it on its own.
     *
     * Counted up rather than divided, because two of the shapes
     * involved are not a straight division. A signal currently firing
     * on *absence* holds a penalty that the first unit removes as well
     * as adding its own points, so the first unit is worth more than
     * the rest. And every one of these signals is capped, so past some
     * number of units the answer stops improving — which is exactly
     * when this signal is the wrong one to name.
     *
     * @param object $signal
     * @param array $entry
     * @param int $held The signal's anchored contribution today
     * @param int $polarity
     * @param int $gap
     * @return int|null
     */
    private function unitsToClose($signal, array $entry, $held,
        $polarity, $gap
    ) {
        $unit = $signal->unit;
        $per = (int)$this->pointsFrom($signal, $entry, $unit['points'])
            * $polarity;
        $cap = (int)$this->pointsFrom($signal, $entry, $unit['cap'])
            * $polarity;
        if ($per <= 0 || $cap <= 0 || $cap - $held < $gap) {
            return null;
        }
        $replaces = $this->firesOnAbsence($signal, $entry, $held,
            $polarity);
        for ($units = 1; $units <= self::MAX_UNITS; $units++) {
            $after = $replaces
                ? min($units * $per, $cap)
                : min($held + $units * $per, $cap);
            if ($after - $held >= $gap) {
                return $units;
            }
        }
        return null;
    }

    /**
     * Whether a signal's current row is its absence penalty rather than
     * a count of anything — in which case the first unit supplied
     * replaces the row instead of adding to it.
     *
     * @param object $signal
     * @param array $entry
     * @param int $held The row's anchored contribution
     * @param int $polarity
     * @return bool
     */
    private function firesOnAbsence($signal, array $entry, $held,
        $polarity
    ) {
        if ($signal->absence_key === null) {
            return false;
        }
        $points = (int)$this->pointsFrom($signal, $entry,
            $signal->absence_key) * $polarity;
        return $points < 0 && $held === $points;
    }

    /**
     * One points value as the profile and the signal's schema between
     * them define it.
     *
     * @param object $signal
     * @param array $entry
     * @param string $key
     * @return int|float
     */
    private function pointsFrom($signal, array $entry, $key)
    {
        if (isset($entry['points'][$key])
            && is_numeric($entry['points'][$key])
        ) {
            return $entry['points'][$key];
        }
        $schema = $signal->points_schema;
        return isset($schema[$key]['default'])
            ? $schema[$key]['default']
            : 0;
    }

    /**
     * The anchored contribution of each signal that fired, by id.
     *
     * @param array $verdict
     * @return array id => int
     */
    private function contributions(array $verdict)
    {
        $held = array();
        foreach ($verdict['ledger'] as $group) {
            foreach ($group['signals'] as $row) {
                if (isset($row['unit']) && $row['unit'] === false) {
                    continue;
                }
                $held[$row['id']] = (int)$row['contribution'];
            }
        }
        return $held;
    }

    /**
     * The rows carrying the band, heaviest first.
     *
     * @param array $verdict
     * @return array
     */
    private function supportingRows(array $verdict)
    {
        $rows = array();
        foreach ($verdict['ledger'] as $group) {
            foreach ($group['signals'] as $row) {
                if ((int)$row['contribution'] > 0) {
                    $rows[] = $row;
                }
            }
        }
        usort($rows, function ($a, $b) {
            return $b['contribution'] - $a['contribution'];
        });
        return $rows;
    }

    /**
     * Whether the lean is contested because the ledger came out against
     * the record's own assertion, rather than because a rule or a
     * stance split said so.
     *
     * The two states are told apart by the *derived* lean and nothing
     * else. A rule or a stance split reaches contested before any
     * scoring, so both leans read contested; only the ledger's own
     * dispute can leave a categorical lean on the record and a
     * contested one on the page.
     *
     * It deliberately does not look at the sign of the signal strength. A
     * benign lean disputed by its ledger re-anchors *positive* — the
     * threat-signed sum was what disputed it — so a negative-signal-strength
     * test finds only half the cases, and the half it misses is the one
     * where the stance probe then reports a change into the state the
     * value is already in.
     *
     * @param array $verdict
     * @return bool
     */
    private function disputedByLedger(array $verdict)
    {
        return $verdict['lean'] === 'contested'
            && $verdict['derived_lean'] !== 'contested';
    }

    /**
     * @param string $stance
     * @param int $orgs
     * @return string
     */
    private function stancePhrase($stance, $orgs)
    {
        if ($stance === 'threat') {
            return $orgs === 1
                ? __('One more organisation flagging it for detection')
                : sprintf(
                    __('%d more organisations flagging it for'
                        . ' detection'),
                    $orgs
                );
        }
        return $orgs === 1
            ? __('One organisation filing it as a false positive')
            : sprintf(
                __('%d organisations filing it as a false positive'),
                $orgs
            );
    }

    /**
     * @param string $lean
     * @return string
     */
    private function leanPhrase($lean)
    {
        switch ($lean) {
            case 'threat':
                return __('it would read as a threat.');
            case 'benign':
                return __('it would read as benign.');
            case 'contested':
                return __('it would become contested.');
            case 'unflagged':
                return __('it would read as recorded for context only.');
        }
        return __('it would no longer lean either way.');
    }

    /**
     * @param int $points
     * @return string
     */
    private function signed($points)
    {
        return ($points > 0 ? '+' : '') . (int)$points;
    }

    /**
     * @param array|null $profile
     * @param string $band
     * @return int
     */
    private function bandFloor($profile, $band)
    {
        $bands = $this->thresholds($profile, 'signal_strength_bands', array());
        if (isset($bands[$band]) && is_numeric($bands[$band])) {
            return (int)$bands[$band];
        }
        return $band === 'high' ? 60 : 30;
    }

    /**
     * The band the thin-record clamp caps at, or null when the profile
     * carries no clamp.
     *
     * @param array|null $profile
     * @return string|null
     */
    private function clamp($profile)
    {
        $clamp = $this->thresholds($profile, 'thin_record_clamp',
            array());
        return isset($clamp['max_band']) && is_string($clamp['max_band'])
            ? $clamp['max_band']
            : null;
    }

    /**
     * @param array|null $profile
     * @param string $key
     * @param mixed $fallback
     * @return mixed
     */
    private function thresholds($profile, $key, $fallback)
    {
        $section = $this->section($profile, 'thresholds');
        return isset($section[$key]) ? $section[$key] : $fallback;
    }

    /**
     * @param array|null $profile
     * @return array
     */
    private function signalEntries($profile)
    {
        $entries = array();
        foreach ($this->section($profile, 'signals') as $entry) {
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
     * @param array|null $profile
     * @param string $name
     * @return array
     */
    private function section($profile, $name)
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
}
