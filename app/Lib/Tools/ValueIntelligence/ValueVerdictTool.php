<?php

App::uses('ValueSignalLoader', 'Tools/ValueIntelligence');
App::uses('ValueStatsTool', 'Tools/ValueIntelligence');
/*
 * Loaded here rather than by the three signals that use it: a signal
 * file is discovered from the filesystem and required by the loader,
 * which is not a place `App::uses` has run — and the engine is the one
 * thing guaranteed to be in memory before any signal evaluates.
 */
App::uses('ValueTrustTool', 'Tools/ValueIntelligence');
App::uses('ValueLeanTool', 'Tools/ValueIntelligence');
App::uses('ValueChangersTool', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

/**
 * The accumulator: a profile plus a value's facts, in; a ledger that
 * sums to a number, out.
 *
 * The page displays a verdict; it does not compute one — this does.
 * What it computes is the assessment's **signal strength** axis: lean is
 * derived categorically by `ValueLeanTool` and relevance is its own
 * axis, so this file is the ledger and the number, not the whole
 * judgement.
 *
 * ## The mechanism, and why it is one loop
 *
 * ```
 * for each enabled signal in profile.signals:
 *     evaluate it against the context           → an outcome
 *     fired:          points = f(outcome, points)   emit a ledger row
 *     silent:         no row and no note
 *     could not run:  a not_counted entry
 *
 * polarity            = +1 (threat lean) | −1 (benign lean)
 * lean row            = points × polarity    reads the value
 * signal-strength row = points               weighs the record
 * signal strength     = Σ signal-strength rows
 * lean_weight         = Σ lean rows
 * direction of a row  = sign(row)
 * ```
 *
 * **Two sums, because there are two questions** — *what the record
 * says* and *how much record there is* are different axes, and
 * anchoring every row to the lean would fuse them again. A signal
 * declares which axis it is on and the polarity reaches only the
 * lean's; a signal with poles on both declares per row. Three
 * shipped signals read the value — the warninglist's hits,
 * false-positive sightings and enrichment verdicts; the `to_ids`
 * stance reads it too, but that one is not a ledger row at all.
 *
 * **The sum is the signal strength by construction rather than by
 * convention.** There is no second code path
 * that could disagree with the ledger — no normalisation, no
 * calibration, no post-processing — which is what makes a profile diff
 * renderable and what lets the page claim the explanation *is* the
 * score. Every guard in this file that looks defensive is protecting
 * that one property: a signal returning a float, a string or an array
 * would break it silently, so a malformed row is treated as *could not
 * run* and named on the page instead.
 *
 * **`direction` is derived, never stored.** It is the sign of the
 * anchored row, so the same declaration renders upward on a threat lean
 * and downward on a benign one. A profile storing a direction would
 * have to keep it in step with the sign of its own points.
 *
 * ## What it does not do
 *
 * No view dependency of any kind, and that is a requirement rather
 * than a preference: a REST path over a batch of values calls this
 * too, so a signal reaching for `$this->Html` or a helper would break
 * it.
 *
 * It also stores nothing. The assessment is computed at render time,
 * which is what makes per-viewer weighting cheap and gives a
 * user-defined signal no sync blast radius.
 *
 * ## The lean-disputed check, which lives here rather than with the lean
 *
 * The lean's categorical rules are `ValueLeanTool`'s and run before any
 * scoring. One check cannot: **a lean whose anchored *lean* rows sum
 * below zero becomes contested**, because that is the record's own
 * reading of the value disputing the assertion the record itself makes.
 * Rows from a signal whose evidence is already a voice in the stance
 * count (`ValueSignalBase::$voice`) are left out of that sum.
 * That can only be known after the sum, so it is applied here — the
 * lean rows go back to threat-signed, the lean becomes contested, and
 * `decided_by` becomes `lean_disputed` so the band explaining the
 * reading stops naming the lean this check discarded.
 *
 * **It weighs the lean rows and not the whole ledger**, because
 * against the whole ledger a thin record would trip it — the absence
 * rows of a single-source value with no galaxy, no first-seen, no
 * sighting, nothing recent and no feed can outweigh its one report —
 * and ordinary thin records would read as contradictions. A thin record is a lean
 * with a low signal-strength band and a full ledger.
 *
 * ## What is still an input
 *
 * **The exclusions.** Only `evidence.window` is read here, because the
 * evidence budget is what bounds a context this file has to score; the
 * rest of the section reaches signals as `$context['excluded']`.
 */
class ValueVerdictTool
{
    /** The ledger's group order, and the composition card's. */
    const GROUP_ORDER = array(
        'Reporting',
        'Sightings',
        'Attribution',
        'Lifecycle',
    );

    /**
     * The signal-strength bands, weakest first, so one can be capped to
     * another.
     */
    const BANDS = array('none', 'low', 'medium', 'high');

    /**
     * `ValueSignalBase::AXIS_LEAN` and `AXIS_SIGNAL_STRENGTH`, mirrored.
     *
     * Mirrored rather than referenced because the signal base is
     * `include_once`d by the loader at first scan, and the path this
     * engine takes for a value with nothing to assess never scans —
     * so naming the class there would make an empty record a fatal
     * rather than an empty ledger. The two pairs must stay equal.
     */
    const AXIS_LEAN = 'lean';
    const AXIS_SIGNAL_STRENGTH = 'signal_strength';

    /** Lean → the ledger's polarity. */
    const POLARITY = array(
        'threat' => 1,
        'benign' => -1,
        'contested' => 1,
        'unflagged' => 1,
        'none' => 1,
    );

    /**
     * The model that owns the data, injected the way `Event.php` does
     * it with `new TrendingTool($this)`. Only `verdictFor()` uses it;
     * `assess()` is pure and needs nothing.
     *
     * @var Model|null
     */
    private $model;

    /**
     * @param Model|null $model Something answering
     *                          `verdictContextFor()` and carrying an
     *                          `AnalystProfile` — `ValueIntelligence`, in
     *                          practice
     */
    public function __construct($model = null)
    {
        $this->model = $model;
    }

    /**
     * The whole computation for one value: resolve the profile, build
     * the context, score it.
     *
     * **This is the one method that takes `$user`**, though no other
     * `Value*` tool does. The exception is deliberate: every count an
     * assessment reads is already the viewer's, and a tool computing an
     * assessment from data it could not scope would be computing
     * somebody else's. What it does not do is fetch — the context comes
     * from the injected model, which is where the queries and the ACL
     * live, and a batch builder can swap in behind the same seam.
     *
     * @param array $user
     * @param string $value
     * @param array $options `lean`, `profile`, `context`, plus
     *                       whatever the context builder takes
     * @return array
     */
    public function verdictFor(array $user, $value,
        array $options = array()
    ) {
        $profile = isset($options['profile'])
            ? $options['profile']
            : $this->profileFor($user);
        $context = isset($options['context'])
            ? $options['context']
            : $this->contextFor($user, $value, $profile, $options);
        return $this->assess($context, $profile, $options);
    }

    /**
     * The accumulator. No database, no models, no `$user` — hand it a
     * context and a profile and it returns the same array every time,
     * which is what lets the page, the simulator and a batch worker
     * agree.
     *
     * @param array $context From the context builder; the contract is
     *                       documented on `ValueSignalBase`
     * @param array|null $profile An `AnalystProfile` row, unwrapped, or
     *                            null when scoring is switched off
     * @param array $options `lean` forces one instead of deriving it,
     *                       which is how a ledger is scored against a
     *                       stated lean rather than a counted one
     * @return array
     */
    public function assess(array $context, $profile,
        array $options = array()
    ) {
        $derived = $this->derive($context, $profile, $options);
        $lean = $derived['lean'];
        $polarity = isset(self::POLARITY[$lean])
            ? self::POLARITY[$lean]
            : 1;
        /*
         * A `none` lean has no ledger. **And neither has a value with
         * no occurrence this viewer can see**, whatever lean the caller
         * forced — the lean's own first rule, stated here as a fact
         * about the context, because the absence keys would otherwise
         * fire on emptiness: no warninglist hit, no galaxy, nobody
         * sighted it are all true of a value that does not exist for
         * this reader, and scoring them is the engine reading
         * its own blindness as evidence.
         */
        $occurrences = isset($context['occurrences']['total'])
            ? (int)$context['occurrences']['total']
            : 0;
        /*
         * `no_voice` is the exception: the record is there and every
         * voice in it abstained. What it asserts is nothing, but how
         * thick it is still holds — grading a reporter `G` zeroes its
         * say, not the events it published.
         */
        $voiceless = ($derived['decided_by'] ?? null) === 'no_voice';
        if (($lean === 'none' && !$voiceless) || $occurrences === 0) {
            return $this->nothingToAssess($derived, $polarity,
                $context, $profile);
        }
        /*
         * The lean the rows are anchored to, for the one signal that
         * pays for agreeing with it: an outside verdict confirming
         * what the reporters assert is corroboration.
         */
        $context['lean'] = $lean;
        $entries = $this->signalEntries($profile);

        $rows = array();
        $notCounted = array();
        $counts = array(
            'configured' => count($entries),
            'evaluated' => 0,
            'fired' => 0,
            'supporting' => 0,
            'silent' => 0,
            'not_counted' => 0,
        );

        foreach ($entries as $entry) {
            $id = isset($entry['id']) ? $entry['id'] : null;
            if ($id === null || $id === '') {
                continue;
            }
            if (array_key_exists('enabled', $entry)
                && empty($entry['enabled'])
            ) {
                // Not evaluated, and not recorded either: a disabled
                // signal emits nothing at all.
                $counts['configured']--;
                continue;
            }
            $outcome = $this->runSignal($id, $entry, $context);
            if ($outcome['state'] === 'not_counted') {
                $notCounted[] = $outcome['entry'];
                $counts['not_counted']++;
                continue;
            }
            $counts['evaluated']++;
            if ($outcome['state'] === 'silent') {
                $counts['silent']++;
                continue;
            }
            /*
             * **Rows, plural.** Most signals return one and are
             * normalised into a list of one; a signal whose evidence
             * is a set of
             * independent sources returns several, because *GreyNoise
             * said mass scanner, asked 3 h ago, −12* is a row a reader
             * can open the run behind, and one row summing three
             * vendors is not.
             *
             * The counts stay per **signal** — one signal that fired,
             * however many rows it put in the ledger — because that is
             * what `configured`, `evaluated` and `silent` are counting
             * beside it.
             */
            $added = 0;
            foreach ($outcome['rows'] as $row) {
                $anchored = $this->anchor(
                    $row,
                    $entry,
                    $outcome['signal'],
                    $polarity
                );
                if ($anchored['axis'] === self::AXIS_SIGNAL_STRENGTH) {
                    $added += $anchored['contribution'];
                }
                $rows[] = $anchored;
            }
            if ($added > 0) {
                $counts['supporting']++;
            }
            /*
             * And a signal may set some of its own evidence aside. The
             * enrichment group is the case: a module the profile has
             * not graded multiplies by zero, and a row worth nothing
             * belongs in `not_counted` with the reason rather than in
             * the ledger at `+0`, which reads as *counted, and worth
             * nothing*.
             */
            foreach ($outcome['not_counted'] as $note) {
                $notCounted[] = $note;
            }
            $counts['fired']++;
        }

        foreach ($this->setAside($context) as $note) {
            $notCounted[] = $note;
        }

        /*
         * Two sums, because there are two questions. The signal-strength rows
         * sum to the signal strength, exactly — the invariant, narrowed to the
         * axis it is about. The lean rows sum to `lean_weight`, which
         * is what the record's own evidence says the value *is*, and
         * they stay out of the signal strength: a warninglist hit says nothing
         * about how well documented a record is.
         *
         * One sum would get a widely reported value wrong: eight
         * organisations, 53 sightings, 20 events, a listing and a feed
         * would band `low` once `−58` of lean evidence was subtracted
         * from `+57` of record. It is a well-documented contested
         * value and should say so.
         */
        $signalStrength = $this->sum($this->onAxis($rows,
            self::AXIS_SIGNAL_STRENGTH));
        $leanWeight = $this->sum($this->onAxis($rows,
            self::AXIS_LEAN));

        /*
         * The lean-disputed check. **Lean rows that are not voices**
         * summing below zero against the lean they were anchored to
         * are a record disputing its own assertion, and the honest
         * state for that is contested. A false positive or an outside
         * verdict has already been weighed against the reporters in
         * the stance count; letting its points decide here as
         * well is how one false positive outvoted ten organisations.
         * On the shipped catalogue what is left is the warninglist.
         *
         * Weighing the whole ledger would let a thin record trip it:
         * on an ordinary single-source value the absence rows — no
         * galaxy, no first-seen, no sighting, nothing recent, no feed
         * — can outweigh the record it has. That is not a
         * contradiction; it should read as *a lean with low signal strength
         * and a full ledger*.
         *
         * **And it defers to a lean that is already contested.** An
         * escalation rule reaching `contested` before any scoring has
         * already named the contradiction, in prose written for that
         * value's shape; this check firing over the top of it would
         * replace `decided_by` and lose the rule's own sentence.
         *
         * **And `unflagged` has no assertion to dispute**: a
         * record that only holds the value as context is not
         * contradicting itself when a list calls it infrastructure.
         *
         * It cannot run twice: there is one branch, and it sets the
         * lean it would have been re-entered for.
         */
        $disputeWeight = $this->sum(array_filter(
            $this->onAxis($rows, self::AXIS_LEAN),
            function ($row) {
                return empty($row['voice']);
            }
        ));
        if ($disputeWeight < 0 && $lean !== 'contested'
            && $lean !== 'unflagged'
        ) {
            $rows = $this->reanchor($rows, $polarity);
            $leanWeight = $this->sum($this->onAxis($rows,
                self::AXIS_LEAN));
            $lean = 'contested';
            /*
             * The exit gets its own name, because the band under *How
             * this reading was decided* reads `decided_by`, and leaving
             * it naming the lean just discarded would draw a
             * **Contested** badge over the sentence *2 of 2
             * organisations report this as harmless*.
             */
            $derived['decided_by'] = 'lean_disputed';
            $polarity = 1;
        }
        $ledger = $this->group($this->onAxis($rows,
            self::AXIS_SIGNAL_STRENGTH));
        $context['outside_agreement'] = self::outsideAgreement(
            $derived['stances'],
            $lean
        );

        return $this->verdict(array(
            'lean' => $lean,
            'derived' => $derived,
            'polarity' => $polarity,
            'signal_strength' => $signalStrength,
            'lean_weight' => $leanWeight,
            'lean_ledger' => $this->onAxis($rows,
                self::AXIS_LEAN),
            'band' => self::signalStrengthBand(
                $signalStrength,
                $counts,
                $profile,
                $context
            ),
            'ledger' => $ledger,
            'tug' => $this->tug($rows, $polarity),
            'not_counted' => $notCounted,
            'counts' => $counts,
            'context' => $context,
            'profile' => $profile,
        ));
    }

    /**
     * The lean this assessment is anchored to, counted or forced.
     *
     * A forced lean skips the rules entirely — it is how a ledger is
     * scored against a stated lean rather than a counted one, which is
     * what a profile simulator and a re-anchoring regression both need.
     * The stances still come back, because they cost nothing and the
     * falsifiability line needs them either way.
     *
     * @param array $context
     * @param array|null $profile
     * @param array $options
     * @return array
     */
    private function derive(array $context, $profile, array $options)
    {
        $lean = new ValueLeanTool();
        if (!isset($options['lean'])) {
            return $lean->leanFor($context, $profile);
        }
        return array(
            'lean' => $options['lean'],
            'rule' => null,
            'stances' => $lean->stancesFor($context, $profile),
            'rule_errors' => array(),
            /*
             * No exit, because none was taken: a forced lean skips the
             * rules entirely. Stated rather than left absent — `verdict
             * ()` reads the key unconditionally, so leaving it out
             * would raise a notice for every forced lean.
             * `ValueLeanReasonTool` answers null here, which draws no
             * band, which is the right answer for a reading nobody
             * derived.
             */
            'decided_by' => null,
        );
    }

    /**
     * A value with nothing to assess: no lean to anchor to, or no
     * occurrence this viewer can see.
     *
     * The same array shape, so a caller never has to ask which kind of
     * assessment it is holding — and the profile is still named,
     * because the profile *was* in force; it simply had nothing to
     * weigh.
     *
     * @param array $derived
     * @param int $polarity
     * @param array $context
     * @param array|null $profile
     * @return array
     */
    private function nothingToAssess(array $derived, $polarity,
        array $context, $profile
    ) {
        return $this->verdict(array(
            'lean' => $derived['lean'],
            'derived' => $derived,
            'polarity' => $polarity,
            'signal_strength' => 0,
            'lean_weight' => 0,
            'lean_ledger' => array(),
            'band' => 'none',
            'ledger' => array(),
            'tug' => $this->tug(array(), $polarity),
            'not_counted' => array(),
            'counts' => array('configured' => 0, 'evaluated' => 0,
                'fired' => 0, 'supporting' => 0, 'silent' => 0,
                'not_counted' => 0),
            'context' => $context,
            'profile' => $profile,
        ));
    }

    /**
     * The weight of the graded outside verdicts agreeing with the
     * lean, each at most one source — what the clamp counts beside
     * independent sightings. A contested lean has no side to
     * agree with.
     *
     * @param array $stances
     * @param string $lean
     * @return float
     */
    private static function outsideAgreement(array $stances, $lean)
    {
        if ($lean !== 'threat' && $lean !== 'benign') {
            return 0.0;
        }
        $total = 0.0;
        foreach ($stances['disputes'] ?? array() as $voice) {
            if (($voice['kind'] ?? null) === 'enrichment'
                && ($voice['side'] ?? null) === $lean
            ) {
                $total += min(1.0, (float)$voice['weight']);
            }
        }
        return $total;
    }

    /**
     * The exact-sum invariant, in the one place that computes it.
     *
     * @param array $rows
     * @return int
     */
    private function sum(array $rows)
    {
        $signalStrength = 0;
        foreach ($rows as $row) {
            $signalStrength += $row['contribution'];
        }
        return $signalStrength;
    }

    /**
     * Put a ledger back to threat-signed, which is how a contested
     * ledger renders: no side to support, so no polarity to apply.
     *
     * @param array $rows
     * @param int $polarity The polarity they were anchored with
     * @return array
     */
    private function reanchor(array $rows, $polarity)
    {
        foreach ($rows as $index => $row) {
            $axis = isset($row['axis'])
                ? $row['axis']
                : self::AXIS_SIGNAL_STRENGTH;
            /*
             * Signal-strength rows were never anchored, so there is nothing to
             * put back. Running the multiply over them anyway would
             * silently invert the record's weight under a lean that
             * no longer has one.
             */
            if ($axis !== self::AXIS_LEAN) {
                continue;
            }
            $contribution = (int)$row['contribution'] * $polarity;
            $rows[$index]['contribution'] = $contribution;
            $rows[$index]['direction'] = $contribution < 0
                ? 'down'
                : 'up';
        }
        return $rows;
    }

    /**
     * The two one-sided sums a contested layout puts against each
     * other: what supports the record's assertion, and what disputes
     * it.
     *
     * Both come out of the same lean rows the other leans render —
     * there is no third bucket and no separate computation, which is
     * what lets a reader add the lean ledger up by hand and arrive at
     * the bar. It is not the signal strength's rows; see **The lean rows, and
     * only those** below.
     *
     * **Two keys.** There is no third *unresolved* wedge, because
     * nothing could derive one; a hard zero there would count
     * something different from the foot printed directly under it,
     * under the same word.
     *
     * **The lean rows, and only those.** A tug drawn over the whole
     * ledger would put *no galaxy on any occurrence* and *the record
     * never says when it was seen* on the benign foot of a bar the
     * reader is invited to read as two readings of the value.
     * Absences are not a case. What is
     * left here is the two sides of the evidence that actually reads
     * the value, which on the shipped catalogue is one-sided by
     * construction — the warninglist and false-positive rows both
     * argue benign, and the threat side of the argument is the
     * organisation stance count, which is not a ledger row at all and
     * is drawn as a count in the lean band.
     *
     * @param array $rows
     * @param int $polarity
     * @return array
     */
    private function tug(array $rows, $polarity)
    {
        $support = 0;
        $dispute = 0;
        foreach ($this->onAxis($rows, self::AXIS_LEAN)
            as $row
        ) {
            $threatSigned = (int)$row['contribution'] * $polarity;
            if ($threatSigned >= 0) {
                $support += $threatSigned;
            } else {
                $dispute -= $threatSigned;
            }
        }
        return array(
            'support' => $support,
            'dispute' => $dispute,
        );
    }

    /**
     * The return shape, in one place so the two paths into it cannot
     * drift apart.
     *
     * @param array $parts
     * @return array
     */
    private function verdict(array $parts)
    {
        $lean = $parts['lean'];
        $signalStrength = $parts['signal_strength'];
        $ledger = $parts['ledger'];
        $context = $parts['context'];
        $profile = $parts['profile'];
        $derived = $parts['derived'];

        $verdict = array(
            'lean' => $lean,
            'derived_lean' => $derived['lean'],
            'rule' => $derived['rule'],
            'rule_errors' => $derived['rule_errors'],
            'stances' => $derived['stances'],
            /*
             * Which of the seven exits produced the lean. Carried so a
             * reader of this array never has to re-derive the
             * derivation's own precedence — `ValueLeanTool::answer()`
             * says what goes wrong when it does.
             */
            'decided_by' => $derived['decided_by'],
            'polarity' => $parts['polarity'],
            'signal_strength' => $signalStrength,
            /*
             * The lean's own arithmetic, beside the signal strength's rather
             * than inside it. `lean_ledger` is the rows and
             * `lean_weight` their sum, so the band that explains the
             * reading can show its working the way the ledger shows
             * the signal strength's — and so nothing has to re-derive from a
             * sign which rows those were.
             */
            'lean_weight' => isset($parts['lean_weight'])
                ? (int)$parts['lean_weight']
                : 0,
            'lean_ledger' => isset($parts['lean_ledger'])
                ? $parts['lean_ledger']
                : array(),
            'band' => $parts['band'],
            /*
             * Assembled here rather than beside either `band`, because
             * there are two of those — the scored path and the
             * no-signal one — and a key computed in one of them is a
             * key a template reads as missing on the other.
             */
            'band_reason' => self::bandReason(
                $parts['signal_strength'],
                $parts['counts'],
                $parts['profile'],
                $parts['context']
            ),
            /*
             * The second axis, assembled beside the signal strength and not out
             * of it. It reads the same context and the same profile,
             * emits no ledger row, and is computed here rather than by
             * the caller so that one `assess()` returns the whole
             * assessment — the page, the simulator and a batch worker
             * cannot then disagree about a value's relevance while
             * agreeing about its signal strength.
             *
             * **Nothing below reads it**, which keeps the axes apart
             * mechanically: the ledger, the band, the tug and the
             * composition are all computed already, so an axis added
             * here cannot alter any of them — the lean and the signal strength
             * are byte-identical with relevance at `current` and at
             * `expired`.
             */
            'relevance' => ValueRelevanceTool::relevanceFor(
                $context,
                $profile
            ),
            'ledger' => $ledger,
            'tug' => $parts['tug'],
            'composition' => ValueStatsTool::verdictComposition($ledger),
            'not_counted' => $parts['not_counted'],
            'signals' => $parts['counts'],
            // Graded outside verdicts agreeing with the lean.
            'outside_agreement' => (float)($context['outside_agreement']
                ?? 0.0),
            'profile' => $this->profileName($profile),
            'profile_id' => $profile === null
                ? null
                : (isset($profile['id']) ? (int)$profile['id'] : null),
            'profile_revision' => $profile === null
                ? null
                : (isset($profile['revision'])
                    ? (int)$profile['revision']
                    : null),
            'computed_at' => isset($context['now'])
                ? (int)$context['now']
                : time(),
            'as_of' => isset($context['as_of'])
                ? $context['as_of']
                : date('Y-m-d'),
        );

        /*
         * Last, because a falsifiability line is derived *from* the
         * assessment — the lean probe re-runs the rules and the signal strength
         * probe re-runs the banding, and both need the finished answer
         * to say what would move it.
         */
        $changers = new ValueChangersTool();
        $verdict['changers'] = $changers->changersFor(
            $verdict,
            $context,
            $profile
        );

        return $verdict;
    }

    /**
     * One signal: resolve it, decide whether it may run, run it, and
     * check what it returned.
     *
     * Every failure path lands in the same place — `not_counted`, with
     * the id named and a reason — because an unavailable signal belongs
     * *on the page*: a signal-strength number computed from eight of nine
     * configured signals and presented as if nine ran is a quiet lie.
     *
     * @param string $id
     * @param array $entry The profile's entry for it
     * @param array $context
     * @return array `state` of fired|silent|not_counted, plus `row`
     *               and `signal`, or `entry`
     */
    private function runSignal($id, array $entry, array $context)
    {
        $signal = ValueSignalLoader::get($id);
        if ($signal === null) {
            return $this->cannotRun(
                $id,
                $this->missingReason($id),
                'unavailable'
            );
        }
        $blocked = $this->budgetBlocks($signal, $context);
        if ($blocked !== null) {
            return $this->cannotRun($id, $blocked, 'nodata', $signal);
        }
        $unreadable = $this->unreadable($signal, $context);
        if ($unreadable !== null) {
            return $this->cannotRun($id, $unreadable, 'nodata',
                $signal);
        }
        try {
            $row = $signal->evaluate($context, $entry);
        } catch (Throwable $e) {
            /*
             * A dropped file's `evaluate()` throwing must not take the
             * page down, and the exception text is what an admin
             * needs to fix it.
             */
            return $this->cannotRun(
                $id,
                sprintf(
                    __('The signal failed: %s'),
                    $e->getMessage()
                ),
                'broken',
                $signal
            );
        }
        if ($row === null) {
            return array('state' => 'silent');
        }
        $returned = $this->normaliseReturn($row);
        if (is_string($returned)) {
            return $this->cannotRun($id, $returned, 'broken', $signal);
        }
        foreach ($returned['rows'] as $one) {
            $invalid = $this->rowFault($one);
            if ($invalid !== null) {
                return $this->cannotRun($id, $invalid, 'broken',
                    $signal);
            }
        }
        if (empty($returned['rows'])
            && empty($returned['not_counted'])
        ) {
            return array('state' => 'silent');
        }
        return array(
            'state' => 'fired',
            'rows' => $returned['rows'],
            'not_counted' => $returned['not_counted'],
            'signal' => $signal,
        );
    }

    /**
     * What a signal returned, as rows and set-aside notes.
     *
     * Two shapes, and the older one is the one nearly every signal
     * uses: **a ledger row** — an array carrying `contribution` — or
     * **an envelope** carrying `rows` and, optionally, `not_counted`.
     *
     * Told apart by `contribution` rather than by whether the array
     * looks like a list, because that test is the kind that works
     * until a signal returns exactly one row in a list and then
     * silently scores it as a malformed row. A row always has the key;
     * an envelope never does.
     *
     * @param array $returned
     * @return array|string The two lists, or why it could not be read
     */
    private function normaliseReturn(array $returned)
    {
        if (array_key_exists('contribution', $returned)) {
            return array(
                'rows' => array($returned),
                'not_counted' => array(),
            );
        }
        if (!array_key_exists('rows', $returned)
            && !array_key_exists('not_counted', $returned)
        ) {
            return __('The signal returned something that is not a'
                . ' ledger row.');
        }
        $rows = isset($returned['rows']) && is_array($returned['rows'])
            ? array_values($returned['rows'])
            : array();
        $notes = isset($returned['not_counted'])
            && is_array($returned['not_counted'])
            ? array_values($returned['not_counted'])
            : array();
        return array('rows' => $rows, 'not_counted' => $notes);
    }

    /**
     * Why a returned row cannot be trusted, or null when it can.
     *
     * `contribution` has to be an integer, and this is the check that
     * protects the exact-sum invariant from third-party code: a float
     * would make the ledger sum to something the printed rows do not,
     * and it would do it invisibly.
     *
     * @param mixed $row
     * @return string|null
     */
    private function rowFault($row)
    {
        if (!is_array($row)) {
            return __('The signal returned something that is not a'
                . ' ledger row.');
        }
        if (!array_key_exists('contribution', $row)) {
            return __('The row carries no contribution.');
        }
        if (!is_int($row['contribution'])) {
            return __('The contribution is not a whole number, so the'
                . ' ledger could not sum to the signal strength.');
        }
        if (empty($row['signal']) || !is_string($row['signal'])) {
            return __('The row states no signal.');
        }
        return null;
    }

    /**
     * Whether the evidence budget stops this signal running at all.
     *
     * The hot-value tier: a value MISP itself flagged as
     * over-correlating is one a time window cannot bound, because a
     * live campaign puts everything inside 90 days. Row-hungry signals
     * bow out and say so; the aggregate-class ones still fire, and the
     * signal strength is computed from what could be read.
     *
     * @param object $signal
     * @param array $context
     * @return string|null
     */
    private function budgetBlocks($signal, array $context)
    {
        if (empty($context['budget']['hot'])) {
            return null;
        }
        if ($signal->evidence_class !== ValueSignalBase::EVIDENCE_ROW) {
            return null;
        }
        return __('Not evaluated: this value is too common for MISP'
            . ' to correlate.');
    }

    /**
     * Whether a fact this signal declared it reads could not be read.
     *
     * `$context['missing']` is how the context builder reports a
     * source it could not reach — a feed cache that has never been
     * populated, a sighting policy that hid everything. A signal
     * scoring that as *absent* would turn a gap into evidence.
     *
     * @param object $signal
     * @param array $context
     * @return string|null
     */
    private function unreadable($signal, array $context)
    {
        if (empty($context['missing'])) {
            return null;
        }
        foreach ($signal->reads as $key) {
            if (isset($context['missing'][$key])) {
                return $context['missing'][$key];
            }
        }
        return null;
    }

    /**
     * The two missing cases differ only in the reason string: an id
     * this instance does not have at all, against one it has but could
     * not load.
     *
     * @param string $id
     * @return string
     */
    private function missingReason($id)
    {
        foreach (ValueSignalLoader::errors() as $file => $reason) {
            if (strpos($reason, '`' . $id . '`') !== false) {
                return sprintf(
                    __('The implementation did not load (%1$s): %2$s'),
                    $file,
                    $reason
                );
            }
        }
        return __('This instance has no implementation for that'
            . ' signal, so the profile weighted something that could'
            . ' not run.');
    }

    /**
     * @param string $id
     * @param string $reason
     * @param string $kind `unavailable`, `nodata` or `broken`
     * @return array
     */
    private function cannotRun($id, $reason, $kind, $signal = null)
    {
        return array(
            'state' => 'not_counted',
            'entry' => array(
                /*
                 * The signal's own sentence, and the id only where
                 * there is no sentence to have — an unavailable signal
                 * is precisely the one nothing can describe. An id
                 * like `sightings.volume_recency` would otherwise sit
                 * directly above the entries this file builds with
                 * English titles. The id is still carried on the entry
                 * for whoever has to fix it.
                 */
                'title' => $signal !== null
                    && !empty($signal->description)
                        ? $signal->description
                        : $id,
                'note' => $reason,
                /*
                 * `reason` is the render-level grouping — what a reader
                 * can do about the entry — and `kind` with `source` are
                 * the diagnostic detail behind it. A signal that could
                 * not run is always `nodata` however it failed: the
                 * three ways it can fail matter to whoever fixes it,
                 * and to a reader they are one statement, *this was not
                 * counted and not by anybody's choice*.
                 */
                'reason' => 'nodata',
                'kind' => $kind,
                'source' => 'signal',
                'id' => $id,
            ),
        );
    }

    /**
     * The budget's own `not_counted` entries — the evidence window,
     * stated as the profile policy it is.
     *
     * @param array $context
     * @return array
     */
    private function setAside(array $context)
    {
        $notes = array();
        /*
         * The profile's own exclusions, computed where the filtering
         * happened. They lead the block because they are the analyst's
         * decisions rather than the engine's, and so the only rows a
         * reader can do anything about.
         */
        if (!empty($context['exclusions'])
            && is_array($context['exclusions'])
        ) {
            foreach ($context['exclusions'] as $note) {
                $notes[] = $note;
            }
        }
        $budget = isset($context['budget'])
            ? $context['budget']
            : array();
        if (!empty($budget['window_days'])) {
            $notes[] = array(
                'title' => __('Long history'),
                'note' => sprintf(
                    __('Scored from the last %d days of row evidence.'
                        . ' Counts and dates are whole-history.'),
                    (int)$budget['window_days']
                ),
                'reason' => 'policy',
                'kind' => 'policy',
                'source' => 'exclusion',
                'id' => 'evidence.window',
            );
        }
        if (!empty($budget['hot'])) {
            $notes[] = array(
                'title' => __('Over-correlating value'),
                'note' => __('This value is too common for MISP to'
                    . ' correlate, so the signals that read its'
                    . ' occurrences were skipped.'),
                'reason' => 'nodata',
                'kind' => 'nodata',
                'source' => 'budget',
                'id' => 'over_correlating_values',
            );
        }
        return $notes;
    }

    /**
     * Turn a fired row into a ledger row: the group comes from the
     * profile, the anchoring and the direction from the lean
     * — and the anchoring only where the row has a side to take.
     *
     * **The polarity reaches lean rows and nothing else.** A signal strength
     * row's declared points are already the right sign for the only
     * thing it can say: more corroboration, more publication, more
     * temporal precision is a better record, and it is a better record
     * whether the record concluded threat or benign. Multiplying those
     * by the lean's polarity would render *four independent
     * organisations reported it* as `−28` **against** a benign reading,
     * and make the emptiest record the best-scoring benign one.
     *
     * `direction` therefore means two different things and the row says
     * which: on a lean row it is supports/disputes the stated lean, on
     * a signal-strength row it is adds to/deducts from the weight of the
     * record. The ledger draws them apart rather than leaving a reader
     * to infer it from the sign.
     *
     * @param array $row What the implementation returned
     * @param array $entry The profile's entry
     * @param object $signal
     * @param int $polarity
     * @return array
     */
    private function anchor(array $row, array $entry, $signal, $polarity)
    {
        $axis = isset($row['axis'])
            ? $row['axis']
            : (isset($signal->axis)
                ? $signal->axis
                : self::AXIS_SIGNAL_STRENGTH);
        $contribution = (int)$row['contribution']
            * ($axis === self::AXIS_LEAN ? $polarity : 1);
        $anchored = array(
            'kind' => !empty($entry['group'])
                ? $entry['group']
                : $signal->group,
            'axis' => $axis,
            'direction' => $contribution < 0 ? 'down' : 'up',
            'contribution' => $contribution,
            'signal' => $row['signal'],
            'evidence' => isset($row['evidence'])
                ? $row['evidence']
                : '',
            'tab' => isset($row['tab']) ? $row['tab'] : $signal->tab,
            'as_of' => isset($row['as_of']) ? $row['as_of'] : '',
            'id' => $signal->id,
            // A row may keep itself out of the dispute check on its own.
            'voice' => array_key_exists('voice', $row)
                ? !empty($row['voice'])
                : !empty($signal->voice),
        );
        // A row outside the signal's declared `$unit` (an event row).
        if (isset($row['unit']) && $row['unit'] === false) {
            $anchored['unit'] = false;
        }
        return $anchored;
    }

    /**
     * The rows on one axis.
     *
     * @param array $rows
     * @param string $axis
     * @return array
     */
    private function onAxis(array $rows, $axis)
    {
        $out = array();
        foreach ($rows as $row) {
            $rowAxis = isset($row['axis'])
                ? $row['axis']
                : self::AXIS_SIGNAL_STRENGTH;
            if ($rowAxis === $axis) {
                $out[] = $row;
            }
        }
        return $out;
    }

    /**
     * Group the rows the way `value_verdict_ledger.ctp` renders them —
     * by kind, in a fixed order, with the group's note.
     *
     * Grouped by kind rather than sorted by weight for the reason the
     * template's own docblock gives: an analyst checking whether the
     * sightings were counted twice wants them next to each other.
     *
     * @param array $rows
     * @return array
     */
    private function group(array $rows)
    {
        $byKind = array();
        foreach ($rows as $row) {
            $byKind[$row['kind']][] = $row;
        }
        $ordered = array();
        $kinds = array_keys($byKind);
        $known = array_values(self::GROUP_ORDER);
        $custom = array_values(array_diff($kinds, $known));
        foreach (array_merge($known, $custom) as $kind) {
            if (empty($byKind[$kind])) {
                continue;
            }
            $ordered[] = array(
                'kind' => $kind,
                'note' => $this->groupNote($kind),
                'signals' => $byKind[$kind],
            );
        }
        return $ordered;
    }

    /**
     * The one-line note under a group heading. A custom group gets no
     * note rather than a guessed one.
     *
     * A switch rather than a map, so the strings are literals where
     * `__()` sees them — a translated string built from a variable is
     * one the extractor never finds.
     *
     * @param string $kind
     * @return string
     */
    private function groupNote($kind)
    {
        switch ($kind) {
            case 'Reporting':
                return __('who reported it, and how widely');
            case 'Sightings':
                return __('who has seen it, and how recently');
            case 'Attribution':
                return __('what it has been linked to');
            case 'Lifecycle':
                return __('whether it is still worth acting on');
        }
        return '';
    }

    /**
     * The four-segment gauge's band, and where it came from.
     *
     * Bands are calibration and the stakes are deliberately low: a
     * misplaced band miscolours a gauge, it does not change what the
     * record asserts. That is the whole reason the three axes were
     * split apart.
     *
     * `signal_strength_high_min_signals` is what stops one heavy row buying a
     * `high` band on its own: a value's signal strength is high when several
     * independent readings agree, not when one signal is generous. It
     * counts the signal-strength signals that added points: an absence row or
     * a lean row fires on nearly every value, so counting those would
     * leave the guard with nothing to hold.
     *
     * @param int $signalStrength
     * @param array $signals `fired`, and `supporting` — the signal strength
     *                       signals whose rows sum above zero
     * @param array|null $profile
     * @param array $context Needed for the thin-record clamp; an empty
     *                       array asks for the unclamped band, which
     *                       is how a caller finds out whether the
     *                       clamp is what is holding a band down
     * @return string `none`, `low`, `medium` or `high`
     */
    public static function signalStrengthBand($signalStrength, array $signals,
        $profile, array $context = array()
    ) {
        if ((int)($signals['fired'] ?? 0) === 0) {
            return 'none';
        }
        $thresholds = self::section($profile, 'thresholds');
        $bands = isset($thresholds['signal_strength_bands'])
            ? $thresholds['signal_strength_bands']
            : array();
        $high = isset($bands['high']) ? (int)$bands['high'] : 60;
        $medium = isset($bands['medium']) ? (int)$bands['medium'] : 30;
        $minSignals = isset($thresholds['signal_strength_high_min_signals'])
            ? (int)$thresholds['signal_strength_high_min_signals']
            : 4;
        if ($signalStrength >= $high
            && (int)($signals['supporting'] ?? 0) >= $minSignals
        ) {
            $band = 'high';
        } elseif ($signalStrength >= $medium) {
            $band = 'medium';
        } else {
            $band = 'low';
        }
        return self::clamped($band, $thresholds, $context);
    }

    /**
     * Which of the band's four ways out produced this band, and the
     * numbers it was decided against.
     *
     * `signalStrengthBand()` answers *what* and has three callers that only
     * want that; this answers *why* without changing its signature.
     * The ledger prints the arithmetic and the hero the band, and
     * between them sits the one thing neither says: the floor. Lean
     * names its supermajority and relevance names its TTL — the profile
     * setting that decided the state belongs on the page, and this is
     * signal strength's.
     *
     * **`clamped` is detected, not predicted.** The band is computed
     * twice, once with the context and once without, and a difference
     * is the clamp — the same trick `ValueChangersTool::clampPhrase()`
     * uses, and for the same reason: the clamp's conditions live in
     * the profile and re-reading them here would be a second
     * implementation of them.
     *
     * @param int $signalStrength
     * @param array $signals As `signalStrengthBand()` takes them
     * @param array|null $profile
     * @param array $context
     * @return array `reason` — `no_signal`, `clamped`, `min_signals`
     *               or `points` — and `floors`, the numbers in force
     */
    public static function bandReason($signalStrength, array $signals,
        $profile, array $context = array()
    ) {
        $thresholds = self::section($profile, 'thresholds');
        $bands = isset($thresholds['signal_strength_bands'])
            ? $thresholds['signal_strength_bands']
            : array();
        $clamp = isset($thresholds['thin_record_clamp'])
            && is_array($thresholds['thin_record_clamp'])
            ? $thresholds['thin_record_clamp']
            : array();
        $floors = array(
            'medium' => isset($bands['medium']) ? (int)$bands['medium'] : 30,
            'high' => isset($bands['high']) ? (int)$bands['high'] : 60,
            'min_signals' => isset(
                $thresholds['signal_strength_high_min_signals']
            )
                ? (int)$thresholds['signal_strength_high_min_signals']
                : 4,
            'clamp_band' => isset($clamp['max_band'])
                ? $clamp['max_band']
                : null,
            'clamp_voices' => isset($clamp['max_voices'])
                ? (float)$clamp['max_voices']
                : (isset($clamp['max_orgs'])
                    ? (float)$clamp['max_orgs']
                    : null),
            'clamp_sightings' => isset($clamp['max_sightings'])
                ? (int)$clamp['max_sightings']
                : null,
        );

        if ((int)($signals['fired'] ?? 0) === 0) {
            return array('reason' => 'no_signal', 'floors' => $floors);
        }
        $withContext = self::signalStrengthBand($signalStrength, $signals,
            $profile, $context);
        $unclamped = self::signalStrengthBand($signalStrength, $signals,
            $profile);
        if ($withContext !== $unclamped) {
            $floors['would_be'] = $unclamped;
            $ceiling = self::clampCeiling($thresholds, $context);
            $floors['clamp_grade'] = $ceiling === null
                ? null
                : $ceiling['grade'];
            return array('reason' => 'clamped', 'floors' => $floors);
        }
        if ($signalStrength >= $floors['high']
            && (int)($signals['supporting'] ?? 0) < $floors['min_signals']
        ) {
            return array(
                'reason' => 'min_signals',
                'floors' => $floors,
            );
        }
        return array('reason' => 'points', 'floors' => $floors);
    }

    /**
     * The thin-record clamp: a ceiling on the band for a record with
     * one source and nothing corroborating it.
     *
     * It exists because the weights alone cannot express it, which was
     * measured rather than assumed. A single organisation reporting the
     * same value every month for over a year, carried by a few feeds,
     * reaches the `medium` band under any weighting that still says
     * something useful about the values that *do* have corroboration —
     * the positives such a record can honestly attain simply sum past
     * the floor. That is not obviously the wrong answer, but it is not
     * what an analyst means by *how much can I trust this*, and the
     * place to say so is the band rather than the arithmetic: a clamp
     * leaves the ledger's own sum intact and visible, where a weighting
     * would have shrunk every signal to hide one shape.
     *
     * So it is stated as its own threshold, in the profile, with the
     * whole condition named — how many sources still count as one, how
     * many sightings still count as none, and what the ceiling is. An
     * analyst who disagrees edits three numbers; an analyst who wants
     * no clamp deletes the section.
     *
     * A caller passing no context gets the unclamped band, which is
     * how the falsifiability line finds out whether the clamp is what
     * is holding a record down.
     *
     * @param string $band
     * @param array $thresholds
     * @param array $context
     * @return string
     */
    private static function clamped($band, array $thresholds,
        array $context
    ) {
        if (empty($context)) {
            return $band;
        }
        $ceiling = self::clampCeiling($thresholds, $context);
        if ($ceiling === null) {
            return $band;
        }
        $limit = array_search($ceiling['band'], self::BANDS, true);
        $reached = array_search($band, self::BANDS, true);
        if ($limit === false || $reached === false
            || $reached <= $limit
        ) {
            return $band;
        }
        return $ceiling['band'];
    }

    /**
     * The ceiling the clamp puts on this record, or null when the
     * record is not thin.
     *
     * **Sources are voices**: each reporting organisation at its
     * grade factor once the profile grades anybody, and **at most one
     * each** — the question is how many sources there are, not how
     * reliable they are, so an `A` is one source and a `G` none. The
     * record is thin while it has less than `max_voices + 1` sources'
     * worth: on whole numbers that is the old `orgs ≤ max_orgs`
     * exactly, and it is what keeps a quarter-voice second source from
     * lifting the clamp alone.
     *
     * **Corroboration is weighed the same way**, and has two kinds:
     * type-0 sightings from organisations that did not report the
     * value, and a graded outside verdict agreeing with the lean,
     * which `assess()` leaves in `outside_agreement`.
     *
     * **The ceiling can depend on the grade.** `max_band_by_grade`
     * names a band per grade, read for the heaviest reporter; a grade
     * it does not name takes `max_band`.
     *
     * @param array $thresholds
     * @param array $context
     * @return array|null `band`, and `grade` when a grade set it
     */
    public static function clampCeiling(array $thresholds, array $context)
    {
        $clamp = isset($thresholds['thin_record_clamp'])
            && is_array($thresholds['thin_record_clamp'])
            ? $thresholds['thin_record_clamp']
            : array();
        if (empty($clamp['max_band'])) {
            return null;
        }
        $maxVoices = isset($clamp['max_voices'])
            && is_numeric($clamp['max_voices'])
            ? (float)$clamp['max_voices']
            : (isset($clamp['max_orgs']) && is_numeric($clamp['max_orgs'])
                ? (float)$clamp['max_orgs']
                : 1.0);
        $maxSightings = isset($clamp['max_sightings'])
            ? (float)$clamp['max_sightings']
            : 0.0;
        $sources = self::sourceVoices($context);
        if (ValueLeanTool::atLeast($sources['voices'], $maxVoices + 1)) {
            return null;
        }
        $corroboration = self::weightedCorroboration($context)
            + (float)($context['outside_agreement'] ?? 0);
        if (ValueLeanTool::atLeast($corroboration, $maxSightings + 1)) {
            return null;
        }
        $byGrade = isset($clamp['max_band_by_grade'])
            && is_array($clamp['max_band_by_grade'])
            ? $clamp['max_band_by_grade']
            : array();
        $grade = $sources['grade'];
        if ($grade !== null && isset($byGrade[$grade])
            && in_array($byGrade[$grade], self::BANDS, true)
        ) {
            return array('band' => $byGrade[$grade], 'grade' => $grade);
        }
        return array('band' => $clamp['max_band'], 'grade' => null);
    }

    /**
     * How many sources the record has, each counted at most once, and
     * the grade of the heaviest.
     *
     * @param array $context
     * @return array `voices` (float) and `grade` (string|null)
     */
    private static function sourceVoices(array $context)
    {
        $orgs = isset($context['orgs']) && is_array($context['orgs'])
            ? $context['orgs']
            : array();
        if (empty($orgs)) {
            return array(
                'voices' => (float)($context['occurrences']['orgs'] ?? 0),
                'grade' => null,
            );
        }
        $weighted = !empty(ValueTrustTool::blockFrom($context)['in_force']);
        $voices = 0.0;
        $heaviest = -1.0;
        $grade = null;
        foreach ($orgs as $org) {
            $id = (int)($org['id'] ?? 0);
            $factor = $weighted ? ValueTrustTool::factor($context, $id) : 1.0;
            $voices += min(1.0, $factor);
            if ($weighted && $factor > $heaviest) {
                $heaviest = $factor;
                $grade = ValueTrustTool::gradeFor($context, $id);
            }
        }
        return array('voices' => $voices, 'grade' => $grade);
    }

    /**
     * `corroboratingSightings()`, each filer's sightings at its grade
     * factor (at most one each) once the profile grades anybody.
     *
     * @param array $context
     * @return float
     */
    private static function weightedCorroboration(array $context)
    {
        $byOrg = isset($context['sightings']['seen']['by_org'])
            && is_array($context['sightings']['seen']['by_org'])
            ? $context['sightings']['seen']['by_org']
            : array();
        $reporters = array();
        foreach ($context['orgs'] ?? array() as $org) {
            if (isset($org['id'])) {
                $reporters[(int)$org['id']] = true;
            }
        }
        $weighted = !empty(ValueTrustTool::blockFrom($context)['in_force']);
        $total = 0.0;
        foreach ($byOrg as $id => $n) {
            if (isset($reporters[(int)$id])) {
                continue;
            }
            $total += (int)$n * ($weighted
                ? min(1.0, ValueTrustTool::factor($context, $id))
                : 1.0);
        }
        return $total;
    }

    /**
     * Type-0 sightings filed by organisations that did not report the
     * value — what the clamp means by *corroborated*.
     *
     * A reporter sighting its own value is still one source, and a
     * false positive or an expiration is not a sighting at all. An
     * anonymised sighting is left out: its filer may be the reporter.
     *
     * @param array $context
     * @return int
     */
    public static function corroboratingSightings(array $context)
    {
        $byOrg = isset($context['sightings']['seen']['by_org'])
            && is_array($context['sightings']['seen']['by_org'])
            ? $context['sightings']['seen']['by_org']
            : array();
        $reporters = array();
        foreach ($context['orgs'] ?? array() as $org) {
            if (isset($org['id'])) {
                $reporters[(int)$org['id']] = true;
            }
        }
        $count = 0;
        foreach ($byOrg as $id => $n) {
            if (!isset($reporters[(int)$id])) {
                $count += (int)$n;
            }
        }
        return $count;
    }

    /**
     * The profile's `signals` list, or nothing when there is no
     * profile.
     *
     * A viewer with no profile in force is a real state, not an error:
     * `AnalystProfile::resolveFor()` returns null when a site admin has
     * disabled the default, and the page then has a lean and no
     * signal strength.
     *
     * @param array|null $profile
     * @return array
     */
    private function signalEntries($profile)
    {
        $signals = self::section($profile, 'signals');
        if (!is_array($signals)) {
            return array();
        }
        $entries = array();
        foreach ($signals as $entry) {
            if (is_array($entry)) {
                $entries[] = $entry;
            }
        }
        return $entries;
    }

    /**
     * One `parameters` section, whichever shape the profile arrived in
     * — the model's `afterFind` decodes `parameters` into an array, and
     * a caller building a profile by hand may hand over the parameters
     * alone.
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
     * What the hero names as the profile in force.
     *
     * A profile whose `parameters` would not parse still gets named:
     * the profile *was* the thing that weighted the assessment,
     * imperfectly, and naming something else would make the hero's
     * sentence untrue.
     *
     * @param array|null $profile
     * @return string|null
     */
    private function profileName($profile)
    {
        if (!is_array($profile)) {
            return null;
        }
        return isset($profile['name']) ? $profile['name'] : null;
    }

    /**
     * @param array $user
     * @return array|null
     */
    private function profileFor(array $user)
    {
        if ($this->model === null) {
            return null;
        }
        return ClassRegistry::init('AnalystProfile')->resolveFor($user);
    }

    /**
     * @param array $user
     * @param string $value
     * @param array|null $profile
     * @param array $options
     * @return array
     */
    private function contextFor(array $user, $value, $profile,
        array $options
    ) {
        if ($this->model === null
            || !method_exists($this->model, 'verdictContextFor')
        ) {
            throw new InvalidArgumentException(
                __('ValueVerdictTool needs either a context or a model'
                    . ' that can build one.')
            );
        }
        return $this->model->verdictContextFor(
            $user,
            $value,
            $profile,
            $options
        );
    }
}
