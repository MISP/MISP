<?php

App::uses('ValueTrustTool', 'Tools/ValueIntelligence');

/**
 * The assessment's second axis: does what the record asserts still
 * matter operationally, today?
 *
 * MISP's decaying models answer *how bad is this* and *how stale is
 * this* in one number, while the signal-strength ledger already answers the
 * first from more evidence with an audit trail. What is taken from them
 * here is the time factor; what is left is the base score.
 *
 * **No ledger row, ever.** Relevance is its own axis, so nothing here
 * returns points and nothing here can move the lean or the signal-strength sum.
 * That is not a style rule: staleness emitted as threat-signed points
 * would let silence promote a value to definite BENIGN and let a
 * freshly-confirmed value fall *out* of it. An axis that never touches
 * the other two cannot do either.
 *
 * **Pure and static, and it takes no `$user`.** Every fact it reads is
 * on the context the owning model built, already scoped to the viewer;
 * it issues no query and resolves no permission.
 *
 * ## The four states
 *
 * ```
 * current              runway ≥ aging_fraction
 * aging                0 < runway < aging_fraction
 * expired              elapsed ≥ ttl
 * timeline uncertain   the clock itself is not trustworthy
 * ```
 *
 * The discontinuity at the boundary is deliberate: **expiry is an
 * event, not a gradient.** A value one day past its TTL reads
 * differently from one a day before it, because that is what a TTL
 * means and it is what makes the relevance falsifiability line worth
 * stating.
 *
 * **Uncertainty is a flag as well as a state**, and the order the two
 * resolve in is an argument rather than a preference. A record date
 * is *later* than the observation it stands for, so elapsed-time
 * measured from it is a **lower bound** on the true elapsed time. A
 * lower bound already past the TTL is past it on any honest reading, so
 * `expired` survives an untrustworthy clock; `current` and `aging` do
 * not, and degrade to `timeline uncertain`. Both facts travel, so the
 * page can read *"expired · timeline uncertain"* — which is exactly
 * what a phishing URL encoded long after the incident should say.
 *
 * ## The virtual age, and why it is not a measurement
 *
 * A record date — `created`, or `timestamp` on rows from before MISP
 * 3.0 — says when MISP was written to, not when the value was seen, and
 * `Event.date` is typed by an analyst, so no pair of them measures how
 * late a value was encoded.
 *
 * The axis uses `undated_assumed_days` instead — **a declared
 * assumption, not a reading.** When no occurrence carries
 * `first_seen`, the value is treated as that many days older than its
 * record, and the page says so in those words. `elapsed_days` is what
 * the runway is drawn from; `recorded_days` is what the rows actually
 * say; `assumed_days` is the difference and is never larger than what
 * leaves one day of lifetime, so the assumption can age a value and
 * can never expire one.
 */
class ValueRelevanceTool
{
    /**
     * How far back a runway series may run.
     *
     * The runway is the only dense series in the sightings payload — a
     * count can be sparse because most days have none, a shelf life
     * cannot because every day has one — so this is the number that
     * bounds the fragment. Uncapped, a value first reported a decade
     * ago would ship thousands of daily samples even when all its
     * reports are recent.
     *
     * There is **no** occurrence cap. A runway is computed from
     * aggregates and a list of corroboration dates, so its cost does
     * not track the occurrence count at all and there is nothing to cap.
     */
    const SPAN_CAP_DAYS = 1095;

    /** Clock settings, in the order the editor should offer them. */
    const CLOCKS = array(
        'last_independent_corroboration',
        'last_sighting',
        'last_occurrence',
    );

    /** `type_rule` settings. */
    const TYPE_RULES = array('shortest', 'longest', 'most_common');

    /** The states the axis can report, in clock order. */
    const STATES = array('current', 'aging', 'expired', 'uncertain');

    /**
     * Clock kinds whose date is an observation rather than a record date.
     *
     * A sighting carries `date_sighting` — an organisation saying *I
     * saw this, at this time*. `org_joined`, `occurrence` and
     * `fallback` read the occurrences' dates, which are a record date
     * wherever no seen date is declared.
     */
    const SIGHTED_CLOCK_KINDS = array('sighting', 'foreign_sighting');

    /**
     * The shelf-life buckets a type may be assigned to.
     *
     * Four, not three, and the reason is arithmetic rather than taste:
     * the shipped table uses five distinct values (60, 90, 120, 365,
     * 730), and three buckets cannot hold them without moving `url`
     * off 60 and the whole 120-day group onto some other number —
     * which would change how long real values stay relevant on every
     * instance running the default. Four plus one override reproduces
     * the shipped table exactly.
     */
    const BUCKETS = array('short', 'medium', 'long', 'very_long');

    /** What each bucket is worth when a profile does not say. */
    const BUCKET_DAYS = array(
        'short' => 90,
        'medium' => 120,
        'long' => 365,
        'very_long' => 730,
    );

    /** Defaults for a profile that names none, or for no profile. */
    const DEFAULTS = array(
        'clock' => 'last_independent_corroboration',
        // A float, so that `section()` returns one type whether the
        // profile named the speed or not: `1 !== 1.0` and a caller
        // comparing the resolved section against a default should not
        // have to know which branch produced it.
        'decay_speed' => 1.0,
        'type_rule' => 'shortest',
        'aging_fraction' => 0.33,
        /*
         * How much older than its record an undated value is assumed
         * to be. Not a measured lag — the columns cannot support one,
         * as `Value::recordSummaryFor()` describes. Conservative,
         * because dropping a live indicator costs more than keeping a
         * stale one, and capped at render so the assumption alone can
         * never expire anything.
         */
        'undated_assumed_days' => 30,
        'ttl_default' => 180,
    );

    /**
     * The axis with nothing to say, and why.
     *
     * Two paths reach it — no record at all, and a record whose rows
     * the budget did not read — and they return the same shape so a
     * caller can branch on `reason` rather than on which fields
     * happen to be null.
     *
     * @param string $reason `no_record` or `rows_not_read`
     * @param array $clock
     * @param array $ttl
     * @param array $precision
     * @return array
     */
    private static function noClock($reason, array $clock, array $ttl,
        array $precision
    ) {
        return array(
            'state' => null,
            'expired_by' => null,
            'reason' => $reason,
            'clock' => $clock,
            'ttl' => $ttl,
            'precision' => $precision,
            'runway' => null,
            'elapsed_days' => null,
            'recorded_days' => null,
            'recorded_runway' => null,
            'assumed_days' => 0,
            'assumed_setting' => (int)$precision['assumed_days'],
            'assumed_capped' => false,
            'runway_days' => null,
            'expires_at' => null,
            'uncertain' => false,
            'uncertain_note' => null,
        );
    }

    /**
     * The relevance axis for one value.
     *
     * @param array $context From the context builder — `now`, `types`,
     *                       `occurrences`, `orgs`, `temporal` and
     *                       `corroboration`
     * @param array|null $profile An `AnalystProfile` row, unwrapped, or
     *                            null when the section is absent
     * @return array
     */
    public static function relevanceFor(array $context, $profile = null)
    {
        $section = self::section($profile);
        $now = isset($context['now']) ? (int)$context['now'] : time();
        $ttl = self::ttlFor($context, $section);
        $clock = self::clockFor($context, $section);
        $precision = self::precisionFor($context, $section, $clock);

        /*
         * A clock whose sighting half was never fetched can only run
         * slow, and a slow clock on this axis says `expired` about a
         * value that is current.
         *
         * A value like `github.com` is the case: MISP flags it as
         * over-correlating, so the evidence budget leaves its rows
         * unread and the clock falls back to the record date,
         * which can read well past the TTL. The Sightings tab reads the
         * same value with no budget, finds a recent independent
         * sighting, and draws days left. Two panels, one axis, opposite
         * answers.
         *
         * So the axis stands down rather than guessing. `not_counted`
         * already names the budget on the page — *"this value is
         * flagged as over-correlating, so the rows this signal reads
         * were not fetched"* — and a shelf life computed around that
         * absence would be the one part of the assessment presenting a
         * degraded read as a measurement. No state means no chart, and
         * the hero's sentence ends after the band.
         *
         * Deliberately narrower than the clock's own `rows_read`, which
         * is also false when a sighting policy hides rows. That case
         * keeps its caveat on the relevance card: rows exist and the
         * date may be older than the truth, which is a caveat rather
         * than an absence.
         */
        if (!empty($context['budget']['hot'])) {
            return self::noClock('rows_not_read', $clock, $ttl,
                $precision);
        }

        /*
         * No occurrence this viewer can see is not a stale value and
         * not a fresh one: there is no clock to run and no type to take
         * a TTL from. The lean's own first rule says `none` here, and
         * this axis says the same thing by having no state — a page
         * that printed `expired` for a value it holds nothing about
         * would be inventing an assertion in order to age it.
         */
        if ($clock['at'] === null) {
            return array(
                'state' => null,
                'expired_by' => null,
                'reason' => 'no_record',
                'clock' => $clock,
                'ttl' => $ttl,
                'precision' => $precision,
                'runway' => null,
                'elapsed_days' => null,
                'recorded_days' => null,
                'recorded_runway' => null,
                'assumed_days' => 0,
                'assumed_setting' => (int)$precision['assumed_days'],
                'assumed_capped' => false,
                'runway_days' => null,
                'expires_at' => null,
                'uncertain' => false,
                'uncertain_note' => null,
            );
        }

        $elapsedDays = self::daysBetween($clock['at'], $now);
        /*
         * The virtual age. Nothing records when an undated value was
         * seen, so the profile states how much older than its record
         * to treat it as — and the days-left figure is computed from
         * that, rather than from a date everyone knows is too recent.
         *
         * **Capped so the assumption alone can never expire it.** An
         * assumption that drops live indicators out of an export is
         * the costlier of the two mistakes, and most real values carry
         * no `first_seen`, so an uncapped offset would age the whole
         * instance past its own TTL. The cap leaves `expired` reachable
         * only by elapsed time that actually elapsed; the assumption
         * can carry a value as far as the last day of its lifetime and
         * no further.
         *
         * Both numbers travel. A page that showed only the effective
         * one would be presenting an assumption as a measurement.
         */
        $assumed = 0;
        if (!empty($precision['uncertain'])) {
            $assumed = max(0, min(
                (int)$precision['assumed_days'],
                (int)$ttl['days'] - 1 - $elapsedDays
            ));
        }
        $effectiveDays = $elapsedDays + $assumed;
        $runway = self::runway(
            $effectiveDays,
            $ttl['days'],
            $section['decay_speed']
        );
        /*
         * The same curve without the assumption. The track's axis is
         * runway remaining, not elapsed time, so a panel wanting to
         * draw the stretch the assumption consumed needs both readings
         * in *that* coordinate system — subtracting days and scaling
         * them linearly is only correct at `decay_speed` 1.
         */
        $recordedRunway = self::runway(
            $elapsedDays,
            $ttl['days'],
            $section['decay_speed']
        );
        /*
         * **The real elapsed time decides expiry; the assumed one
         * decides everything else.** Passing the effective days here
         * would let the assumption expire a value, and `stateFor()`
         * uses its first argument for the `>= ttl` test alone — so the
         * record's own days go in, and the runway computed above,
         * which already carries the assumption, settles current
         * against aging.
         */
        $state = self::stateFor(
            $elapsedDays,
            $ttl['days'],
            $runway,
            $section['aging_fraction'],
            $precision['uncertain']
        );
        $runwayDays = $ttl['days'] - $elapsedDays;
        $expiresAt = $clock['at'] + ($ttl['days'] * 86400);
        /*
         * A filed expiration is the end of the lifetime, stated rather
         * than reached: expired from that day, whatever runway the
         * clock had left.
         */
        $expiry = self::standingExpiry($context, $clock);
        if ($expiry !== null) {
            $state = 'expired';
            $runway = 0.0;
            $runwayDays = min($runwayDays,
                -self::daysBetween($expiry['at'], $now));
            $expiresAt = min($expiresAt, (int)$expiry['at']);
        }

        return array(
            'state' => $state,
            'expired_by' => $expiry,
            'reason' => null,
            'clock' => $clock,
            'ttl' => $ttl,
            'precision' => $precision,
            'runway' => $runway,
            'elapsed_days' => $effectiveDays,
            'recorded_days' => $elapsedDays,
            'recorded_runway' => $recordedRunway,
            'assumed_days' => $assumed,
            'assumed_setting' => (int)$precision['assumed_days'],
            /*
             * Only where the cap actually bit on a live value. Past
             * the lifetime the clamp drives `assumed` to zero as a
             * matter of arithmetic, and flagging it there would print
             * *the rest is not applied, because an assumption may
             * never expire a value* about a value real time expired
             * months earlier.
             */
            'assumed_capped' => !empty($precision['uncertain'])
                && $assumed < (int)$precision['assumed_days']
                && $elapsedDays < $ttl['days'],
            /*
             * Both of these are the record's, not the assumption's.
             * Taken from the assumption, the card contradicts itself
             * within three lines — *41 days left* over *expires in 71
             * days* — because the cap hands the assumed days back as
             * the real ones run out. The
             * assumption moves where the value sits on the curve —
             * which is what the bar draws and what `current` against
             * `aging` reads — and the date its lifetime ends is a fact
             * about the clock and the TTL that no assumption touches.
             */
            'runway_days' => $runwayDays,
            'expires_at' => $expiresAt,
            'uncertain' => $precision['uncertain'],
            'uncertain_note' => $precision['note'],
            'aging_fraction' => $section['aging_fraction'],
            'decay_speed' => $section['decay_speed'],
        );
    }

    /**
     * The curve, lifted rather than called.
     *
     * `DecayingModelsFormulas/Polynomial.php:17` is
     * `base × (1 − (elapsed / lifetime)^(1 / decay_speed))`, clamped at
     * zero, and at `decay_speed = 1` the exponent is 1 and this is
     * linear. The two are not alternatives — one contains the other —
     * which is why *"polynomial or linear"* is a false choice.
     *
     * The one-line expression is lifted rather than passing a synthetic
     * `DecayingModel` array through a class that expects a real one:
     * `computeScore()` takes `($model, $attribute, $base, $elapsed)`
     * and the page has no model and no attribute to give it. Passing
     * two empty arrays to get a fraction out is coupling with nothing
     * on the other end of it.
     *
     * With `base = 1` the result *is* the fraction of shelf life left:
     * 1 at zero elapsed, 0 at the TTL.
     *
     * @param float $elapsedDays
     * @param int $ttlDays
     * @param float $speed
     * @return float In `[0, 1]`
     */
    public static function runway($elapsedDays, $ttlDays, $speed = 1)
    {
        $ttlDays = (float)$ttlDays;
        if ($ttlDays <= 0) {
            // A TTL of nothing expires on arrival. Not a division.
            return 0.0;
        }
        $speed = (float)$speed;
        if ($speed <= 0) {
            $speed = 1.0;
        }
        $ratio = (float)$elapsedDays / $ttlDays;
        if ($ratio <= 0) {
            return 1.0;
        }
        if ($ratio >= 1) {
            return 0.0;
        }
        return max(0.0, min(1.0, 1 - pow($ratio, 1 / $speed)));
    }

    /**
     * Where on the curve aging begins, as a fraction of the TTL.
     *
     * `runway()` read backwards: solve `aging = 1 − elapsed^(1/speed)`
     * for elapsed and you get `(1 − aging)^speed`. It lives here rather
     * than in the template that draws the mark because the editor also
     * has to say the same day in words — *0.33 means day 60 of 90* —
     * and the mark and the sentence disagreeing would be worse than
     * either of them being wrong alone.
     *
     * @param float $aging The share of shelf life left when aging starts
     * @param float $speed
     * @return float In `[0, 1]`
     */
    public static function agingElapsed($aging, $speed = 1)
    {
        $speed = (float)$speed;
        if ($speed <= 0) {
            $speed = 1.0;
        }
        $aging = max(0.0, min(1.0, (float)$aging));
        return max(0.0, min(1.0, pow(1 - $aging, $speed)));
    }

    /**
     * The same point in days, for a shelf life of `$ttlDays`.
     *
     * @param float $aging
     * @param float $speed
     * @param int $ttlDays
     * @return int
     */
    public static function agingDay($aging, $speed, $ttlDays)
    {
        return (int)round(
            self::agingElapsed($aging, $speed) * (int)$ttlDays
        );
    }

    /**
     * Which state a runway and an elapsed time make.
     *
     * @param float $elapsedDays
     * @param int $ttlDays
     * @param float $runway
     * @param float $aging
     * @param bool $uncertain
     * @return string
     */
    public static function stateFor($elapsedDays, $ttlDays, $runway,
        $aging, $uncertain = false
    ) {
        if ($elapsedDays >= $ttlDays) {
            /*
             * Expiry wins over uncertainty, and the reason is the
             * direction of the bound rather than a preference between
             * two labels — see the class note. The uncertainty is not
             * swallowed: it travels beside the state.
             */
            return 'expired';
        }
        if ($uncertain) {
            return 'uncertain';
        }
        return $runway >= $aging ? 'current' : 'aging';
    }

    /**
     * What a state is called on screen.
     *
     * Two surfaces render this axis — the value page's relevance card
     * and the profile editor's bench — and each one keeping its own
     * copy of four words is how one ends up printing `uncertain` raw
     * while the other says *timeline uncertain*. One writer, the way
     * the clock and `type_rule` lists have one.
     *
     * The uncertainty flag is deliberately not composed in here. It is
     * a second thing that is true at once, and a caller that wants
     * both says so itself rather than receiving a sentence it cannot
     * take apart again.
     *
     * @param string|null $state
     * @return string
     */
    public static function stateLabel($state)
    {
        $labels = array(
            'current' => __('current'),
            'aging' => __('aging'),
            'expired' => __('expired'),
            'uncertain' => __('timeline uncertain'),
        );
        if ($state === null || !isset($labels[$state])) {
            return (string)$state;
        }
        return $labels[$state];
    }

    /**
     * A clock setting, in words.
     *
     * The companion to `stateLabel()`, and here for the same reason:
     * the value card, the editor's bench and the profile viewer all
     * name the setting, and three copies of three strings is how one of
     * them ends up printing the stored key.
     *
     * @param string|null $setting
     * @return string
     */
    public static function clockLabel($setting)
    {
        $labels = array(
            'last_independent_corroboration' => __('last independent'
                . ' corroboration'),
            'last_sighting' => __('last sighting'),
            'last_occurrence' => __('last occurrence'),
        );
        if ($setting === null || !isset($labels[$setting])) {
            return (string)$setting;
        }
        return $labels[$setting];
    }

    /**
     * What a state means, for the hover beside the word.
     *
     * `stateLabel()` names the state and this says what it tells a
     * reader to do about it. Split because the label is read in places
     * with no room for a sentence — the hero's badge, the editor's
     * bench — and the sentence is read in the places that have one.
     *
     * @param string|null $state
     * @return string|null Null where there is nothing to add
     */
    public static function stateHint($state)
    {
        $hints = array(
            'current' => __('Inside its lifetime.'),
            'aging' => __('Not expired, but no longer current under'
                . ' this profile.'),
            'expired' => __('Past its lifetime. Re-check it before'
                . ' acting on it.'),
            'uncertain' => __('It may be older than shown.'),
        );
        return isset($hints[$state]) ? $hints[$state] : null;
    }

    /**
     * What reset the clock, in words.
     *
     * `new organisation` and `independent sighting` are terms this
     * feature invented, and they are read on three surfaces — the
     * Lifetime card, the Assessment tab's clock band and the editor's
     * bench. `clockLabel()`'s docblock names the failure this avoids:
     * the copy that does not get updated is the one that prints
     * `org_joined` at a reader.
     *
     * @param string|null $kind
     * @return string The stored key where the kind is unknown
     */
    public static function kindLabel($kind)
    {
        $labels = array(
            'org_joined' => __('new organisation'),
            'foreign_sighting' => __('independent sighting'),
            'sighting' => __('sighting'),
            'occurrence' => __('occurrence'),
            'fallback' => __('own encoding date'),
        );
        return isset($labels[$kind]) ? $labels[$kind] : (string)$kind;
    }

    /**
     * The definition behind a kind's label.
     *
     * A reader meeting *new organisation* in a list of dates has no way
     * to tell it from *independent sighting*, and six rows of
     * definitions beside six rows of data is the density the Lifetime
     * card is built to avoid. So it is a hover.
     *
     * @param string|null $kind
     * @return string|null Null where there is nothing to add
     */
    public static function kindHint($kind)
    {
        $hints = array(
            'org_joined' => __('An organisation that had not reported'
                . ' this value before now has.'),
            'foreign_sighting' => __('A sighting from an organisation'
                . ' other than the one that reported the value.'),
            'sighting' => __('Somebody reported seeing this value.'),
            'occurrence' => __('This value appeared in an event.'),
            'fallback' => __('The value\'s own date, with nothing'
                . ' confirming it.'),
        );
        return isset($hints[$kind]) ? $hints[$kind] : null;
    }

    /**
     * The TTL in force, and every candidate it was chosen from.
     *
     * A value can occur as both `ip-src` and `ip-dst`, and MISP's
     * per-attribute decay never had to answer which TTL a *value* takes.
     * `shortest` is the default because it is the conservative reading —
     * a value that is stale in any of its roles is worth re-checking —
     * and because the alternative silently extends a short-lived
     * indicator's life on the strength of a type it barely appears as.
     *
     * **The candidates travel whatever the rule chose**, because the
     * panel has to name which type supplied the number and that others
     * were shorter or longer. A single number with no
     * provenance is how a reader concludes the page is wrong about a
     * value they know well.
     *
     * @param array $context
     * @param array $section From section()
     * @return array `days`, `type`, `rule`, `candidates`, `spread`
     */
    public static function ttlFor(array $context, array $section)
    {
        $rule = $section['type_rule'];
        $table = $section['ttl_days'];
        $default = $section['ttl_default'];
        $assigned = isset($section['ttl_types'])
            ? $section['ttl_types']
            : array();
        $overrides = isset($section['ttl_overrides'])
            ? $section['ttl_overrides']
            : array();
        $candidates = array();
        foreach (self::typeList($context) as $type => $count) {
            /*
             * Where the number came from, so the page can say *90 days,
             * short* rather than quoting a bare number a reader then
             * has to go and look up. An override is named as one
             * because it is the thing the buckets could not express.
             */
            if (isset($overrides[$type])) {
                $from = 'override';
            } elseif (isset($assigned[$type])) {
                $from = 'bucket';
            } else {
                $from = 'default';
            }
            $candidates[$type] = array(
                'type' => $type,
                'days' => isset($table[$type])
                    ? (int)$table[$type]
                    : $default,
                'count' => $count,
                'named' => isset($table[$type]),
                'from' => $from,
                'bucket' => isset($assigned[$type]) && $from === 'bucket'
                    ? $assigned[$type]
                    : null,
            );
        }
        if (empty($candidates)) {
            return array(
                'days' => $default,
                'type' => null,
                'rule' => $rule,
                'candidates' => array(),
                'spread' => false,
                'from_default' => true,
                'from' => 'default',
                'bucket' => null,
            );
        }
        $chosen = self::chooseType($candidates, $rule);
        $days = array_column($candidates, 'days');
        return array(
            'days' => $chosen['days'],
            'type' => $chosen['type'],
            'rule' => $rule,
            'candidates' => array_values($candidates),
            'spread' => min($days) !== max($days),
            'from_default' => !$chosen['named'],
            'from' => $chosen['from'],
            'bucket' => $chosen['bucket'],
        );
    }

    /**
     * The candidate the rule picks.
     *
     * `most_common` breaks a tie on the shortest TTL rather than on
     * whichever type the query happened to return first: a rule whose
     * answer depends on row order is a rule that changes its mind
     * between two page loads.
     *
     * @param array $candidates
     * @param string $rule
     * @return array
     */
    private static function chooseType(array $candidates, $rule)
    {
        $best = null;
        foreach ($candidates as $candidate) {
            if ($best === null) {
                $best = $candidate;
                continue;
            }
            if ($rule === 'longest') {
                $better = $candidate['days'] > $best['days'];
            } elseif ($rule === 'most_common') {
                $better = $candidate['count'] > $best['count']
                    || ($candidate['count'] === $best['count']
                        && $candidate['days'] < $best['days']);
            } else {
                $better = $candidate['days'] < $best['days'];
            }
            if ($better) {
                $best = $candidate;
            }
        }
        return $best;
    }

    /**
     * The clock: what last confirmed this value, and who.
     *
     * **This is the load-bearing decision, more than the curve.** MISP's
     * own answer is *last sighting*, and its consequence is that a
     * heavily-sighted value never decays — the term does nothing for
     * exactly the values with the most activity. The default here is
     * `last_independent_corroboration`: the most recent of
     *
     *   - an occurrence created by an organisation that did not already
     *     hold one, or
     *   - a sighting from an organisation other than the occurrence's
     *     reporter,
     *
     * because the clock should reset when *someone new confirms it*, and
     * an org re-sighting its own report for the two-hundredth time is
     * activity rather than corroboration.
     *
     * **The earliest organisation is not corroboration.** It is the
     * original report, which is the thing being corroborated — so the
     * organisation joins are read in date order and the first one is
     * dropped. On a single-organisation value that leaves nothing, the
     * clock falls back to the value's own most recent encoding, and
     * `fallback` says so: this is the majority case in production and
     * it must render as a stated condition rather than as a blank.
     *
     * @param array $context
     * @param array $section
     * @return array `at`, `kind`, `by`, `held_by`, `fallback`, `events`
     */
    public static function clockFor(array $context, array $section)
    {
        $events = self::eventsFor($context, $section['clock']);
        $newest = null;
        foreach ($events as $event) {
            if ($newest === null || $event['at'] > $newest['at']) {
                $newest = $event;
            }
        }
        /*
         * Whether the sighting half of the clock was readable at all.
         * A value MISP flagged as over-correlating has its rows left
         * unfetched by the budget, and a sighting policy can hide them
         * — so a clock running off the organisation joins alone must
         * say which half it is missing rather than presenting half an
         * answer as a whole one.
         */
        $available = empty($context['budget']['hot'])
            && !isset($context['missing']['sightings']);
        if ($newest !== null) {
            return array(
                'setting' => $section['clock'],
                'at' => $newest['at'],
                'kind' => $newest['kind'],
                'by' => isset($newest['by']) ? $newest['by'] : null,
                'held_by' => isset($newest['held_by'])
                    ? $newest['held_by']
                    : null,
                'fallback' => false,
                'events' => $events,
                'rows_read' => $available,
            );
        }
        $fallback = self::fallbackFor($context);
        return array(
            'setting' => $section['clock'],
            'at' => $fallback === null ? null : $fallback['at'],
            'kind' => 'fallback',
            'by' => $fallback === null ? null : $fallback['by'],
            'held_by' => null,
            'fallback' => true,
            'events' => array(),
            'rows_read' => $available,
        );
    }

    /**
     * Every dated event the chosen clock counts, ascending.
     *
     * The list, not just its maximum, because the runway series needs
     * it: the clock moves over history, so the shelf life at a past day
     * is measured from the newest corroboration that had *happened by*
     * that day. Taking the current clock and walking backwards would
     * draw a value corroborated last week as having been fresh in 2019.
     *
     * Taking `max(report, attribute date)` unconditionally is the same
     * mistake: it applies a reset on days that preceded it, and draws a
     * plateau at full score long past a short lifetime — visible the
     * moment the chart is drawn and invisible to every assertion.
     * `runwaySeries()` walks forward for that reason.
     *
     * @param array $context
     * @param string $clock
     * @return array Ascending by `at`; each `at`, `kind`, `by`,
     *               optionally `held_by`
     */
    public static function eventsFor(array $context, $clock)
    {
        $events = array();
        if ($clock === 'last_occurrence') {
            foreach (self::orgRows($context) as $org) {
                if (empty($org['newest'])) {
                    continue;
                }
                $events[] = array(
                    'at' => (int)$org['newest'],
                    'kind' => 'occurrence',
                    'by' => self::orgLabel($org),
                );
            }
        } elseif ($clock === 'last_sighting') {
            $events = self::sightingEvents($context, 'sightings');
        } else {
            $events = array_merge(
                self::joinEvents($context),
                self::sightingEvents($context, 'foreign')
            );
        }
        usort($events, function ($a, $b) {
            return $a['at'] === $b['at'] ? 0 : ($a['at'] < $b['at'] ? -1 : 1);
        });
        return $events;
    }

    /**
     * When each organisation other than the first one joined.
     *
     * **`at` is a declared observation where one exists.**
     * `org['oldest']` is `MIN(Value::observedFrom())` — `first_seen`,
     * then `last_seen`, then when the row was recorded — so an
     * organisation's join date is when it says it saw the value rather
     * than when it last touched the row.
     *
     * @param array $context
     * @return array
     */
    private static function joinEvents(array $context)
    {
        $joins = array();
        foreach (self::orgRows($context) as $org) {
            if (empty($org['oldest'])) {
                continue;
            }
            $joins[] = array(
                'at' => (int)$org['oldest'],
                'kind' => 'org_joined',
                'by' => self::orgLabel($org),
            );
        }
        usort($joins, function ($a, $b) {
            return $a['at'] === $b['at'] ? 0 : ($a['at'] < $b['at'] ? -1 : 1);
        });
        // The first organisation is the report, not its corroboration.
        array_shift($joins);
        return $joins;
    }

    /**
     * The sighting half of the clock, from the day-folded reports the
     * context carries.
     *
     * Every entry is a whole report rather than a bare stamp, so every
     * row of the corroboration timeline has a name on it and the
     * maximum below cannot pick an unlabelled duplicate over a labelled
     * one — a tie bare stamps could lose on a report filed at exactly
     * midnight.
     *
     * @param array $context
     * @param string $which `sightings` or `foreign`
     * @return array
     */
    private static function sightingEvents(array $context, $which)
    {
        $corroboration = isset($context['corroboration'])
            ? $context['corroboration']
            : array();
        $entries = isset($corroboration[$which . '_days'])
            ? $corroboration[$which . '_days']
            : array();
        $kind = $which === 'foreign' ? 'foreign_sighting' : 'sighting';
        $events = array();
        foreach ($entries as $entry) {
            $events[] = array(
                'at' => (int)$entry['at'],
                'kind' => $kind,
                'by' => isset($entry['name']) ? $entry['name'] : null,
                'held_by' => array(
                    'attribute_id' => $entry['attribute_id'] ?? null,
                    'event_id' => $entry['event_id'] ?? null,
                ),
            );
        }
        return $events;
    }

    /**
     * The clock with nothing to corroborate it: the value's own most
     * recent encoding.
     *
     * **An encoding date, deliberately.** It is when a row was
     * recorded, not when anything was observed, so a value whose only
     * date is this one has an unknown observation date — and the
     * precision check turns that into
     * `timeline uncertain` rather than into a confident `current`. The
     * fallback is not a guess dressed up as a measurement; it is the
     * measurement the record actually supports, labelled as such.
     *
     * @param array $context
     * @return array|null
     */
    private static function fallbackFor(array $context)
    {
        $newest = isset($context['occurrences']['newest'])
            ? (int)$context['occurrences']['newest']
            : 0;
        if ($newest <= 0) {
            return null;
        }
        $by = null;
        foreach (self::orgRows($context) as $org) {
            if ((int)($org['newest'] ?? 0) === $newest) {
                $by = self::orgLabel($org);
                break;
            }
        }
        return array('at' => $newest, 'by' => $by);
    }

    /**
     * The first of `$keys` this section gives a number for.
     *
     * So a renamed setting can keep reading the name a stored profile
     * wrote, without the caller branching on which one it found.
     *
     * @param array $section
     * @param array $keys In precedence order
     * @param int $fallback
     * @return int
     */
    private static function firstNumeric(array $section, array $keys,
        $fallback
    ) {
        foreach ($keys as $key) {
            if (isset($section[$key]) && is_numeric($section[$key])) {
                return (int)$section[$key];
            }
        }
        return (int)$fallback;
    }

    /**
     * Whether the clock can be trusted at all.
     *
     * The motivating example: a phishing URL encoded two months after
     * the incident with no `first_seen`, so the clock falls back to a
     * row-modification timestamp and the axis would call a dead
     * campaign *current*.
     *
     * **One detecting fact, not two.** The obvious second would be a
     * created-to-published lag — `Event.date` against the record date.
     * `Event.date` is typed by an analyst and carries the very delay
     * the measurement would be hunting, so neither this check nor
     * `record.temporal_precision` uses it, whether or not the
     * occurrence carries `created`.
     *
     * What remains is the question the rows can answer: **is the date
     * the clock measures from an observation date, or a record
     * date?** Where a lag would be a bad estimate of how much older the
     * value really is, `undated_assumed_days` is a declared assumption
     * about the same thing — visible, editable, and never pretending to
     * be a reading.
     *
     * **A sighting answers it.** Reading `first_seen` on occurrences and
     * nothing else would tell a value whose clock had just been reset
     * by a sighting that its timeline cannot be trusted — while the
     * number the warning qualifies is measured from that sighting's own
     * `date_sighting`, which is an organisation stating *I saw this, at
     * this time*.
     *
     * So the flag asks about the clock it qualifies. A
     * sighting-based clock is dated by definition; an occurrence-based
     * one reads a record date — a creation time dates the record, not
     * the observation — and is uncertain unless the occurrences carry
     * `first_seen` to show MISP holds real observation dates for this
     * value at all.
     *
     * @param array $context
     * @param array $section
     * @param array|null $clock From `clockFor()`, when the caller has it
     * @return array `uncertain`, `reasons`, `note`, plus the raw counts
     */
    public static function precisionFor(array $context, array $section,
        $clock = null
    ) {
        $temporal = isset($context['temporal'])
            ? $context['temporal']
            : array();
        $occurrences = (int)($temporal['occurrences'] ?? 0);
        $dated = (int)($temporal['with_first_seen'] ?? 0);
        $kind = is_array($clock) && isset($clock['kind'])
            ? $clock['kind']
            : null;
        $sighted = in_array($kind, self::SIGHTED_CLOCK_KINDS, true);
        $reasons = array();
        if ($occurrences > 0 && $dated === 0 && !$sighted) {
            $reasons[] = array('key' => 'no_first_seen');
        }
        return array(
            'uncertain' => !empty($reasons),
            'reasons' => $reasons,
            'note' => self::precisionNote($reasons),
            'occurrences' => $occurrences,
            'with_first_seen' => $dated,
            'clock_is_dated' => $sighted,
            'assumed_days' => (int)$section['undated_assumed_days'],
        );
    }

    /**
     * The measurement that tripped, as the sentence the panels print.
     *
     * Worded here rather than in each template because two panels show
     * it at two scales and a state this specific must not be paraphrased
     * differently in each. The state has to carry its reason: *never a
     * silently wrong `current`*, and never a bare *uncertain* either.
     *
     * @param array $reasons
     * @return string|null
     */
    private static function precisionNote(array $reasons)
    {
        if (empty($reasons)) {
            return null;
        }
        $parts = array();
        foreach ($reasons as $reason) {
            $parts[] = __('no occurrence records when it was first seen');
        }
        return implode(__(' · '), $parts);
    }

    /**
     * The runway over a day grid, for the chart overlay.
     *
     * Two quantities rather than two estimates of one. Plotting the
     * synthesised score against a NIDS decay score would put a second
     * decay opinion on a page that has one; this plots **evidence
     * against remaining shelf life**, which is a question an analyst
     * actually has.
     *
     * The walk is forward and the event list is sorted, so this is
     * linear in days plus events rather than a scan per day. `null`
     * before the first day anything is known: a gap is the honest mark,
     * and zero is a value that has expired rather than one with nothing
     * recorded.
     *
     * @param array $relevance From relevanceFor()
     * @param array $grid Ascending unix timestamps, one per day
     * @param int|null $first The value's own first encoding, so days
     *                        before the record starts draw nothing
     * @return array One point per grid day: float in `[0, 1]`, or null
     */
    public static function runwaySeries(array $relevance, array $grid,
        $first = null
    ) {
        $ttl = $relevance['ttl']['days'];
        $speed = isset($relevance['decay_speed'])
            ? $relevance['decay_speed']
            : self::DEFAULTS['decay_speed'];
        $events = isset($relevance['clock']['events'])
            ? $relevance['clock']['events']
            : array();
        $assumed = (int)($relevance['assumed_days'] ?? 0);
        $stamps = array();
        foreach ($events as $event) {
            $stamps[] = (int)$event['at'];
        }
        sort($stamps);
        /*
         * With nothing corroborating it the clock is the fallback, and
         * the fallback is a single stamp — so the series is that one
         * stamp's runway from the day it lands.
         */
        if (empty($stamps) && $relevance['clock']['at'] !== null) {
            $stamps = array((int)$relevance['clock']['at']);
        }
        $points = array();
        $next = 0;
        $count = count($stamps);
        $held = null;
        $filed = isset($relevance['expired_by']['at'])
            ? strtotime(date('Y-m-d', (int)$relevance['expired_by']['at']))
            : null;
        foreach ($grid as $at) {
            if ($filed !== null && $at >= $filed) {
                $points[] = 0.0;
                continue;
            }
            while ($next < $count && $stamps[$next] <= $at) {
                $held = $stamps[$next];
                $next++;
            }
            $from = $held;
            if ($from === null && $first !== null && $first <= $at) {
                // Before anything corroborated it the shelf life runs
                // from the record's own start, which is the same
                // fallback the state uses.
                $from = (int)$first;
            }
            if ($from === null) {
                $points[] = null;
                continue;
            }
            /*
             * The assumed days ride along the whole series, or the
             * chart's last point and the card's bar disagree by
             * exactly the assumption.
             */
            $points[] = self::runway(
                self::daysBetween($from, $at) + $assumed,
                $ttl,
                $speed
            );
        }
        return $points;
    }

    /**
     * What would move this axis — the relevance falsifiability line,
     * solved for the boundary rather than guessed at.
     *
     * One line per axis and the cheapest one, so this answers the
     * question the state raises rather than every question it could:
     * a value that is current says how long it has, an aging one says
     * it is already past the line and what puts it back, an expired one
     * says what would bring it back, and an uncertain one says what
     * measurement would settle it — which is the only case where the
     * answer is not a number of days.
     *
     * **`aging` has a line of its own.** Falling through to `current`'s
     * would tell a value the profile has just flagged for re-checking
     * *no corroboration for 12 more days and the assessment expires* —
     * a countdown, when the thing worth saying is that the countdown
     * has already passed the mark the reader set. Elsewhere the state
     * is a chip and nothing else; this is the one place it can say what
     * it is for.
     *
     * @param array $relevance
     * @return array|null `axis`, `direction`, `text`
     */
    public static function changerFor(array $relevance)
    {
        if ($relevance['state'] === null) {
            return null;
        }
        if ($relevance['state'] === 'uncertain') {
            return array(
                'axis' => 'relevance',
                'direction' => 'up',
                /*
                 * Not `first_seen` and not *encoding*: the column name
                 * is `First seen` on MISP's own attribute form, and
                 * there is no encoding date in MISP to contrast it
                 * with. What the reader gains is concrete —
                 * the assumed days stop being added.
                 */
                'text' => sprintf(
                    __n(
                        'A first-seen date on any occurrence would say'
                            . ' when this was observed — the timeline'
                            . ' stops being uncertain and the %s'
                            . ' assumed day comes off.',
                        'A first-seen date on any occurrence would say'
                            . ' when this was observed — the timeline'
                            . ' stops being uncertain and the %s'
                            . ' assumed days come off.',
                        (int)($relevance['assumed_days'] ?? 0)
                    ),
                    (int)($relevance['assumed_days'] ?? 0)
                ),
            );
        }
        if ($relevance['state'] === 'expired'
            && !empty($relevance['expired_by'])
        ) {
            return array(
                'axis' => 'relevance',
                'direction' => 'up',
                'text' => sprintf(
                    __('%1$s filed it as expired on %2$s. A sighting or'
                        . ' a fresh report after that brings it back.'),
                    $relevance['expired_by']['name'],
                    date('Y-m-d', (int)$relevance['expired_by']['at'])
                ),
            );
        }
        if ($relevance['state'] === 'expired') {
            return array(
                'axis' => 'relevance',
                'direction' => 'up',
                'text' => sprintf(
                    __('One independent corroboration resets the clock —'
                        . ' the assessment is current again for %s days.'),
                    $relevance['ttl']['days']
                ),
            );
        }
        $days = (int)ceil($relevance['runway_days']);
        if ($relevance['state'] === 'aging') {
            /*
             * `up`, like `expired`'s: the line names something a reader
             * can go and do, where `current`'s names what happens if
             * nobody does anything. An aging value has both available
             * and the action is the useful half — it is already below
             * the mark, so counting its remaining days down is the
             * question it has stopped raising.
             */
            return array(
                'axis' => 'relevance',
                'direction' => 'up',
                'text' => sprintf(
                    __n(
                        'Already aging, with %s day left before it'
                            . ' expires. One independent corroboration'
                            . ' puts it back to current.',
                        'Already aging, with %s days left before it'
                            . ' expires. One independent corroboration'
                            . ' puts it back to current.',
                        $days
                    ),
                    $days
                ),
            );
        }
        return array(
            'axis' => 'relevance',
            'direction' => 'down',
            'text' => sprintf(
                __n(
                    'If nobody independent confirms it within %s day,'
                        . ' the assessment expires.',
                    'If nobody independent confirms it within %s days,'
                        . ' the assessment expires.',
                    $days
                ),
                $days
            ),
        );
    }

    /**
     * The clock's sighting half, folded from the rows.
     *
     * Lives here rather than in the owning model because it *is* the
     * clock's definition — *a sighting from an organisation other than
     * the occurrence's reporter* — and a definition split between a
     * tool and a model is a definition two readers will disagree about.
     * It takes rows and a map, issues nothing, and so is checkable
     * without an instance.
     *
     * **Type 0 only.** A false positive and an expiration are reports
     * that argue *against* the value; counting either as corroboration
     * would let a value be kept current by the community disputing it.
     * The Sightings tab exists to make that line visible. Expirations
     * are kept apart, each filer's newest, for standingExpiry().
     *
     * **Folded to one report a day, and whole-history.** The runway
     * series samples a day at a time, so a second sighting on a day
     * that already has one cannot move any curve; and the clock is a
     * whole-history aggregate by declaration, because a windowed clock
     * could not tell stale-since-91-days from stale-since-three-years
     * while the TTL table reaches 730. So the caller must fold
     * **before** applying `evidence.window` — which is the one
     * exclusion this clock does not see — and after `sightings.self`,
     * which is the same argument in a different place.
     *
     * **The fold keeps the day's newest report whole, not just its
     * date.** The curve reads only dates, but bare stamps labelled only
     * at the newest would put *unnamed* on most rows of the
     * corroboration timeline — and naming what supplied the clock is
     * part of the aggregation rule, not a decoration. A name per
     * distinct day costs a few dozen strings on a busy value.
     *
     * @param array $rows Rows as `Sighting::listSightings` returns
     * @param array $occurrences From `Value::sightedOccurrenceIdsFor` —
     *                           flat, keyed by attribute id
     * @return array The `corroboration` context block
     */
    public static function corroborationFrom(array $rows,
        array $occurrences
    ) {
        $days = array();
        $foreignDays = array();
        $expirations = array();
        $undecidable = 0;
        foreach ($rows as $row) {
            $type = (int)($row['Sighting']['type'] ?? 0);
            $at = (int)($row['Sighting']['date_sighting'] ?? 0);
            if ($type === 2 && $at > 0) {
                $orgId = (int)($row['Sighting']['org_id'] ?? 0);
                if (!isset($expirations[$orgId])
                    || $at > $expirations[$orgId]['at']
                ) {
                    $expirations[$orgId] = self::sightingEntry($row, $at);
                }
                continue;
            }
            if ($type !== 0 || $at <= 0) {
                continue;
            }
            $day = strtotime(date('Y-m-d', $at));
            $entry = self::sightingEntry($row, $at);
            if (!isset($days[$day]) || $at > $days[$day]['at']) {
                $days[$day] = $entry;
            }
            $orgId = (int)($row['Sighting']['org_id'] ?? 0);
            $id = (int)($row['Sighting']['attribute_id'] ?? 0);
            $author = isset($occurrences[$id])
                ? (int)($occurrences[$id]['orgc_id'] ?? 0)
                : 0;
            if ($orgId === 0 || $author === 0) {
                /*
                 * An anonymised report, or an occurrence whose reporter
                 * this viewer's row does not name. Independence is then
                 * a comparison that cannot be made, and the honest
                 * answer is to leave the sighting out of the
                 * *independent* half and say how many were skipped —
                 * the same conservative direction `sightings.self`
                 * takes from the other side. The count exists because
                 * a fold that reports nothing looks exactly like a fold
                 * with nothing to do.
                 */
                $undecidable++;
                continue;
            }
            if ($orgId === $author) {
                continue;
            }
            if (!isset($foreignDays[$day])
                || $at > $foreignDays[$day]['at']
            ) {
                $foreignDays[$day] = $entry;
            }
        }
        ksort($days);
        ksort($foreignDays);
        return array(
            'sightings_days' => array_values($days),
            'foreign_days' => array_values($foreignDays),
            'last_sightings' => empty($days)
                ? null
                : end($days),
            'last_foreign' => empty($foreignDays)
                ? null
                : end($foreignDays),
            'undecidable' => $undecidable,
            'expirations' => $expirations,
        );
    }

    /**
     * The expiration that ends the value's relevance, if one stands.
     *
     * An organisation filing an expiration is saying *this is over*.
     * It stands unless something later keeps the value alive: a type-0
     * sighting from anybody, or the clock's own date — a fresh report
     * or an independent corroboration after the filing, whichever the
     * profile's clock runs on. A filer whose grade counts for nothing
     * expires nothing.
     *
     * @param array $context
     * @param array $clock From clockFor()
     * @return array|null The filing, as sightingEntry() writes it
     */
    public static function standingExpiry(array $context, array $clock)
    {
        $expirations = $context['corroboration']['expirations'] ?? array();
        if (empty($expirations) || !is_array($expirations)) {
            return null;
        }
        $after = (int)($clock['at'] ?? 0);
        $seen = $context['corroboration']['last_sightings'] ?? null;
        if (is_array($seen)) {
            $after = max($after, (int)$seen['at']);
        }
        $trust = ValueTrustTool::blockFrom($context);
        $standing = null;
        foreach ($expirations as $orgId => $entry) {
            if ((int)$entry['at'] <= $after) {
                continue;
            }
            if (!empty($trust['in_force'])
                && ValueTrustTool::factor($context, (int)$orgId) <= 0.0
            ) {
                continue;
            }
            if ($standing === null || $entry['at'] > $standing['at']) {
                $standing = $entry;
            }
        }
        return $standing;
    }

    /**
     * One labelled sighting, in the shape the clock names its source
     * with.
     *
     * @param array $row
     * @param int $at
     * @return array
     */
    private static function sightingEntry(array $row, $at)
    {
        $name = $row['Organisation']['name'] ?? '';
        return array(
            'at' => $at,
            'org_id' => (int)($row['Sighting']['org_id'] ?? 0),
            'name' => $name === '' ? __('Others') : $name,
            'attribute_id' => (int)($row['Sighting']['attribute_id'] ?? 0),
            'event_id' => (int)($row['Sighting']['event_id'] ?? 0),
        );
    }

    /**
     * The `relevance` section, with every default filled in.
     *
     * A top-level section rather than an entry in the `signals` list,
     * because it configures an axis rather than a ledger row. A profile
     * naming none of these still produces the shipped behaviour —
     * *defaults that work unedited*, applied to this axis.
     *
     * An unrecognised `clock` or `type_rule` falls back to the default
     * rather than throwing: a profile is a hand-edited JSON document
     * and a typo in it must not take a page down.
     *
     * @param array|null $profile
     * @return array
     */
    public static function section($profile)
    {
        $section = array();
        if (is_array($profile)) {
            $parameters = isset($profile['parameters'])
                ? $profile['parameters']
                : $profile;
            if (isset($parameters['relevance'])
                && is_array($parameters['relevance'])
            ) {
                $section = $parameters['relevance'];
            }
        }
        $clock = isset($section['clock']) ? $section['clock'] : null;
        $rule = isset($section['type_rule'])
            ? $section['type_rule']
            : null;
        $shelf = self::shelfLife($section);
        $table = $shelf['ttl_days'];
        $default = $shelf['ttl_default'];
        return array(
            'ttl_buckets' => $shelf['ttl_buckets'],
            'ttl_types' => $shelf['ttl_types'],
            'ttl_overrides' => $shelf['ttl_overrides'],
            'clock' => in_array($clock, self::CLOCKS, true)
                ? $clock
                : self::DEFAULTS['clock'],
            'type_rule' => in_array($rule, self::TYPE_RULES, true)
                ? $rule
                : self::DEFAULTS['type_rule'],
            'decay_speed' => isset($section['decay_speed'])
                && is_numeric($section['decay_speed'])
                && (float)$section['decay_speed'] > 0
                ? (float)$section['decay_speed']
                : self::DEFAULTS['decay_speed'],
            'aging_fraction' => isset($section['aging_fraction'])
                && is_numeric($section['aging_fraction'])
                ? (float)$section['aging_fraction']
                : self::DEFAULTS['aging_fraction'],
            /*
             * `lag_uncertain_days` is still read, because older forks
             * carry it and a profile that silently lost a setting on
             * upgrade is worse than one that repurposes a number a
             * reader chose. Same units, same order of magnitude,
             * opposite kind of thing: the old key named a threshold a
             * measurement had to cross, the new one the assumption
             * that stands in for the measurement.
             */
            'undated_assumed_days' => self::firstNumeric(
                $section,
                array('undated_assumed_days', 'lag_uncertain_days'),
                self::DEFAULTS['undated_assumed_days']
            ),
            'ttl_days' => $table,
            'ttl_default' => $default,
        );
    }

    /**
     * Shelf life, from whichever of the two shapes the profile carries.
     *
     * **Current shape.** `ttl_buckets` gives each of the four buckets a
     * day count, `ttl_types` assigns a type to a bucket,
     * `ttl_overrides` gives a type its own day count, and `ttl_default`
     * covers every type nobody named. An override beats a bucket
     * assignment, because it exists for the type the buckets cannot
     * express.
     *
     * **Legacy shape.** A flat `ttl_days` map — the one every existing
     * fork carries, because `AnalystProfile::updateDefaults()` never
     * touches a fork. It reads as *no buckets, and every named type is
     * its own override*, which is exactly what it already meant. The
     * reading is exact rather than approximate, and it is why the
     * override list exists at all: an old fork keeps behaving
     * identically until somebody opens the editor. Without this a fork
     * would resolve no TTLs and every value in it would silently change
     * shelf life, with nobody having edited anything.
     *
     * Both shapes come out as one **effective type => days** map, so
     * `ttlFor()` and `chooseType()` compare days and `shortest` keeps
     * meaning shortest. Comparing bucket ordinals instead would be a
     * different rule wearing the same name.
     *
     * @param array $section The raw `relevance` section
     * @return array `ttl_buckets`, `ttl_types`, `ttl_overrides`,
     *               `ttl_days` (effective), `ttl_default`
     */
    private static function shelfLife(array $section)
    {
        /*
         * The two shapes do not blend. A document carrying any of the
         * current keys is read as a current one and its `ttl_days` is
         * ignored outright — a half-edited fork whose stale flat map
         * shadowed its own bucket assignments would resolve to a blend
         * of two shapes, which is unpredictable and which no analyst
         * asked for. `merge()` drops the legacy key on save for the
         * same reason.
         */
        $current = false;
        foreach (array('ttl_buckets', 'ttl_types', 'ttl_overrides',
            'ttl_default') as $key
        ) {
            if (isset($section[$key])) {
                $current = true;
            }
        }
        $buckets = self::BUCKET_DAYS;
        if (isset($section['ttl_buckets'])
            && is_array($section['ttl_buckets'])
        ) {
            foreach ($section['ttl_buckets'] as $name => $days) {
                if (!isset($buckets[$name]) || !is_numeric($days)
                    || (int)$days <= 0
                ) {
                    continue;
                }
                $buckets[$name] = (int)$days;
            }
        }

        $legacy = !$current && isset($section['ttl_days'])
            && is_array($section['ttl_days'])
            ? $section['ttl_days']
            : array();
        $default = null;
        if (array_key_exists('default', $legacy)
            && is_numeric($legacy['default'])
        ) {
            $default = (int)$legacy['default'];
        }
        unset($legacy['default']);
        if (isset($section['ttl_default'])
            && is_numeric($section['ttl_default'])
        ) {
            $default = (int)$section['ttl_default'];
        }
        if ($default === null || $default <= 0) {
            $default = self::DEFAULTS['ttl_default'];
        }

        $types = array();
        if (isset($section['ttl_types'])
            && is_array($section['ttl_types'])
        ) {
            foreach ($section['ttl_types'] as $type => $bucket) {
                if (!is_string($bucket) || !isset($buckets[$bucket])) {
                    continue;
                }
                $types[(string)$type] = $bucket;
            }
        }

        // The legacy map's named types become overrides, which is
        // exactly what they already meant.
        $overrides = array();
        foreach ($legacy as $type => $days) {
            if (!is_numeric($days) || (int)$days <= 0) {
                continue;
            }
            $overrides[(string)$type] = (int)$days;
        }
        if (isset($section['ttl_overrides'])
            && is_array($section['ttl_overrides'])
        ) {
            foreach ($section['ttl_overrides'] as $type => $days) {
                if (!is_numeric($days) || (int)$days <= 0) {
                    continue;
                }
                $overrides[(string)$type] = (int)$days;
            }
        }

        $effective = array();
        foreach ($types as $type => $bucket) {
            $effective[$type] = $buckets[$bucket];
        }
        foreach ($overrides as $type => $days) {
            $effective[$type] = $days;
        }

        return array(
            'ttl_buckets' => $buckets,
            'ttl_types' => $types,
            'ttl_overrides' => $overrides,
            'ttl_days' => $effective,
            'ttl_default' => $default,
        );
    }

    /**
     * Whole days between two stamps, measured between calendar days.
     *
     * The same rule `ValueStatsTool::agoPhrase` uses, and for the same
     * reason: a TTL is a number of days, so a clock that ticks over at
     * an arbitrary time of day would put a value on either side of its
     * own expiry depending on when the page was opened.
     *
     * @param int $from
     * @param int $to
     * @return int
     */
    public static function daysBetween($from, $to)
    {
        return (int)floor(
            (strtotime(date('Y-m-d', (int)$to))
                - strtotime(date('Y-m-d', (int)$from))) / 86400
        );
    }

    /**
     * @param array $context
     * @return array type => occurrences
     */
    private static function typeList(array $context)
    {
        $types = array();
        foreach (($context['types'] ?? array()) as $row) {
            $name = is_array($row)
                ? ($row['type'] ?? null)
                : $row;
            if ($name === null || $name === '') {
                continue;
            }
            $types[$name] = is_array($row)
                ? (int)($row['count'] ?? 0)
                : 0;
        }
        return $types;
    }

    /**
     * @param array $context
     * @return array
     */
    private static function orgRows(array $context)
    {
        return isset($context['orgs']) && is_array($context['orgs'])
            ? $context['orgs']
            : array();
    }

    /**
     * @param array $org
     * @return string
     */
    private static function orgLabel(array $org)
    {
        return isset($org['name']) && $org['name'] !== ''
            ? $org['name']
            : __('Unknown organisation');
    }
}
