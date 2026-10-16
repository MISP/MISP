<?php

/**
 * What a value signal is: a class that reads the value's aggregated
 * facts and returns one ledger row, or nothing.
 *
 * Signals are **discovered from the filesystem** rather than registered
 * anywhere in code. The shipped catalogue lives beside this file; an
 * instance admin drops their own in `app/Lib/ValueSignals/`, which no
 * upgrade touches. A dropped file changes no score until a profile
 * references its `id` — discovery makes a signal *available*, a
 * profile makes it *active*.
 *
 * **The profile owns the points, the implementation owns the
 * sentence.** An implementation never decides what a piece of evidence
 * is worth: it reads `$config['points']` for that. What it does own is
 * the prose — only the signal knows how to say *"47 sightings from 4
 * orgs, last 2 days ago"* — and the evidence line under it.
 *
 * **Points are declared threat-signed**, always: positive points mean
 * *this evidence points at a threat*. An implementation never sees the
 * lean and never flips its own sign. `ValueVerdictTool` multiplies by
 * the lean's polarity at assembly, which is what lets one declaration
 * render `+38` supporting a benign lean and `−38` disputing a threat
 * one.
 *
 * **And it multiplies only the rows that read the value** — the axis
 * below. A signal measuring *the record* rather than *the value* has
 * no side to take, so its declared points are already the right sign
 * for the only thing it can mean: more corroboration, more
 * publication, more precision is a better record whatever the record
 * says. Anchoring those would make four organisations corroborating a
 * value read as an argument against its benign lean, and the emptiest
 * record the best-scoring one.
 *
 * ## The row to return
 *
 * ```php
 * return array(
 *     'signal'       => __('4 independent organisations reported it'),
 *     'evidence'     => 'ORG-A, ORG-B, ORG-C, ORG-D',
 *     'contribution' => 28,          // threat-signed integer
 *     'tab'          => 'occurrences', // where the evidence is read
 *     'as_of'        => '2025-08-19',
 * );
 * ```
 *
 * `kind`, `axis` and `direction` are the engine's: the group comes
 * from the profile or from `$this->group`, the axis from `$this->axis`
 * unless the row names one, and the direction is the sign of the
 * anchored row.
 * `contribution` **must** be an integer — the engine rejects a float, a
 * string or an array, because the ledger summing exactly to its total
 * is the one thing that may not fail quietly.
 *
 * Return `null` to stay silent: evaluated, nothing to say, no row and no
 * note. Absence is only allowed to *fire* where the implementation
 * declares an `$absence_key` and the profile carries it in `points` —
 * *"no galaxy on any occurrence"* is a real signal, and a warninglist
 * that matched nothing is not.
 *
 * ## The context
 *
 * Built once per assessment and shared by every signal, already scoped
 * to the viewer. Keys, with the evidence class each belongs to:
 *
 * ```
 * value        string        the value itself
 * now          int           assembly time, unix seconds
 * as_of        'Y-m-d'       the date a row stamps with no better one
 * viewer       ['org_id']    whose page this is; 0 when unknown
 * types        [['type','count'], …]                     aggregate
 * occurrences  ['total','events','orgs','oldest','newest']  aggregate
 * orgs         [['id','name','occurrences','to_ids_yes',
 *                'to_ids_no','newest','newest_flagged',
 *                'oldest'], …]                            aggregate
 * publication  ['events','published','unpublished']       aggregate
 * activity     ['months' => ['2025-07' => 3, …], 'active_months',
 *               'span_months','longest_run','gaps']       aggregate
 * temporal     ['occurrences','with_first_seen']              row
 * sightings    ['total','fp','expiration','orgs','fp_orgs',
 *               'fp_org_names','first_stamp','last_stamp',
 *               'recent','recent_days','by_org_fp',
 *               'by_org_fp_last','anonymous_fp','anonymous_fp_last',
 *               'seen' => ['total','orgs','last_stamp','recent',
 *                          'by_org','by_org_last','anonymous']]  row
 * galaxies     ['clusters' => ['APT28' => 2],
 *               'techniques' => ['T1071.001' => 3]]              row
 * warninglist  ['hits' => [['name','category'], …],
 *               'lists_checked','category']              aggregate
 * feeds        ['count','names']                          aggregate
 * corroboration ['sightings_days','foreign_days'  day => report,
 *                 'last_sightings','last_foreign' int stamps,
 *                 'undecidable' int]                       aggregate
 * budget       ['window_days','hot','occurrences','threshold']
 * excluded     ['sightings' => int, …]  what exclusions removed
 * missing      ['sightings' => 'reason', …]  facts that could not be read
 * ```
 *
 * `excluded` is why absence keys check it: a sightings signal seeing
 * zero rows *because an exclusion emptied the set* is not seeing a value
 * nobody sighted. `missing` is how a fact that could not be read
 * reaches `not_counted` instead of being scored as absent — the engine
 * reads it against `$reads`.
 *
 * `corroboration` is the relevance axis's, and it is classed
 * **aggregate** although it is folded from rows — because the clock is
 * whole-history by declaration and does not see `evidence.window`. No
 * signal here reads it: relevance is its own axis and emits no ledger
 * row, so it is documented for the shape rather than offered as
 * evidence.
 */
abstract class ValueSignalBase
{
    /**
     * The loader's handshake, in the shape of its two in-tree
     * precedents — `WorkflowBaseModule` answers *The Factory Must Grow*
     * and a decaying-model formula *BONFIRE LIT*. A class that
     * subclasses this and overrides nothing else still answers it, so
     * what it actually proves is that the file's class was constructed
     * rather than merely defined.
     */
    const LOADED = 'SIGNAL ACQUIRED';

    /** Index aggregates: cheap at any cardinality, never windowed. */
    const EVIDENCE_AGGREGATE = 'aggregate';

    /** Row evidence: what the evidence window bounds, and what a hot
     *  value makes unreadable. */
    const EVIDENCE_ROW = 'row';

    /**
     * A row that **reads the value**: it states what the record says
     * this thing is, so it takes the lean's polarity and it is what
     * `ValueVerdictTool` weighs when it asks whether a record disputes
     * its own assertion.
     *
     * Three shipped signals declare it: the warninglist's hits,
     * false-positive sightings and enrichment verdicts. The `to_ids`
     * stance also reads the value, but it feeds the lean derivation
     * directly and is not a ledger row.
     */
    const AXIS_LEAN = 'lean';

    /**
     * A row that **weighs the record**: corroboration breadth, org
     * trust, attribution, published ratio, temporal precision. It takes
     * no polarity, because *how much record there is* is the same
     * question whatever the record concluded.
     *
     * The default, so a drop-in signal that declares nothing is
     * treated as the thing nearly every signal is.
     */
    const AXIS_SIGNAL_STRENGTH = 'signal_strength';

    /**
     * The ledger's groups. A profile may move a signal between them;
     * a custom signal may name one of its own.
     *
     * The first four name where inside MISP the evidence came from.
     * `Enrichment` is the fifth and names the one place it did not: an
     * outside source's opinion, which a reader weighs differently from
     * the record's own and which would be misfiled under any of the
     * four.
     */
    const GROUPS = array(
        'Reporting',
        'Sightings',
        'Attribution',
        'Lifecycle',
        'Enrichment',
    );

    /** The profile's key for this signal, e.g. `reporting.published_ratio`. */
    public $id = 'to-override';

    /** One of GROUPS, unless a custom signal names its own. */
    public $group = 'Reporting';

    /** One line, shown in the editor's palette. */
    public $description = 'to-override';

    /**
     * What the editor's "More info" popover says about this signal.
     *
     * `name`, `what`, `how`, an optional `note`, `settings` (key =>
     * what changing it does) and `recipes` (each a `want` and a `do`).
     * `{key}` in any of them is replaced by that setting's value. A
     * signal that declares none gets a popover built from its schema.
     */
    public $help = array();

    /**
     * The keys this signal reads from `points`, so the editor can
     * render a form for a signal it has never seen.
     *
     * `key => array('type' => 'int'|'float', 'label' => …,
     * 'default' => …)`. The one addition to Workflow's module shape,
     * and the thing that makes a drop-in configurable without
     * hand-edited JSON.
     */
    public $points_schema = array();

    /**
     * The keys this signal reads from `config` — its thresholds, in the
     * same shape as `points_schema`.
     *
     * `points` is what evidence is worth, `config` is the
     * implementation's non-points parameters — a TTL table, a window,
     * a threshold. The editor has to render both or a signal whose
     * threshold lives in `config` is configurable only by hand, which
     * is the half-usable drop-in `points_schema` exists to prevent —
     * so `config` gets a schema too.
     */
    public $config_schema = array();

    /**
     * The `points` key that fires on genuine absence, or null when
     * absence is silent.
     */
    public $absence_key = null;

    /**
     * What a reader could supply more of, so the falsifiability card
     * can say *"two more organisations reporting it"* instead of
     * *"14 more points"*.
     *
     * ```php
     * public $unit = array(
     *     'points' => 'per_org',   // the points key one unit is worth
     *     'cap' => 'cap',          // the key bounding the total
     *     'one' => …,              // the phrase for exactly one
     *     'many' => …,             // a %d format for more than one
     * );
     * ```
     *
     * Declared only where the points really are linear in the unit up
     * to the cap, because the arithmetic reading it is exact and a
     * signal with a saturation curve or a minimum-months gate would
     * make it quietly wrong. Null means *this signal has no unit a
     * reader can hand over*, and the card falls back to naming the
     * points gap — which is the honest answer for a signal whose
     * shape cannot be summarised in one.
     */
    public $unit = null;

    /** Which context keys this signal needs; the engine checks them
     *  against `$context['missing']`. */
    public $reads = array();

    /** EVIDENCE_AGGREGATE or EVIDENCE_ROW — declared so the evidence
     *  budget is enforceable rather than aspirational. */
    public $evidence_class = self::EVIDENCE_AGGREGATE;

    /**
     * AXIS_LEAN or AXIS_SIGNAL_STRENGTH — which axis this signal's rows
     * belong to, and therefore whether the engine anchors them.
     *
     * A signal whose poles are not all one axis overrides it per row:
     * `row()` takes an axis, and `lifecycle.warninglist` is the one
     * shipped signal that needs it — its hits read the value, its
     * *no hit* does not.
     */
    public $axis = self::AXIS_SIGNAL_STRENGTH;

    /**
     * Whether this signal's evidence is already counted as voices in
     * the lean's stance count.
     *
     * Its lean rows are still drawn, but they do not decide the
     * lean-disputed check: a voice weighed against the reporters once
     * must not get a second, unweighted say as a sum of points.
     *
     * A row carrying its own `voice` key overrides this for that row:
     * `enrichment.registration_age` keeps its weak tier out of the
     * check that way.
     */
    public $voice = false;

    /** The value-page tab a reader should go and argue with the row in. */
    public $tab = 'occurrences';

    public $version = 1;

    /** Set by the loader on anything found under `app/Lib/`. */
    public $is_custom = false;

    public function checkLoading()
    {
        return self::LOADED;
    }

    /**
     * The identity the loader hands the editor's palette.
     *
     * @return array
     */
    public function getConfig()
    {
        return array(
            'id' => $this->id,
            'group' => $this->group,
            'description' => $this->description,
            'help' => $this->help,
            'points_schema' => $this->points_schema,
            'config_schema' => $this->config_schema,
            'absence_key' => $this->absence_key,
            'unit' => $this->unit,
            'reads' => $this->reads,
            'evidence_class' => $this->evidence_class,
            'axis' => $this->axis,
            'tab' => $this->tab,
            'version' => $this->version,
            'is_custom' => $this->is_custom,
        );
    }

    /**
     * @param array $context The value's aggregated facts, ACL-scoped
     * @param array $config This signal's entry from `profile.signals`
     * @return array|null null = silent; otherwise a ledger row
     */
    abstract public function evaluate(array $context, array $config);

    /**
     * Whether a `points` map makes sense for this implementation.
     *
     * Per-implementation validation, derived from `points_schema` so
     * that an implementation declaring its keys gets it for free. An
     * unknown key is *not* an error: a profile written against a later
     * version of a signal has to survive a downgrade, and a missing
     * key is no worse than a missing signal, which is reported rather
     * than refused.
     *
     * @param array $points
     * @return array Error strings, empty when the map is usable
     */
    public function validatePoints(array $points)
    {
        return $this->checkMap($points, $this->points_schema, 'points');
    }

    /**
     * The same, for one whole profile entry — both maps at once, which
     * is what a caller validating a saved profile actually has.
     *
     * @param array $entry This signal's entry from `profile.signals`
     * @return array Error strings, empty when the entry is usable
     */
    public function validateEntry(array $entry)
    {
        return array_merge(
            $this->validatePoints(
                isset($entry['points']) && is_array($entry['points'])
                    ? $entry['points']
                    : array()
            ),
            $this->checkMap(
                isset($entry['config']) && is_array($entry['config'])
                    ? $entry['config']
                    : array(),
                $this->config_schema,
                'config'
            )
        );
    }

    /**
     * @param array $map
     * @param array $schema
     * @param string $label Which map the message should name
     * @return array
     */
    private function checkMap(array $map, array $schema, $label)
    {
        $errors = array();
        foreach ($schema as $key => $spec) {
            if (!array_key_exists($key, $map)) {
                continue;
            }
            $given = $map[$key];
            $type = isset($spec['type']) ? $spec['type'] : 'int';
            if ($type === 'int' && !is_int($given)) {
                $errors[] = sprintf(
                    __('%1$s: `%2$s.%3$s` must be a whole number.'),
                    $this->id,
                    $label,
                    $key
                );
            } elseif ($type === 'float'
                && !is_int($given) && !is_float($given)
            ) {
                $errors[] = sprintf(
                    __('%1$s: `%2$s.%3$s` must be a number.'),
                    $this->id,
                    $label,
                    $key
                );
            }
        }
        return $errors;
    }

    /**
     * One points value, falling back to the schema's default so that a
     * profile carrying half a map still scores.
     *
     * @param array $config This signal's profile entry
     * @param string $key
     * @param int|float|null $fallback Used when the schema has no default
     * @return int|float|null
     */
    protected function points(array $config, $key, $fallback = null)
    {
        if (isset($config['points'])
            && array_key_exists($key, $config['points'])
            && is_numeric($config['points'][$key])
        ) {
            return $config['points'][$key];
        }
        if (isset($this->points_schema[$key]['default'])) {
            return $this->points_schema[$key]['default'];
        }
        return $fallback;
    }

    /**
     * One threshold, from `config`, falling back to the schema's
     * default. `points()`'s sibling, for the half of a signal's
     * parameters that are not worth anything on their own.
     *
     * @param array $config This signal's profile entry
     * @param string $key
     * @param int|float|null $fallback
     * @return int|float|null
     */
    protected function setting(array $config, $key, $fallback = null)
    {
        if (isset($config['config'])
            && array_key_exists($key, $config['config'])
            && is_numeric($config['config'][$key])
        ) {
            return $config['config'][$key];
        }
        if (isset($this->config_schema[$key]['default'])) {
            return $this->config_schema[$key]['default'];
        }
        return $fallback;
    }

    /**
     * Whether the profile asked this signal to fire on absence.
     *
     * The implementation has an absence key, the profile carries it,
     * **and** no exclusion
     * emptied the input set. A signal whose evidence was excluded stays
     * silent and lets the exclusion's own `not_counted` entry do the
     * explaining.
     *
     * @param array $config
     * @param array $context
     * @param string|null $excludedKey Which `excluded` tally guards it
     * @return bool
     */
    protected function absenceFires(array $config, array $context,
        $excludedKey = null
    ) {
        if ($this->absence_key === null) {
            return false;
        }
        if (!isset($config['points'])
            || !array_key_exists($this->absence_key, $config['points'])
        ) {
            return false;
        }
        if ($excludedKey !== null
            && !empty($context['excluded'][$excludedKey])
        ) {
            return false;
        }
        return true;
    }

    /**
     * A ledger row, with the fields every implementation would
     * otherwise repeat.
     *
     * @param int|float $contribution Threat-signed; rounded here, so an
     *                                implementation may compute in
     *                                fractions and still satisfy the
     *                                integer invariant
     * @param string $signal The claim, in prose
     * @param string $evidence The line under it
     * @param string|null $asOf Defaults to the context's own date
     * @param array $context
     * @return array
     */
    protected function row($contribution, $signal, $evidence,
        array $context, $asOf = null, $axis = null
    ) {
        return array(
            'signal' => $signal,
            'evidence' => $evidence,
            'contribution' => (int)round($contribution),
            'tab' => $this->tab,
            'as_of' => $asOf === null
                ? ($context['as_of'] ?? date('Y-m-d'))
                : $asOf,
            /*
             * The class's axis unless this row is the exception. Stated
             * on the row rather than looked up later because the engine
             * must not have to know which pole an implementation took —
             * that is exactly the kind of knowledge a drop-in signal
             * cannot hand over.
             */
            'axis' => $axis === null ? $this->axis : $axis,
        );
    }

    /**
     * A unix stamp as the ledger's date, or the context's date when
     * there is none — a row with no `as_of` reads as undated rather
     * than as today.
     *
     * @param int|null $stamp
     * @param array $context
     * @return string
     */
    protected function stampAsOf($stamp, array $context)
    {
        return empty($stamp)
            ? ($context['as_of'] ?? date('Y-m-d'))
            : date('Y-m-d', (int)$stamp);
    }

    /**
     * An age in days, as a ledger row says it.
     *
     * `ValueStatsTool::agoPhrase()` does this from a stamp for the
     * sightings panel; this is the days-in version, on the base class
     * so that every signal — including a dropped-in one — words an age
     * the same way as the rest of the page. A row reading *"last 63
     * days ago"* beside one reading *"2 months ago"* is the page
     * disagreeing with itself in the same column.
     *
     * @param int $days
     * @return string
     */
    protected function agoPhrase($days)
    {
        $days = (int)$days;
        if ($days <= 0) {
            return __('today');
        }
        if ($days === 1) {
            return __('yesterday');
        }
        if ($days < 60) {
            return sprintf(__('%d days ago'), $days);
        }
        $months = (int)round($days / 30);
        if ($months < 24) {
            return sprintf(__('%d months ago'), $months);
        }
        return sprintf(__('%d years ago'), (int)round($days / 365));
    }

    /**
     * `min` against a cap that may be either sign, so an
     * implementation does not have to branch on it.
     *
     * A cap of `28` bounds `+35` to `+28`; a cap of `-26` bounds `-30`
     * to `-26`. A cap of 0 means uncapped, because a signal whose
     * profile entry omits the cap should still score.
     *
     * @param int|float $points
     * @param int|float|null $cap
     * @return int|float
     */
    protected function capped($points, $cap)
    {
        if ($cap === null || $cap == 0) {
            return $points;
        }
        return $cap > 0
            ? min($points, $cap)
            : max($points, $cap);
    }
}
