<?php

/**
 * What outside sources said about this value, and how far the profile
 * believes them.
 *
 * The first signal that scores something MISP did not record itself.
 * Every other one reads MISP's own tables — who filed it, how often,
 * how long ago, what they tagged it — and the number that comes out is
 * a statement about the record. This one reads the enrichment store:
 * an opinion a third party gave when somebody pressed Run.
 *
 * ## It reads the store and never queries
 *
 * A signal that fired an HTTP request during scoring would be a signal
 * whose value depends on a third party's uptime, and a score that
 * moved because a vendor was slow is not reproducible. Firing is the
 * page's job and happens outside the engine; what arrives here is the
 * shaped answers already held, so the number is a pure function of
 * what the store contains. The clock affects when the page settles,
 * never what it says.
 *
 * ## One row per module
 *
 * *GreyNoise · malicious · asked 3 h ago · +12* — and the reader can
 * open the run behind that row and see the answer that produced it,
 * which is the ledger's existing invariant applied to a new source.
 * One row summing three vendors would be a number nobody could check.
 *
 * ## Only verdict-bearing shapes score
 *
 * A trust grade says how far to believe a source. It does not say what
 * the answer means — and the engine's whole contract is that a signal
 * declares points *toward or away from threat*. A geolocation, an
 * autonomous system, a certificate or a registration record has no
 * such reading: where an address sits is context. It is drawn in the
 * strip and never scored.
 *
 * Three shapes carry a verdict, and **the reading lives in their
 * renderers rather than here**: `ReputationRenderer::readingOf()` and
 * `FileVerdictRenderer::readingOf()` decide what `malicious`, `riot`
 * and `0/3` mean, and the widget on the Overview asks the same two
 * functions. Written again in this file it would be two readings of
 * one answer, which is how a widget and a ledger row start disagreeing
 * about the same thing.
 *
 * ## Ungraded is zero, and the row says so
 *
 * The shipped default grades no module, so on a stock instance these
 * rows appear in the ledger **marked as not counted**, with the reason.
 * The reader sees what outside sources said, sees that it moved
 * nothing, and grading a module in their profile is the single act
 * that turns it on. A shipped fallback grade would have the neutral
 * document asserting that some particular vendor is worth twelve
 * points.
 *
 * ## Two windows, two jobs
 *
 * The store's own reuse window decides when a run is stale enough to
 * ask *again*; this signal's `window_hours` decides when a stored
 * answer stops *counting*. They are different questions and a profile
 * sets them separately: a fraud analyst and a disinformation
 * researcher disagree about how long an answer stays true, and neither
 * disagrees per vendor. A row past the window stays in the ledger,
 * not counted, with its age — the reader sees that somebody asked and
 * that the answer has expired, and a press refreshes it.
 *
 * ## An empty answer is not an opinion
 *
 * A module that ran and found nothing produces no row. Absence of an
 * outside opinion is what the eleven shipped signals already measure
 * from MISP's own tables; counting it again here would pay twice for
 * one silence.
 */
class EnrichmentAnswer extends ValueSignalBase
{
    public $id = 'enrichment.answer';

    /**
     * A fifth group. The four shipped ones name where the evidence
     * came from inside MISP, and this evidence came from outside it —
     * folding it into `Lifecycle` or `Attribution` would put a
     * vendor's opinion under a heading that promises the record's own.
     */
    public $group = 'Enrichment';

    /**
     * An aggregate: one indexed read of one table per value, whatever
     * the value's size. The hot-value tier bounds row evidence, and a
     * value MISP flags as over-correlating has no more enrichment runs
     * than a quiet one.
     */
    public $evidence_class = self::EVIDENCE_AGGREGATE;

    /**
     * A verdict reads **the value** — it states what somebody thinks
     * this thing is — so it takes the lean's polarity, the same way a
     * warninglist category and a false-positive sighting do. It is not
     * a statement about how well documented the record is.
     */
    public $axis = self::AXIS_LEAN;

    // Each counted verdict is a voice in the stance count.
    public $voice = true;

    public $reads = array('enrichment');

    public $tab = 'enrichment';

    public function __construct()
    {
        $this->description = __(
            'Verdicts from enrichment modules such as reputation services'
            . ' and antivirus scans. Only modules you have graded count.'
        );
        $this->help = array(
            'name' => __('Enrichment verdicts'),
            'what' => __(
                'When somebody runs an enrichment module, some answers carry'
                . ' a verdict: malicious, suspicious, clean, a detection'
                . ' count. A verdict counts at its module\'s grade, and'
                . ' "suspicious" at half of it. An ungraded module is shown'
                . ' and never counted, and an answer stops counting once it'
                . ' is older than the window.'
            ),
            'how' => __(
                'Each verdict is drawn as {per_verdict} points times the'
                . ' module\'s grade, {cap} at most, in the lean evidence. A'
                . ' verdict agreeing with the reading adds {per_agreeing}'
                . ' times the grade to the signal strength, {agreeing_cap}'
                . ' at most. Answers count for {window_hours} hours.'
            ),
            'note' => __(
                'Only the agreeing points reach the signal strength. Every'
                . ' counted verdict is already a vote in the lean, so'
                . ' per_verdict and cap only size its rows. Grade modules'
                . ' under Sources & reputation → Enrichment module'
                . ' reputation.'
            ),
            'settings' => array(
                'per_verdict' => __(
                    'How large one verdict is drawn in the lean evidence.'
                ),
                'cap' => __('The most all verdicts together are drawn'
                    . ' as.'),
                'per_agreeing' => __(
                    'What an outside source confirming the reporters adds'
                    . ' to the signal strength: the one way a single-source'
                    . ' record gains strength from outside MISP.'
                ),
                'agreeing_cap' => __(
                    'The most agreeing verdicts can add.'
                ),
                'window_hours' => __(
                    'How long an answer keeps counting after it was asked.'
                    . ' 168 is a week.'
                ),
                'abuse_confidence_min' => __(
                    'A reputation score (e.g. AbuseIPDB\'s confidence) at'
                    . ' or above which an answer reads as malicious.'
                ),
                'malicious_ratio' => __(
                    'How many antivirus engines must detect a file for it'
                    . ' to read as malicious.'
                ),
                'benign_engines' => __(
                    'How many engines must have answered before zero'
                    . ' detections reads as clean.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('An outside verdict should count at all'),
                    'do' => __('Grade its module under Sources &'
                        . ' reputation: an ungraded module never'
                        . ' counts.'),
                ),
                array(
                    'want' => __('An outside confirmation should'
                        . ' strengthen a thin record more'),
                    'do' => __('Raise per_agreeing to 12 and agreeing_cap'
                        . ' to 24.'),
                ),
                array(
                    'want' => __('Answers should count for a month'),
                    'do' => __('Raise window_hours to 720.'),
                ),
                array(
                    'want' => __('Fewer detections should read as'
                        . ' malicious'),
                    'do' => __('Lower malicious_ratio, e.g. to 3.'),
                ),
            ),
        );
        $this->points_schema = array(
            'per_verdict' => array(
                'type' => 'int',
                'default' => 12,
                'label' => __('Points per verdict, before the'
                    . ' module\'s grade'),
            ),
            'cap' => array(
                'type' => 'int',
                'default' => 24,
                'label' => __('Most this signal may contribute, across'
                    . ' every module'),
            ),
            'per_agreeing' => array(
                'type' => 'int',
                'default' => 6,
                'label' => __('Signal-strength points per verdict agreeing'
                    . ' with the reporters, before the module\'s grade'),
            ),
            'agreeing_cap' => array(
                'type' => 'int',
                'default' => 12,
                'label' => __('Most the agreeing verdicts may add to the'
                    . ' signal strength'),
            ),
        );
        $this->config_schema = array(
            'window_hours' => array(
                'type' => 'int',
                'default' => 168,
                'label' => __('Stop counting an answer after'),
            ),
            'abuse_confidence_min' => array(
                'type' => 'int',
                'default' => 75,
                'label' => __('Confidence score that reads as'
                    . ' malicious'),
            ),
            'malicious_ratio' => array(
                'type' => 'int',
                'default' => 5,
                'label' => __('Detections that read as malicious'),
            ),
            'benign_engines' => array(
                'type' => 'int',
                'default' => 40,
                'label' => __('Engines that must answer before zero'
                    . ' detections reads as clean'),
            ),
        );
        /*
         * No `unit`. What a reader could supply more of here is *a
         * module that has not been asked*, and the points that would
         * arrive depend on which verdict it gives and what grade the
         * profile puts on it — neither of which is knowable before the
         * run. The falsifiability card naming the points gap is the
         * honest answer for a signal whose next unit has no fixed
         * worth.
         */
    }

    /**
     * Rows and set-aside notes, rather than one row.
     *
     * @param array $context
     * @param array $config
     * @return array|null
     */
    public function evaluate(array $context, array $config)
    {
        $read = $this->counted($context, $config);
        if ($read === null) {
            return null;
        }
        $per = $this->points($config, 'per_verdict');
        $now = isset($context['now']) ? (int)$context['now'] : time();
        $rows = array();
        $notes = $read['not_counted'];
        foreach ($read['counted'] as $verdict) {
            $points = $per * $verdict['weight'];
            if ($verdict['reading'] === ReputationRenderer::TOWARD_BENIGN) {
                $points = -$points;
            }
            $age = max(0, $now - (int)$verdict['ran_at']);
            $rows[] = $this->row(
                $points,
                sprintf(
                    __('%1$s · %2$s'),
                    $verdict['module'],
                    $verdict['word']
                ),
                sprintf(
                    __('asked %1$s · %2$s'),
                    $this->agoPhrase((int)floor($age / 86400)),
                    sprintf(
                        __('graded %s'),
                        $verdict['grade'] === null
                            ? '?'
                            : $verdict['grade']
                    )
                ),
                $context,
                $this->stampAsOf((int)$verdict['ran_at'], $context)
            );
        }

        /*
         * The cap is across every module and is applied after the
         * rows are built, so it has to come off them rather than out
         * of the total — the ledger sums its printed rows exactly, and
         * a cap subtracted anywhere else would make the column and the
         * number disagree.
         */
        $rows = $this->applyCap($rows, $this->points($config, 'cap'));
        $rows = array_merge($rows, $this->applyCap(
            $this->agreeing($read['counted'], $config, $context),
            $this->points($config, 'agreeing_cap')
        ));

        if (empty($rows) && empty($notes)) {
            return null;
        }
        return array('rows' => $rows, 'not_counted' => $notes);
    }

    /**
     * The graded, in-window verdicts, and a note for every one set
     * aside.
     *
     * The one reading both halves of the signal share: the ledger
     * rows above, and the voices the lean counts (`voices()`). Two
     * filters would be two answers to *which verdicts count*.
     *
     * @param array $context
     * @param array $config
     * @return array|null `counted` (each verdict plus `module`,
     *                    `grade`, `factor`, `weight`) and
     *                    `not_counted`, or null with nothing held
     */
    private function counted(array $context, array $config)
    {
        $held = isset($context['enrichment']['runs'])
            && is_array($context['enrichment']['runs'])
            ? $context['enrichment']['runs']
            : array();
        if (empty($held)) {
            return null;
        }
        $trust = isset($context['enrichment']['trust'])
            && is_array($context['enrichment']['trust'])
            ? $context['enrichment']['trust']
            : array();
        $thresholds = array(
            'abuse_confidence_min' => $this->setting(
                $config,
                'abuse_confidence_min'
            ),
            'malicious_ratio' => $this->setting(
                $config,
                'malicious_ratio'
            ),
            'benign_engines' => $this->setting(
                $config,
                'benign_engines'
            ),
        );
        $window = (int)$this->setting($config, 'window_hours');
        $now = isset($context['now']) ? (int)$context['now'] : time();

        $counted = array();
        $notes = array();
        foreach ($this->verdictsIn($held, $thresholds) as $verdict) {
            $age = max(0, $now - (int)$verdict['ran_at']);
            $module = (string)$verdict['module'];
            /*
             * Two refusals before the arithmetic, and each keeps its
             * row on the page rather than dropping it. A reader who
             * can see *what was said* and *why it did not count* can
             * act on both; a row silently missing looks like a module
             * that was never asked.
             */
            if ($window > 0 && $age > $window * 3600) {
                $notes[] = $this->aside($module, $verdict, sprintf(
                    __('Asked %1$s, which is past this profile\'s %2$s'
                        . '-hour window, so it no longer counts.'),
                    $this->agoPhrase((int)floor($age / 86400)),
                    $window
                ));
                continue;
            }
            $factor = isset($trust['factors'][$module])
                ? (float)$trust['factors'][$module]
                : 0.0;
            if ($factor <= 0.0) {
                $notes[] = $this->aside($module, $verdict, __(
                    'Your profile has not graded this module, so its'
                    . ' answer is shown and not counted. Grade it under'
                    . ' Sources & reputation to have it count.'
                ));
                continue;
            }
            /*
             * A source hedging is paid half rather than ignored or
             * believed outright — the one place the reading table
             * distinguishes *suspicious* from *malicious*.
             */
            $weight = ReputationRenderer::isHedged($verdict)
                ? $factor / 2
                : $factor;
            $counted[] = $verdict + array(
                'module' => $module,
                'grade' => isset($trust['grades'][$module])
                    ? $trust['grades'][$module]
                    : null,
                'factor' => $factor,
                'weight' => $weight,
            );
        }
        return array('counted' => $counted, 'not_counted' => $notes);
    }

    /**
     * A signal-strength row for each counted verdict agreeing with the lean:
     * an outside source confirming what the reporters assert is
     * the one corroboration a single-source record can get from
     * outside MISP. A verdict disagreeing adds no signal strength — it is a
     * voice against the lean, and that is weighed in the stance count.
     *
     * @param array $counted From `counted()`
     * @param array $config
     * @param array $context Carrying the `lean` the engine anchored to
     * @return array
     */
    private function agreeing(array $counted, array $config,
        array $context
    ) {
        $lean = isset($context['lean']) ? $context['lean'] : null;
        if ($lean !== 'threat' && $lean !== 'benign') {
            return array();
        }
        $per = $this->points($config, 'per_agreeing');
        $rows = array();
        foreach ($counted as $verdict) {
            if ($verdict['reading'] !== $lean) {
                continue;
            }
            $rows[] = $this->row(
                $per * $verdict['weight'],
                sprintf(
                    __('%1$s agrees · %2$s'),
                    $verdict['module'],
                    $verdict['word']
                ),
                sprintf(
                    __('an outside source confirming the reporters ·'
                        . ' graded %s'),
                    $verdict['grade'] === null ? '?' : $verdict['grade']
                ),
                $context,
                $this->stampAsOf((int)$verdict['ran_at'], $context),
                self::AXIS_SIGNAL_STRENGTH
            );
        }
        return $rows;
    }

    /**
     * The verdicts the lean counts as voices: each graded,
     * in-window verdict at its module's weight, on the side it argues.
     *
     * Public because the lean is decided before any signal scores,
     * and it has to read the same verdicts the ledger will print.
     *
     * @param array $context
     * @param array $config The signal's profile entry
     * @return array `module`, `grade`, `word`, `side` (`threat` or
     *               `benign`), `weight`, `ran_at`
     */
    public function voices(array $context, array $config)
    {
        $read = $this->counted($context, $config);
        if ($read === null) {
            return array();
        }
        $voices = array();
        foreach ($read['counted'] as $verdict) {
            $voices[] = array(
                'module' => $verdict['module'],
                'grade' => $verdict['grade'],
                'word' => $verdict['word'],
                'side' => $verdict['reading']
                    === ReputationRenderer::TOWARD_BENIGN
                    ? 'benign'
                    : 'threat',
                'weight' => $verdict['weight'],
                'ran_at' => (int)$verdict['ran_at'],
            );
        }
        return $voices;
    }

    /**
     * Every verdict the held answers carry, one per module.
     *
     * The extraction is the renderers' — each one already turns a set
     * of objects into the fields a verdict has, and asking them here
     * is what stops this file and the widget reading one answer two
     * ways.
     *
     * @param array $runs Shaped runs carrying `module` and `ran_at`
     * @param array $thresholds
     * @return array
     */
    private function verdictsIn(array $runs, array $thresholds)
    {
        $drawn = ValueRendererTool::drawFor($runs);
        $out = array();
        foreach (array('reputation', 'known-good', 'file-verdict')
            as $shape
        ) {
            if (!isset($drawn[$shape])) {
                continue;
            }
            $data = $drawn[$shape]['data'];
            if ($shape === 'reputation') {
                foreach ($data['verdicts'] as $verdict) {
                    $reading = ReputationRenderer::readingOf(
                        $verdict,
                        $thresholds
                    );
                    if ($reading === null) {
                        continue;
                    }
                    $out[] = $verdict + array(
                        'reading' => $reading,
                        'word' => $this->wordFor($verdict, $reading),
                    );
                }
                continue;
            }
            if ($shape === 'file-verdict') {
                foreach ($data['reports'] as $report) {
                    $reading = FileVerdictRenderer::readingOf(
                        $report,
                        $thresholds
                    );
                    if ($reading === null) {
                        continue;
                    }
                    $out[] = $report + array(
                        'reading' => $reading,
                        'word' => $report['ratio'],
                        'classification' => null,
                    );
                }
                continue;
            }
            foreach ($data['records'] as $record) {
                /*
                 * A known-good record's reading is its own presence:
                 * a hash a vendor shipped argues against a threat, and
                 * the same service saying *known malicious* argues for
                 * one. There is no middle, which is why this shape
                 * needs no threshold.
                 */
                $out[] = $record + array(
                    'reading' => $record['malicious'] === null
                        ? ReputationRenderer::TOWARD_BENIGN
                        : ReputationRenderer::TOWARD_THREAT,
                    'word' => $record['malicious'] === null
                        ? __('known good')
                        : __('known bad'),
                    'classification' => null,
                );
            }
        }
        return $out;
    }

    /**
     * What a verdict is called on its row.
     *
     * @param array $verdict
     * @param string $reading
     * @return string
     */
    private function wordFor(array $verdict, $reading)
    {
        if (!empty($verdict['classification'])) {
            return (string)$verdict['classification'];
        }
        if (isset($verdict['score']) && $verdict['score'] !== null) {
            return sprintf(__('%d%% confidence'), (int)$verdict['score']);
        }
        if (!empty($verdict['riot'])) {
            return __('known service');
        }
        return $reading === ReputationRenderer::TOWARD_BENIGN
            ? __('whitelisted')
            : __('listed');
    }

    /**
     * A row that stays on the page and out of the sum.
     *
     * @param string $module
     * @param array $verdict
     * @param string $why
     * @return array
     */
    private function aside($module, array $verdict, $why)
    {
        return array(
            'title' => sprintf(
                __('%1$s · %2$s'),
                $module,
                $verdict['word']
            ),
            'note' => $why,
            /*
             * `policy` rather than `nodata`: nothing failed and
             * nothing is missing. The profile decided, and a reader
             * who wants the row counted knows where to go.
             */
            'reason' => 'policy',
            'kind' => 'ungraded',
            'source' => 'enrichment',
            'id' => $this->id,
        );
    }

    /**
     * The cap, taken off the rows themselves.
     *
     * Applied from the smallest row up, so the module that said the
     * most keeps the most of what it said: a cap that shaved the
     * largest row first would make the biggest verdict on the page
     * look like the weakest one.
     *
     * @param array $rows
     * @param int|float|null $cap
     * @return array
     */
    private function applyCap(array $rows, $cap)
    {
        if ($cap === null || $cap == 0 || empty($rows)) {
            return $rows;
        }
        $cap = abs((int)$cap);
        foreach (array(1, -1) as $sign) {
            $total = 0;
            $indices = array();
            foreach ($rows as $i => $row) {
                if (($row['contribution'] > 0 ? 1 : -1) !== $sign
                    || $row['contribution'] === 0
                ) {
                    continue;
                }
                $total += abs($row['contribution']);
                $indices[] = $i;
            }
            if ($total <= $cap || empty($indices)) {
                continue;
            }
            usort($indices, function ($a, $b) use ($rows) {
                return abs($rows[$a]['contribution'])
                    - abs($rows[$b]['contribution']);
            });
            $left = $cap;
            $remaining = count($indices);
            foreach ($indices as $i) {
                $share = (int)floor($left / $remaining);
                $keep = min(abs($rows[$i]['contribution']), $share);
                $rows[$i]['contribution'] = $sign * $keep;
                $left -= $keep;
                $remaining--;
            }
        }
        return $rows;
    }
}
