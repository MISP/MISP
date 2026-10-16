<?php

/**
 * What an outside source thinks of an address, in a word.
 *
 * **The set of templates is a roster.** Most sources emit the generic
 * `reputation` template, but some verdict vendors still ship their own,
 * each with its own vocabulary — `classification` on one, a confidence
 * score on another. The key is still the object template and never the
 * module.
 *
 * ## The reading is here, and it is used twice
 *
 * A verdict is the only enrichment answer that can move a signal strength
 * number, and what it means has to be decided in exactly one place:
 * this renderer draws it and the enrichment signal scores it, and two
 * readings of one word is how a widget and a ledger row start
 * disagreeing about the same answer. `readingOf()` is that place. It
 * takes its thresholds as an argument rather than reading a profile,
 * because the renderer has no business knowing which profile is in
 * force and the signal cannot score without one.
 *
 * **`noise` alone is not a verdict.** GreyNoise saying a host is
 * scanning the internet is a statement about behaviour that the
 * `classification` field is the opinion about; counting the flag as
 * well would pay twice for one observation. `unknown` is likewise a
 * source saying it has no opinion, which is not an opinion.
 */
class ReputationRenderer extends ValueRendererBase
{
    public $id = 'reputation';

    public $templates = array(
        'greynoise-ip',
        'abuseipdb',
        'crowdsec-ip-context',
        'reputation',
    );

    public $compact = 'Values/Renderers/reputation_compact';

    public $full = 'Values/Renderers/reputation_full';

    public $eventUse = self::EVENT_EACH;

    const TOWARD_THREAT = 'threat';

    const TOWARD_BENIGN = 'benign';

    /**
     * The default thresholds the reading uses where a template states
     * a number instead of a word. Overridden by whatever the caller
     * passes; stated here so a widget drawn with no profile in hand
     * still reads the same way the ledger will.
     */
    const THRESHOLDS = array(
        'abuse_confidence_min' => 75,
    );

    /** Words that are a verdict, per template. */
    const MALICIOUS = array('malicious');

    const SUSPICIOUS = array('suspicious');

    const BENIGN = array('benign', 'safe', 'known', 'legitimate');

    public function __construct()
    {
        $this->description = __('What reputation services say about an'
            . ' address, and how sure they are.');
    }

    public function subjectWords()
    {
        return array_merge(parent::subjectWords(), array(
            'one' => __('address'),
            'many' => __('addresses'),
        ));
    }

    public function subjectsOf(array $object)
    {
        $address = $this->firstValue($object, array('ip-src', 'ip'));
        return $address === null ? array() : array($address);
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->verdictOf($object) !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $verdicts = array();
        foreach ($objects as $object) {
            $verdict = $this->verdictOf($object);
            if ($verdict === null) {
                continue;
            }
            $verdict['reading'] = self::readingOf(
                $verdict,
                self::THRESHOLDS
            );
            $verdicts[] = $verdict;
        }
        usort($verdicts, function ($a, $b) {
            return ($b['ran_at'] ?? 0) - ($a['ran_at'] ?? 0);
        });
        $threat = 0;
        $benign = 0;
        foreach ($verdicts as $verdict) {
            if ($verdict['reading'] === self::TOWARD_THREAT) {
                $threat++;
            } elseif ($verdict['reading'] === self::TOWARD_BENIGN) {
                $benign++;
            }
        }
        return array(
            'verdicts' => $verdicts,
            'headline' => empty($verdicts) ? null : $verdicts[0],
            'threat' => $threat,
            'benign' => $benign,
            /*
             * Two sources disagreeing is the thing a compact widget
             * must not average away: *malicious* and *benign* from two
             * services is a state a reader acts on differently from
             * either word on its own.
             */
            'split' => $threat > 0 && $benign > 0,
            'sources' => $this->sources($objects),
        );
    }

    /**
     * Which way one verdict points, or null where it points nowhere.
     *
     * Called by the widget with the defaults above and by the
     * enrichment signal with the profile's own thresholds, so that one
     * function decides what a word means on both surfaces.
     *
     * @param array $verdict A row from `prepare()`
     * @param array $thresholds
     * @return string|null `threat`, `benign`, or null
     */
    public static function readingOf(array $verdict, array $thresholds)
    {
        if (!empty($verdict['whitelisted'])) {
            return self::TOWARD_BENIGN;
        }
        /*
         * GreyNoise's RIOT set is *common business services somebody
         * will otherwise waste a morning on*, which is the strongest
         * benign statement that source makes, and it arrives beside a
         * classification rather than inside it.
         */
        if (!empty($verdict['riot'])) {
            return self::TOWARD_BENIGN;
        }
        $word = strtolower((string)($verdict['classification'] ?? ''));
        if ($word !== '') {
            if (in_array($word, self::MALICIOUS, true)
                || in_array($word, self::SUSPICIOUS, true)
            ) {
                return self::TOWARD_THREAT;
            }
            if (in_array($word, self::BENIGN, true)) {
                return self::TOWARD_BENIGN;
            }
        }
        $score = $verdict['score'] ?? null;
        if ($score !== null) {
            $min = isset($thresholds['abuse_confidence_min'])
                ? (float)$thresholds['abuse_confidence_min']
                : self::THRESHOLDS['abuse_confidence_min'];
            if ($score >= $min) {
                return self::TOWARD_THREAT;
            }
        }
        /*
         * Everything else — `unknown`, a score below the threshold, a
         * host that is only noisy — is a source with no opinion, and
         * absence of an outside opinion is not evidence.
         */
        return null;
    }

    /**
     * Whether this verdict is a half-strength one.
     *
     * `suspicious` is a source hedging, and the ledger pays it half
     * rather than either ignoring the hedge or treating it as
     * certainty.
     *
     * @param array $verdict
     * @return bool
     */
    public static function isHedged(array $verdict)
    {
        $word = strtolower((string)($verdict['classification'] ?? ''));
        return in_array($word, self::SUSPICIOUS, true);
    }

    /**
     * One object's verdict, in the shape both surfaces read, or null
     * where the object carries no opinion at all.
     *
     * @param array $object
     * @return array|null
     */
    private function verdictOf(array $object)
    {
        $name = $object['name'] ?? null;
        $verdict = array(
            'template' => $name,
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
            'classification' => null,
            'score' => null,
            'riot' => false,
            'whitelisted' => false,
            'detail' => array(),
            'link' => null,
        );
        if ($name === 'greynoise-ip') {
            $verdict['classification'] = $this->value(
                $object,
                'classification'
            );
            $verdict['riot'] = $this->flag($object, 'riot');
            $verdict['link'] = $this->value($object, 'link');
            $verdict['detail'] = $this->detail($object, array(
                'actor', 'noise', 'tor', 'vpn', 'bot',
                'source_country', 'trust-level', 'provider',
            ));
        } elseif ($name === 'abuseipdb') {
            $verdict['score'] = $this->number(
                $this->value($object, 'abuse-confidence-score')
            );
            $verdict['whitelisted'] = $this->flag(
                $object,
                'is-whitelisted'
            );
            if ($this->flag($object, 'is-malicious')) {
                $verdict['classification'] = 'malicious';
            }
            $verdict['detail'] = $this->detail($object, array(
                'is-public', 'is-tor',
            ));
        } elseif ($name === 'crowdsec-ip-context') {
            $verdict['classification'] = $this->value(
                $object,
                'reputation'
            );
            $verdict['detail'] = $this->detail($object, array(
                'as-name', 'country', 'behaviors', 'classifications',
                'attack-details', 'background-noise', 'scores',
            ));
        } else {
            /*
             * The generic template, whose whole point is that it says
             * these things under the names this function already uses.
             */
            $verdict['classification'] = $this->value(
                $object,
                'classification'
            );
            $verdict['score'] = $this->number(
                $this->value($object, 'score')
            );
            $verdict['link'] = $this->value($object, 'link');
            $verdict['detail'] = $this->detail($object, array(
                'source', 'list-name', 'first-seen', 'last-seen',
                'text',
            ));
        }
        $empty = $verdict['classification'] === null
            && $verdict['score'] === null
            && !$verdict['riot']
            && !$verdict['whitelisted'];
        return $empty ? null : $verdict;
    }

    /**
     * The relations worth showing under the verdict, as they came.
     *
     * @param array $object
     * @param array $relations
     * @return array
     */
    private function detail(array $object, array $relations)
    {
        $out = array();
        foreach ($relations as $relation) {
            $values = $this->values($object, $relation);
            if (!empty($values)) {
                $out[$relation] = $values;
            }
        }
        return $out;
    }
}
