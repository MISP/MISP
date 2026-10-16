<?php

/**
 * How a prefix ranks against every other prefix announced.
 *
 * **Nothing emits this**, and unlike the other three in that state the
 * service exists and is public — there is simply no module wrapping
 * it. A ranking is the one reputation statement on this page that is
 * about the neighbourhood rather than about the address, which is what
 * makes it worth a widget of its own rather than a row in the
 * reputation one.
 *
 * **A rank means nothing without the size of the field it is a rank
 * in.** Position 412 is excellent or unremarkable depending on how
 * many prefixes were ranked, so the percentile is computed here where
 * both numbers are in hand, and a rank arriving without a total is
 * drawn as a position and never as a judgement.
 */
class PrefixReputationRenderer extends ValueRendererBase
{
    public $id = 'prefix-reputation';

    public $templates = array('bgp-ranking', 'bgp-hijack');

    public $compact = 'Values/Renderers/prefix_reputation_compact';

    public $full = 'Values/Renderers/prefix_reputation_full';

    public $eventUse = self::EVENT_SET;

    public $producer = self::PRODUCER_NONE;

    public function __construct()
    {
        $this->description = __('How a prefix ranks, and whether it'
            . ' has been announced by somebody else.');
        $this->producer_note = __('No module wraps a prefix ranking'
            . ' service yet.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->rankOf($object) !== null
                || $this->hijackOf($object) !== null
            ) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $ranks = array();
        $hijacks = array();
        foreach ($objects as $object) {
            $rank = $this->rankOf($object);
            if ($rank !== null) {
                $ranks[] = $rank;
            }
            $hijack = $this->hijackOf($object);
            if ($hijack !== null) {
                $hijacks[] = $hijack;
            }
        }
        usort($ranks, function ($a, $b) {
            return ($b['at'] ?? 0) - ($a['at'] ?? 0);
        });
        return array(
            'ranks' => $ranks,
            'headline' => empty($ranks) ? null : $ranks[0],
            'hijacks' => $hijacks,
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function rankOf(array $object)
    {
        if (($object['name'] ?? null) !== 'bgp-ranking') {
            return null;
        }
        $position = $this->number($this->value($object, 'position'));
        $ranking = $this->number($this->value($object, 'ranking'));
        if ($position === null && $ranking === null) {
            return null;
        }
        return array(
            'position' => $position === null ? null : (int)$position,
            'ranking' => $ranking,
            'family' => $this->value($object, 'address-family'),
            'at' => $this->stamp($this->value($object, 'date')),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function hijackOf(array $object)
    {
        if (($object['name'] ?? null) !== 'bgp-hijack') {
            return null;
        }
        $prefix = $this->value($object, 'subnet-announced');
        $detected = $this->value($object, 'detected-asn');
        if ($prefix === null && $detected === null) {
            return null;
        }
        return array(
            'prefix' => $prefix,
            'detected_asn' => $detected,
            'expected_asn' => $this->value($object, 'expected-asn'),
            'country' => $this->value($object, 'country'),
            'description' => $this->value($object, 'description'),
            'start' => $this->stamp($this->value($object, 'start')),
            'end' => $this->stamp($this->value($object, 'end')),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }
}
