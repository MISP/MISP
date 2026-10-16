<?php

/**
 * Who announces an address, and over what.
 *
 * The `asn` template leads with `last-seen` and the fact a reader came
 * for is `asn`, two relations later — which is why the chips this
 * replaces read so badly on it, and why nothing here reads *the first
 * relation of the object*.
 *
 * **`subnet-announced` repeats.** One object carries one prefix per
 * announcement, so a read that took the first value would draw a
 * single prefix and quietly assert it was the whole of what the holder
 * announces.
 */
class NetworkOwnershipRenderer extends ValueRendererBase
{
    public $id = 'network-ownership';

    public $templates = array('asn');

    public $compact = 'Values/Renderers/network_ownership_compact';

    public $full = 'Values/Renderers/network_ownership_full';

    public $eventUse = self::EVENT_SET;

    /** Who holds it, in the order the templates prefer to say it. */
    const HOLDER = array('description', 'organization', 'name');

    public function __construct()
    {
        $this->description = __('The autonomous system an address is'
            . ' announced from, and its prefixes.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->value($object, 'asn') !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $systems = array();
        foreach ($objects as $object) {
            $asn = $this->value($object, 'asn');
            if ($asn === null) {
                continue;
            }
            $asn = $this->normaliseAsn($asn);
            $prefixes = $this->values($object, 'subnet-announced');
            if (!isset($systems[$asn])) {
                $systems[$asn] = array(
                    'asn' => $asn,
                    'holder' => $this->firstValue($object, self::HOLDER),
                    'country' => $this->value($object, 'country'),
                    'prefixes' => array(),
                    'first' => $this->stamp(
                        $this->value($object, 'first-seen')
                    ),
                    'last' => $this->stamp(
                        $this->value($object, 'last-seen')
                    ),
                    'sources' => array(),
                );
            }
            foreach ($prefixes as $prefix) {
                if (!in_array($prefix, $systems[$asn]['prefixes'],
                    true)
                ) {
                    $systems[$asn]['prefixes'][] = $prefix;
                }
            }
            $module = $object['module'] ?? null;
            if ($module !== null
                && !in_array($module, $systems[$asn]['sources'], true)
            ) {
                $systems[$asn]['sources'][] = $module;
            }
            /*
             * A second source that knows the holder fills a gap the
             * first left; it never overwrites an answer, because two
             * sources disagreeing about who holds an AS is a fact the
             * full form shows rather than one the compact form picks a
             * winner in.
             */
            foreach (array('holder', 'country') as $field) {
                if ($systems[$asn][$field] === null) {
                    $systems[$asn][$field] = $field === 'holder'
                        ? $this->firstValue($object, self::HOLDER)
                        : $this->value($object, 'country');
                }
            }
        }
        $newest = $this->newest($objects);
        $headline = null;
        if ($newest !== null) {
            $asn = $this->value($newest, 'asn');
            $asn = $asn === null ? null : $this->normaliseAsn($asn);
            $headline = $asn !== null && isset($systems[$asn])
                ? $systems[$asn]
                : reset($systems);
        }
        return array(
            'systems' => array_values($systems),
            'headline' => $headline === false ? null : $headline,
            'sources' => $this->sources($objects),
        );
    }

    /**
     * `AS15169` and `15169` are the same autonomous system, and two
     * modules spell it both ways — so without this the compact form
     * would draw one AS twice and call it two.
     *
     * @param string $asn
     * @return string
     */
    private function normaliseAsn($asn)
    {
        $asn = trim($asn);
        if (stripos($asn, 'AS') === 0 && ctype_digit(substr($asn, 2))) {
            return 'AS' . substr($asn, 2);
        }
        return ctype_digit($asn) ? 'AS' . $asn : $asn;
    }
}
