<?php

/**
 * Whether a file is one somebody shipped on purpose.
 *
 * A hash that belongs to a distribution package is the cheapest
 * dismissal an analyst has, and it is the one answer on this page that
 * argues *against* a threat rather than for one — which is why it is
 * one of the three shapes that reach the ledger.
 *
 * **`KnownMalicious` inverts it.** The same service that knows a hash
 * is part of a package also carries the ones known to be otherwise,
 * and a widget that read only the presence of a row would draw a
 * known-bad file as a known-good one.
 */
class KnownGoodRenderer extends ValueRendererBase
{
    public $id = 'known-good';

    public $templates = array('hashlookup');

    public $compact = 'Values/Renderers/known_good_compact';

    public $full = 'Values/Renderers/known_good_full';

    public $eventUse = self::EVENT_EACH;

    /** What the file is called, in the order the service says it. */
    const NAMES = array('FileName', 'PackageName');

    /** Everything worth listing in the full form, in reading order. */
    const FIELDS = array(
        'FileName', 'FileSize', 'PackageName', 'PackageVersion',
        'PackageRelease', 'PackageArch', 'PackageMaintainer',
        'PackageDescription', 'MD5', 'SHA-1', 'SHA-256', 'SSDEEP',
        'TLSH', 'KnownMalicious', 'source',
    );

    public function __construct()
    {
        $this->description = __('Whether a file hash belongs to'
            . ' something a vendor shipped.');
    }

    public function subjectWords()
    {
        return array_merge(parent::subjectWords(), array(
            'one' => __('hash'),
            'many' => __('hashes'),
        ));
    }

    public function subjectsOf(array $object)
    {
        $hash = $this->firstValue($object, array('SHA-256', 'SHA-1', 'MD5'));
        return $hash === null ? array() : array($hash);
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->recordOf($object) !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $records = array();
        foreach ($objects as $object) {
            $record = $this->recordOf($object);
            if ($record !== null) {
                $records[] = $record;
            }
        }
        usort($records, function ($a, $b) {
            return ($b['ran_at'] ?? 0) - ($a['ran_at'] ?? 0);
        });
        $malicious = null;
        foreach ($records as $record) {
            if ($record['malicious'] !== null) {
                $malicious = $record['malicious'];
                break;
            }
        }
        return array(
            'records' => $records,
            'headline' => empty($records) ? null : $records[0],
            /*
             * A service that has said a hash is known-malicious has
             * said the strongest thing it can say, and it outranks the
             * package row it arrives beside — so the flag is hoisted
             * out of the newest record rather than read off it.
             */
            'malicious' => $malicious,
            'known' => $malicious === null && !empty($records),
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function recordOf(array $object)
    {
        $fields = array();
        foreach (self::FIELDS as $relation) {
            $value = $this->value($object, $relation);
            if ($value !== null) {
                $fields[$relation] = $value;
            }
        }
        if (empty($fields)) {
            return null;
        }
        $malicious = isset($fields['KnownMalicious'])
            && trim($fields['KnownMalicious']) !== ''
            ? $fields['KnownMalicious']
            : null;
        $package = null;
        if (isset($fields['PackageName'])) {
            $package = $fields['PackageName'];
            if (isset($fields['PackageVersion'])) {
                $package .= ' ' . $fields['PackageVersion'];
            }
        }
        return array(
            'name' => $this->firstValue($object, self::NAMES),
            'package' => $package,
            'malicious' => $malicious,
            'size' => $this->number($fields['FileSize'] ?? null),
            'source' => $fields['source'] ?? null,
            'fields' => $fields,
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }
}
