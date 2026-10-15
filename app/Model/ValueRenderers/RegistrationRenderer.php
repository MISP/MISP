<?php

/**
 * When a domain was registered, and by whom through whom.
 *
 * **`rdap` emits this, free and unauthenticated.** RDAP is the
 * structured successor to whois, and the module returns a `whois`
 * object carrying `creation-date`, `expiration-date`,
 * `modification-date`, the registrar, the registrant and the
 * nameservers — every relation this renderer reads. Three keyed
 * modules emit the template as a side result besides.
 *
 * The older `whois` module still queries a whois server over a socket
 * and sends back the raw text it got, which is why one of the two
 * answers to *when was this registered* is a widget and the other is a
 * paragraph. That is a conversion upstream, and it no longer gates
 * this shape.
 *
 * **A `whois` object carrying only `text` is declined.** It would draw
 * a widget whose one fact is *a registration record exists*, and the
 * chip it replaces says that already.
 */
class RegistrationRenderer extends ValueRendererBase
{
    public $id = 'registration';

    public $templates = array('whois');

    public $compact = 'Values/Renderers/registration_compact';

    public $full = 'Values/Renderers/registration_full';

    public $eventUse = self::EVENT_SET;

    const FRESH = 'fresh';

    const YOUNG = 'young';

    /**
     * How old a domain may have been at its first report and still read
     * as fresh or young. Overridden by whatever the caller passes; stated
     * here so a widget drawn with no profile in hand reads the same way
     * the ledger will.
     */
    const THRESHOLDS = array(
        'fresh_days' => 30,
        'young_days' => 180,
    );

    /**
     * A registration this many days after the first report still counts
     * as age 0: a `first_seen` typed as a bare date is midnight, and the
     * domain may have been registered that afternoon.
     */
    const REREGISTRATION_TOLERANCE_DAYS = 2;

    const REGISTRANT = array(
        'registrant-name' => 'name',
        'registrant-org' => 'organisation',
        'registrant-email' => 'email',
        'registrant-phone' => 'phone',
    );

    public function __construct()
    {
        $this->description = __('When a domain was registered, its'
            . ' registrar and its nameservers.');
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
        return array(
            'records' => $records,
            'headline' => empty($records) ? null : $records[0],
            'sources' => $this->sources($objects),
        );
    }

    /**
     * How old the domain was when MISP first saw the value, and what
     * that age reads as.
     *
     * Called by the widget with the defaults above and by the
     * registration-age signal with the profile's own thresholds, so
     * that one function decides what an age means on both surfaces.
     *
     * The age is measured at the first report, never today: a domain
     * registered six days before anybody reported it was a burner, and
     * stays one after it turns three. A creation date more than
     * `REREGISTRATION_TOLERANCE_DAYS` after the first report belongs to
     * a later registration than the one reported, so it has no age and
     * no tier.
     *
     * @param array $record A row from `prepare()`
     * @param string $value The value the page is about
     * @param int|null $firstReport Unix seconds
     * @param array $thresholds `fresh_days`, `young_days`
     * @return array|null `match` (`exact` or `parent`), `domain`,
     *     `created`, `first_report`, `age_days`, `tier` (`fresh`,
     *     `young` or null) and `reregistered`; null where the record is
     *     about another name, carries no creation date, or the value
     *     has no first report
     */
    public static function readingOf(array $record, $value, $firstReport,
        array $thresholds
    ) {
        $match = self::matchOf(
            isset($record['domain']) ? $record['domain'] : null,
            $value
        );
        if ($match === null || empty($record['created'])
            || empty($firstReport)
        ) {
            return null;
        }
        $created = (int)$record['created'];
        $firstReport = (int)$firstReport;
        $reading = array(
            'match' => $match,
            'domain' => self::normalised($record['domain']),
            'created' => $created,
            'first_report' => $firstReport,
            'age_days' => null,
            'tier' => null,
            'reregistered' => false,
        );
        $gap = $firstReport - $created;
        if ($gap < -self::REREGISTRATION_TOLERANCE_DAYS * 86400) {
            $reading['reregistered'] = true;
            return $reading;
        }
        $age = max(0, (int)floor($gap / 86400));
        $reading['age_days'] = $age;
        $fresh = isset($thresholds['fresh_days'])
            ? (int)$thresholds['fresh_days']
            : self::THRESHOLDS['fresh_days'];
        $young = isset($thresholds['young_days'])
            ? (int)$thresholds['young_days']
            : self::THRESHOLDS['young_days'];
        if ($age <= $fresh) {
            $reading['tier'] = self::FRESH;
        } elseif ($age <= $young) {
            $reading['tier'] = self::YOUNG;
        }
        return $reading;
    }

    /**
     * Whether a registration record is about the value, or about the
     * domain the value sits under.
     *
     * A registry only holds registered domains, so `login.evil.com` is
     * answered by the record for `evil.com`. A record naming a bare
     * label is never a parent: it would make every name under that TLD
     * match.
     *
     * @param string|null $recordDomain
     * @param string $value
     * @return string|null `exact`, `parent`, or null
     */
    public static function matchOf($recordDomain, $value)
    {
        $domain = self::normalised($recordDomain);
        $value = self::normalised($value);
        if ($domain === '' || $value === ''
            || strpos($domain, '.') === false
        ) {
            return null;
        }
        if ($domain === $value) {
            return 'exact';
        }
        $suffix = '.' . $domain;
        if (strlen($value) > strlen($suffix)
            && substr($value, -strlen($suffix)) === $suffix
        ) {
            return 'parent';
        }
        return null;
    }

    /**
     * A domain as registries spell it: trimmed, lowercased, no trailing
     * dot, and in its ASCII form where the intl extension can give it.
     *
     * @param string|null $name
     * @return string
     */
    private static function normalised($name)
    {
        $name = rtrim(strtolower(trim((string)$name)), '.');
        if ($name !== '' && preg_match('/[^\x00-\x7F]/', $name)
            && function_exists('idn_to_ascii')
        ) {
            $ascii = idn_to_ascii(
                $name,
                IDNA_DEFAULT,
                INTL_IDNA_VARIANT_UTS46
            );
            if ($ascii !== false) {
                $name = $ascii;
            }
        }
        return $name;
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function recordOf(array $object)
    {
        $created = $this->stamp($this->value($object, 'creation-date'));
        $registrar = $this->value($object, 'registrar');
        $nameservers = $this->values($object, 'nameserver');
        if ($created === null && $registrar === null
            && empty($nameservers)
        ) {
            return null;
        }
        $registrant = array();
        foreach (self::REGISTRANT as $relation => $field) {
            $value = $this->value($object, $relation);
            if ($value !== null) {
                $registrant[$field] = $value;
            }
        }
        $expires = $this->stamp(
            $this->value($object, 'expiration-date')
        );
        return array(
            'domain' => $this->value($object, 'domain'),
            'created' => $created,
            /*
             * The age in days, computed here so the compact widget and
             * the full rendering cannot round it differently — and
             * because the full rendering states it against the
             * profile's own threshold, which needs a number rather
             * than a date.
             */
            'age_days' => $created === null
                ? null
                : (int)floor((time() - $created) / 86400),
            'expires' => $expires,
            'expires_in_days' => $expires === null
                ? null
                : (int)floor(($expires - time()) / 86400),
            'modified' => $this->stamp(
                $this->value($object, 'modification-date')
            ),
            'registrar' => $registrar,
            'nameservers' => $nameservers,
            'registrant' => $registrant,
            'text' => $this->value($object, 'text'),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }
}
