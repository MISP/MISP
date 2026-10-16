<?php

/**
 * Which enrichment modules answer without anything leaving the
 * instance.
 *
 * Phase 7 of prd/analyst-profile/ needs this and **module
 * introspection does not carry it.** Measured 2026-09-07 against the
 * dev instance's 146 modules: the top-level keys are `name`, `type`,
 * `mispattributes` and `meta`, and `meta` runs `author`, `config`,
 * `description`, `features`, `input`, `logo`, `module-type`, `name`,
 * `output`, `references`, `require_standard_format`, `requirements`
 * and `version`. Not one of them says whether asking the module tells
 * a third party that somebody is looking at the value
 * (`08-enrichment.md` §1.3, §3.1).
 *
 * ## Why it cannot be derived, with the receipt
 *
 * The obvious heuristic is *a module with an API key leaves the
 * building, one without does not*, and it is wrong in both
 * directions:
 *
 * - **`countrycode`** declares `config: []` and `requirements: []` —
 *   nothing to configure, nothing to install — and fetches
 *   `http://www.geognos.com/api/en/countries/info/all.json` over plain
 *   HTTP to expand a ccTLD.
 * - **`clamav`** takes one config key and reaches nothing but the
 *   `clamd` socket the operator pointed it at.
 *
 * So the same shape says both things, exactly as phase 6's fixture put
 * `7` in two weight bands and thereby foreclosed a derived band
 * (**D14**). The knowledge is editorial and ships as code, following
 * `GalaxyColour` before it.
 *
 * ## The test that decides membership
 *
 * **Does anything about this value reach a party the instance operator
 * does not control?**
 *
 * - **No → local.** Pure computation (`extract_url_components`),
 *   local files (`geoip_*` read Maxmind's database off disk), or an
 *   endpoint that can only ever be the operator's own — `clamav` has
 *   no default connection string at all, so it reaches whatever
 *   `clamd` the operator runs and nothing when they run none.
 * - **Yes → external**, and *configurable* is not the same as
 *   *local*: `mmdb_lookup` defaults to CIRCL's `ip.circl.lu` and
 *   `dns` to Google's `8.8.8.8`, so both leave the building on a
 *   deployment nobody has configured.
 *
 * ## An omission is the safe direction, and it is a real one
 *
 * A module this map does not name resolves `unknown`, and every reader
 * of this class treats `unknown` as `external` — `leavesInstance()`
 * says so in one place so that no caller has to remember it. So the
 * failure mode of an incomplete map is *a local module described as
 * though it might not be*, never *a value quietly sent somewhere*.
 *
 * Nothing here withholds a module. This map labels; the reader decides
 * and presses. The `locality_posture` setting that once turned a label
 * into a refusal has been withdrawn.
 *
 * That the map *is* incomplete is measured rather than hoped: the
 * roster is the modules whose source was read, and reading source is
 * not proof either — **`socialscan` shows no outbound call in its own
 * file** because the library it wraps makes them, which is why the map
 * carries only what it can defend and says nothing about the other 124.
 */
class ModuleLocality
{
    /** Nothing about the value leaves the instance. */
    const LOCAL = 'local';

    /** Asking tells somebody the operator does not control. */
    const EXTERNAL = 'external';

    /** This map has nothing to say, and `local_only` treats it as
     * `external`. */
    const UNKNOWN = 'unknown';

    /**
     * Where an answer came from, carried per module so the tab can
     * name it: a shipped map that has fallen behind should be visible
     * rather than silent.
     */
    const SOURCE_SHIPPED = 'shipped';
    const SOURCE_UNKNOWN = 'unknown';

    /**
     * The roster, by each module's exact introspection `name`.
     *
     * Read off the running misp-modules 2026-09-07 rather than
     * transcribed from documentation: every entry's source was grepped
     * for `requests`, `urlopen`, `resolver`, a socket and an `http://`
     * literal, and the comment beside a non-obvious one says what the
     * reading turned up. A key naming no real module is inert.
     *
     * The list is short because *most* enrichment is a lookup against
     * somebody else's data — that is what enrichment is for — and the
     * local ones are mostly the file and syntax modules, which a value
     * page rarely has a type for. That asymmetry is the honest shape
     * of the platform, not a gap in the reading.
     */
    const LOCAL_MODULES = array(
        // Pure computation over the attribute itself.
        'extract_url_components',
        'eql',
        'jinja_template_rendering',
        'sigmf_expand',
        // Syntax work against a local library.
        'sigma_queries',
        'sigma_syntax_validator',
        'stix2_pattern_syntax_validator',
        'yara_query',
        'yara_syntax_validator',
        // Attachment readers: text out of a file that is already here.
        'docx_enrich',
        'ods_enrich',
        'odt_enrich',
        'pdf_enrich',
        'pptx_enrich',
        'xlsx_enrich',
        'ocr_enrich',
        'convert_markdown_to_pdf',
        // Decodes the barcode in an attachment; the schema strings in
        // its source are what it emits, not what it fetches.
        'qrcode',
        // "A local copy of Maxmind's Geolite database" — a file read,
        // and the only reference to maxmind.com is in `references`.
        'geoip_asn',
        'geoip_city',
        'geoip_country',
        // No default connection string, so it can only ever reach the
        // `clamd` the operator configured — unix socket or host:port.
        'clamav',
    );

    /**
     * The shipped locality for a module, or null when this map has
     * nothing to say about it.
     *
     * Null rather than `external`, so that `resolve()` can tell *this
     * module is known to leave the building* from *nobody has read
     * this module's source*. `leavesInstance()` treats them the same
     * and the tab does not: one is a fact about the module, the other
     * is a gap in the map, and a reader deciding whether to press run
     * is owed the difference.
     *
     * @param string|null $name The module's `name`, exactly
     * @return string|null
     */
    public static function shippedFor($name)
    {
        if (!is_string($name) && !is_numeric($name)) {
            return null;
        }
        return in_array((string)$name, self::LOCAL_MODULES, true)
            ? self::LOCAL
            : null;
    }

    /**
     * The shipped map's answer, or `unknown`, in one place so that the
     * tab and the editor cannot disagree about it.
     *
     * @param string|null $name
     * @return array `locality` and `source`
     */
    public static function resolve($name)
    {
        $shipped = self::shippedFor((string)$name);
        if ($shipped !== null) {
            return array(
                'locality' => $shipped,
                'source' => self::SOURCE_SHIPPED,
            );
        }
        return array(
            'locality' => self::UNKNOWN,
            'source' => self::SOURCE_UNKNOWN,
        );
    }

    /**
     * Whether asking this module tells anybody outside the instance.
     *
     * **`unknown` counts as yes**, which is what makes an incomplete
     * map safe to ship. Stated as its own method so that no caller has
     * to remember it, and so that the two states stay distinguishable
     * everywhere else.
     *
     * @param string|null $name
     * @return bool
     */
    public static function leavesInstance($name)
    {
        $resolved = self::resolve($name);
        return $resolved['locality'] !== self::LOCAL;
    }

    /**
     * Whether a locality is one this class admits. `unknown` is not
     * one of them: it is what the absence of an answer resolves to.
     *
     * @param mixed $locality
     * @return bool
     */
    public static function valid($locality)
    {
        return $locality === self::LOCAL
            || $locality === self::EXTERNAL;
    }

    /**
     * Whether V1 can retire: introspection now carries the fact
     * itself.
     *
     * The mechanical criterion, in code so that *"can this file
     * go?"* is answered by an instance rather than by reading a
     * roadmap. It is satisfied when **every module the
     * instance offers** declares its own locality, not merely the ones
     * this map happens to name: a field that exists for 22 modules and
     * not the other 124 leaves `unknown` meaning two different things,
     * which is the state this file exists to avoid.
     *
     * @param array $declared name => locality as introspection
     *                        declared it, for every module offered
     * @return array `retirable`, `confirmed`, `outstanding`
     */
    public static function retirable(array $declared)
    {
        $confirmed = array();
        $outstanding = array();
        foreach ($declared as $name => $locality) {
            if (self::valid($locality)) {
                $confirmed[] = (string)$name;
            } else {
                $outstanding[] = (string)$name;
            }
        }
        return array(
            'retirable' => !empty($declared) && empty($outstanding),
            'confirmed' => $confirmed,
            'outstanding' => $outstanding,
        );
    }
}
