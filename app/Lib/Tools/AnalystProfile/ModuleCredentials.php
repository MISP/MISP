<?php

/**
 * Which enrichment modules cannot answer until somebody configures
 * them, and which settings they need.
 *
 * A module enabled but unconfigured is the quietest failure this page
 * has: the declaration saves, the row looks healthy, the box arrives
 * ticked, and the analyst finds out by pressing Run and reading an
 * error. Three of the twelve modules the shipped default names are in
 * exactly that state on a fresh instance.
 *
 * ## Why this cannot be derived, with the receipt
 *
 * Introspection carries `meta.config` — a flat list of setting names —
 * and **nothing that says which of them are required**. The obvious
 * heuristic, *a module with config keys needs them set*, is wrong for
 * most of the roster and wrong in the worst direction, because it
 * would cry wolf over the two modules the default profile most relies
 * on:
 *
 * - **`mmdb_lookup`** declares `custom_API`, `db_source_filter` and
 *   `max_country_info_qt`, and with none of them set it queries
 *   CIRCL's `ip.circl.lu` and works. Its own `features` text says so:
 *   *"by default. The module can be configured with a custom mmdb
 *   server url if required."*
 * - **`dns`** declares `nameserver` and resolves through `8.8.8.8`
 *   without it.
 * - **`circl_passivedns`** declares `username` and `password` and can
 *   do nothing at all without them — its `requirements` say *"A CIRCL
 *   passive DNS account with username & password"*.
 *
 * Same shape, opposite answers. So membership is editorial and ships
 * as code, following `ModuleLocality` before it, and for the same stated
 * reason.
 *
 * ## Silence is the safe direction here
 *
 * The opposite of `ModuleLocality`'s rule, because the risk runs the
 * other way. An unlisted module is assumed to work unconfigured, so an
 * incomplete roster's failure mode is *a module that fails on press
 * with no warning* — which is the status quo for every module, and
 * exactly what it was before this file existed. A roster that guessed
 * instead would put a warning on rows that are fine, and a warning
 * that is usually wrong is worse than none: it teaches the reader to
 * ignore the real ones.
 *
 * So this names only modules whose own `requirements` or `features`
 * text states the need, and says nothing about the rest.
 */
class ModuleCredentials
{
    /**
     * Module name => the settings it cannot answer without.
     *
     * Read off the running misp-modules 2026-09-12. The comment beside
     * each is the module's own words, because that is the evidence and
     * a maintainer rechecking this should not have to re-derive it.
     */
    const REQUIRED = array(
        // "A CIRCL passive DNS account with username & password"
        'circl_passivedns' => array('username', 'password'),
        // "A CIRCL passive SSL account with username & password"
        'circl_passivessl' => array('username', 'password'),
        // "An access to the Farsight Passive DNS API (apikey)"
        'farsight_passivedns' => array('apikey'),
        // "An access to the VirusTotal API (apikey), with a high
        // request rate limit." The proxy settings beside it are
        // optional and deliberately not named.
        'virustotal' => array('apikey'),
        // "An access to the VirusTotal API (apikey)"
        'virustotal_public' => array('apikey'),
        // "An access to the Shodan API (apikey)"
        'shodan' => array('apikey'),
        // "API credentials to censys.io"
        'censys_enrich' => array('api_id', 'api_secret'),
        // "An access to the PassiveTotal API (apikey)"
        'passivetotal' => array('username', 'api_key'),
        // "A Recorded Future API token."
        'recordedfuture' => array('token'),
        // "An access to the VMRay API (apikey & url)"
        'vmray_submit' => array('apikey', 'url'),
    );

    /*
     * **`passive_ssh` is deliberately absent**, and it is the entry a
     * maintainer will reach for first: the shipped default names it,
     * it declares `custom_api_url`, `api_user` and `api_key`, and a
     * Passive SSH instance does want credentials. Its own
     * `requirements` and `features` are both **empty**, so there is no
     * evidence here to cite and the rule above holds — silence rather
     * than a warning this file cannot defend. Add it the day the
     * module says so itself.
     */

    /**
     * The settings this module needs before it can answer, or an empty
     * list when this file has nothing to say about it.
     *
     * @param string|null $name The module's `name`, exactly
     * @return array
     */
    public static function requiredFor($name)
    {
        if (!is_string($name) && !is_numeric($name)) {
            return array();
        }
        $key = (string)$name;
        return isset(self::REQUIRED[$key])
            ? self::REQUIRED[$key]
            : array();
    }

    /**
     * The ones that are needed and not set, given what the module
     * actually declares.
     *
     * **Intersected with `meta.config` rather than trusted**, so a
     * roster entry that has fallen behind a renamed setting names
     * nothing instead of naming a key the module no longer reads. A
     * module whose declared config no longer overlaps this roster at
     * all is treated as needing nothing, which is the silence the
     * class note argues for.
     *
     * @param string|null $name
     * @param array $declared The module's `meta.config`
     * @param callable|null $reader Reads a setting; defaults to
     *                              `Configure::read()`, and is
     *                              injectable so this stays testable
     *                              without CakePHP
     * @return array The setting names that are required and empty
     */
    public static function unsetFor($name, array $declared,
        $reader = null
    ) {
        $required = array_intersect(
            self::requiredFor($name),
            $declared
        );
        if (empty($required)) {
            return array();
        }
        if ($reader === null) {
            $reader = function ($setting) {
                return Configure::read($setting);
            };
        }
        $missing = array();
        foreach ($required as $setting) {
            $value = $reader(
                'Plugin.Enrichment_' . $name . '_' . $setting
            );
            if ($value === null || $value === '' || $value === false) {
                $missing[] = $setting;
            }
        }
        return $missing;
    }
}
