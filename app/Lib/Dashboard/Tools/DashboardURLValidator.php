<?php

/**
 * Drilldown URL validator (DD-03).
 *
 * Widget renderers call this before emitting a `drilldown` URL as an
 * `<a href="...">` so a buggy or malicious widget can't smuggle in a
 * `javascript:` payload or an off-host link.
 *
 * Contract:
 *
 *   $safe = DashboardURLValidator::validate($url);
 *   if ($safe !== null) {
 *       // emit <a href="<?= h($safe) ?>">…</a>
 *   } else {
 *       // emit plain text — URL was unsafe
 *   }
 *
 * Rules:
 *   - Non-string / empty input            → null
 *   - Control characters (\x00–\x1f, \x7f) → null
 *   - Any raw backslash                   → null (browsers read `\`
 *     as `/` in the authority position, so `/\evil.com` is off-host)
 *   - javascript: / data: / vbscript: / file: schemes → null
 *     (case-insensitive, leading whitespace tolerated)
 *   - Relative URLs (path / query / fragment only)    → allowed
 *   - MISP filter syntax like `tag:tlp:red` (no `://`) → allowed
 *     (parse_url mis-detects the leading word as a scheme; we
 *     gate "absolute" on the presence of `://`, not the parser's
 *     verdict)
 *   - Protocol-relative `//host/...`      → allowed iff host matches
 *     the host of an allowed origin (see below)
 *   - Absolute `scheme://host[:port]/...` → allowed iff scheme, host,
 *     and port all match an allowed origin's
 *
 * Allowed origins (DD-03 + analyst-track AD-09 relaxation): MISP's own
 * base URL (see baseUrl()), PLUS the admin-configured external reference
 * database the dashboard is permitted to deep-link to — today
 * `MISP.cveurl` (the CVE lookup the trending-vulnerability widget links
 * each identifier to, resolved with MISP's documented default). Only
 * these specific admin-set hosts are allowed off-baseurl; arbitrary
 * off-host links are still dropped.
 *
 * Anything else → null.
 *
 * The static surface mirrors LayoutFixup — same convention for
 * Lib/Dashboard/Tools/ helpers.
 */
class DashboardURLValidator
{
    /**
     * MISP's documented default CVE lookup base (config.default.php:41,
     * Server.php:5862, value_field.ctp:94). Used when MISP.cveurl is unset
     * so the emitter (TrendingWidget) and this gate resolve the SAME base.
     */
    const DEFAULT_CVEURL = 'https://vulnerability.circl.lu/vuln/';

    /**
     * The CVE lookup base URL the dashboard trusts for deep-links: the
     * admin-configured MISP.cveurl, or MISP's documented default when unset.
     * Single source of truth shared by validate()'s allowlist and the
     * trending-vulnerability widget's link builder, so the emitted link and
     * the gate that admits it can never drift (mirrors value_field.ctp:94).
     *
     * @return string
     */
    public static function cveBaseUrl()
    {
        $cveurl = Configure::read('MISP.cveurl');
        return (is_string($cveurl) && $cveurl !== '') ? $cveurl : self::DEFAULT_CVEURL;
    }

    /**
     * MISP's own base URL, resolved exactly the way every dashboard link
     * emitter resolves it: the admin-configured `MISP.baseurl`, falling
     * back to the origin the request was served from when that setting is
     * empty. `MISP.baseurl` is nullable (Server.php marks it
     * `'null' => true`), and on such an install the emitters all use
     * `Router::url('/', true)` — so without the same fallback here the
     * gate and the emitters disagree and every own-host absolute link on
     * the dashboard is dropped. Mirrors cveBaseUrl(): one resolver shared
     * by the emitter and the gate, so the two can never drift.
     *
     * Note this fallback is request-derived. On a baseurl-less install the
     * emitted links are request-derived too, so the allowlist is no weaker
     * than the links it guards; setting `MISP.baseurl` is what pins both.
     *
     * @return string
     */
    public static function baseUrl()
    {
        $baseurl = Configure::read('MISP.baseurl');
        if (is_string($baseurl) && $baseurl !== '') {
            return $baseurl;
        }
        return rtrim(Router::url('/', true), '/');
    }

    /**
     * The set of origins an absolute / protocol-relative drilldown may point
     * at: MISP's own base URL plus the trusted CVE lookup base (above). Each
     * entry is a parse_url() array; unparseable / host-less candidates are
     * skipped. An empty result means nothing is configured → all absolute
     * URLs are dropped (fail-safe).
     *
     * @return array<int, array>
     */
    private static function allowedOrigins()
    {
        $origins = array();
        $candidates = array(
            self::baseUrl(),
            self::cveBaseUrl(),
        );
        foreach ($candidates as $candidate) {
            if (!is_string($candidate) || $candidate === '') {
                continue;
            }
            $parts = @parse_url($candidate);
            if ($parts === false || empty($parts['host'])) {
                continue;
            }
            $origins[] = $parts;
        }
        return $origins;
    }

    /**
     * @param mixed $url
     * @return string|null  The URL to emit, or null if it must be dropped.
     */
    public static function validate($url)
    {
        if (!is_string($url) || $url === '') {
            return null;
        }
        // Reject dangerous schemes early. parse_url's verdict on
        // weird inputs is fragile across PHP versions; a regex is
        // both faster and more predictable.
        if (preg_match('/^\s*(?:javascript|data|vbscript|file):/i', $url)) {
            return null;
        }
        // Reject any control character — NUL, line feeds, tabs, DEL.
        // Real-world URL parsers (and mod_rewrite) are inconsistent
        // about handling these and they can be used to bypass naive
        // string-prefix checks.
        if (preg_match('/[\x00-\x1f\x7f]/', $url)) {
            return null;
        }
        // Reject any raw backslash. The WHATWG URL parser treats `\` as
        // `/` in and around the authority, so `\\evil.com/x`,
        // `/\evil.com/x`, `https:/\evil.com` and `https:\\evil.com` all
        // resolve to evil.com while reading as "relative" to the
        // scheme / `//` tests below. It also kills the userinfo spoof
        // `\\misp.example.com@evil.com/x`, whose visible prefix is the
        // real MISP host. A legitimate URL never needs a raw backslash —
        // the percent-encoded form (%5C) stays an ordinary path
        // character and is still accepted.
        if (strpos($url, '\\') !== false) {
            return null;
        }
        // A URL is "absolute" only if it has a proper hierarchical
        // scheme separator `scheme://` or starts with `//`
        // (protocol-relative). Inputs like `tag:tlp:red` look like a
        // scheme to parse_url but are valid relative MISP filter
        // paths — we treat anything else as relative.
        $isAbsolute         = (bool) preg_match('#^[a-z][a-z0-9+.\-]*://#i', $url);
        $isProtocolRelative = (strncmp($url, '//', 2) === 0);
        if (!$isAbsolute && !$isProtocolRelative) {
            return $url; // relative — allowed
        }
        // Absolute / protocol-relative: scheme (absolute only), host and
        // port must all match one of the allowed origins.
        $parts = @parse_url($url);
        if ($parts === false || empty($parts['host'])) {
            return null;
        }
        // Strict port match — http://host:8080 is a different service from
        // http://host:80, even though both share the host. Treat missing
        // ports as equal (both default).
        $candidatePort = isset($parts['port']) ? (int) $parts['port'] : null;
        foreach (self::allowedOrigins() as $origin) {
            if (strcasecmp($parts['host'], $origin['host']) !== 0) {
                continue;
            }
            $originPort = isset($origin['port']) ? (int) $origin['port'] : null;
            if ($candidatePort !== $originPort) {
                continue;
            }
            // Scheme match for absolute URLs (no http→https swap). Skipped
            // for protocol-relative inputs (no scheme — the browser uses the
            // page's, which is what we want).
            if ($isAbsolute) {
                if (empty($origin['scheme'])
                    || empty($parts['scheme'])
                    || strcasecmp($parts['scheme'], $origin['scheme']) !== 0) {
                    continue;
                }
            }
            return $url;
        }
        return null;
    }
}
