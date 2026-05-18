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
 *   - javascript: / data: / vbscript: / file: schemes → null
 *     (case-insensitive, leading whitespace tolerated)
 *   - Relative URLs (path / query / fragment only)    → allowed
 *   - MISP filter syntax like `tag:tlp:red` (no `://`) → allowed
 *     (parse_url mis-detects the leading word as a scheme; we
 *     gate "absolute" on the presence of `://`, not the parser's
 *     verdict)
 *   - Protocol-relative `//host/...`      → allowed iff host matches
 *     the host of Configure::read('MISP.baseurl')
 *   - Absolute `scheme://host[:port]/...` → allowed iff scheme, host,
 *     and port all match the baseurl's
 *
 * Anything else → null.
 *
 * The static surface mirrors LayoutFixup — same convention for
 * Lib/Dashboard/Tools/ helpers.
 */
class DashboardURLValidator
{
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
        // Absolute: host must match MISP.baseurl's.
        $baseurl = Configure::read('MISP.baseurl');
        if (empty($baseurl) || !is_string($baseurl)) {
            return null;
        }
        $baseParts = @parse_url($baseurl);
        if ($baseParts === false || empty($baseParts['host'])) {
            return null;
        }
        $parts = @parse_url($url);
        if ($parts === false || empty($parts['host'])) {
            return null;
        }
        if (strcasecmp($parts['host'], $baseParts['host']) !== 0) {
            return null;
        }
        // Strict port match — http://host:8080 is a different
        // service from http://host:80, even though both share the
        // host. Treat missing ports as equal (both default).
        $candidatePort = isset($parts['port']) ? (int) $parts['port'] : null;
        $basePort      = isset($baseParts['port']) ? (int) $baseParts['port'] : null;
        if ($candidatePort !== $basePort) {
            return null;
        }
        // Scheme match. Skipped for protocol-relative inputs (they
        // have no scheme); for those the request's own scheme will
        // be used by the browser, which is what we want.
        if ($isAbsolute && !empty($baseParts['scheme'])) {
            if (strcasecmp($parts['scheme'], $baseParts['scheme']) !== 0) {
                return null;
            }
        }
        return $url;
    }
}
