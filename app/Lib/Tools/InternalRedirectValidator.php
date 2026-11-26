<?php

/**
 * Same-origin redirect target validator (V20).
 *
 * MISP has two stored, user-controlled values that end up as a
 * navigation target after login: the `pre_login_requested_url` session
 * entry and the `homepage` user setting. Both must resolve to a path on
 * this instance and nothing else.
 *
 * Contract:
 *
 *   $safe = InternalRedirectValidator::sanitize($candidate);
 *   if ($safe !== '') {
 *       // redirect($safe), or emit it into an href through h()
 *   } else {
 *       // fall back to the built-in default
 *   }
 *
 * The caller must use the *returned* string, never the input it passed
 * in: the return value is the exact byte sequence that was validated, so
 * "what was checked" and "what is emitted" cannot drift.
 *
 * Do not decode inside this function. A stored `/%2f%2fevil.example` is
 * emitted verbatim in a `Location:` header and stays same-origin — the
 * browser does not decode `%2f` before resolving the target. Decoding
 * here while the caller redirects the raw string would validate one
 * value and emit another. `UsersController::routeafterlogin()` decodes
 * the session URL *before* calling in, which is safe precisely because
 * it then redirects what came back.
 *
 * Rules (the `pre_login_requested_url` check that has shipped since
 * `ae760b7bf`, lifted here so the homepage sink cannot disagree with it):
 *   - Non-string / empty                         -> ''
 *   - Unparseable by parse_url (e.g. `///host`)  -> ''
 *   - Any host, scheme or userinfo component     -> ''
 *   - No path, or a path not starting with `/`   -> ''
 *   - `//host` and `/\host` — both resolve to a protocol-relative,
 *     off-site URL in a browser                  -> ''
 *   - Control characters (added here, see below) -> ''
 *   - Anything else -> path [+ `?query`] [+ `#fragment`]
 *
 * The control-character rule is the one addition to the inherited check.
 * `header('Location: ...')` refuses a value containing CR/LF, so a
 * stored newline currently yields a 302 with no target at all; dropping
 * the candidate instead lands the user on the default homepage. No
 * legitimate MISP path contains a raw control character — the
 * percent-encoded form is untouched.
 */
class InternalRedirectValidator
{
    /**
     * @param mixed $url
     * @return string The URL to redirect to / emit, or '' when unsafe.
     */
    public static function sanitize($url)
    {
        if (!is_string($url) || $url === '') {
            return '';
        }
        if (preg_match('/[\x00-\x1f\x7f]/', $url)) {
            return '';
        }
        $parts = parse_url($url);
        if (
            $parts === false ||
            isset($parts['host']) ||
            isset($parts['scheme']) ||
            isset($parts['user']) ||
            !isset($parts['path']) ||
            $parts['path'][0] !== '/' ||
            // reject "//x" and "/\x" - both resolve to a protocol-relative (off-site) URL
            (isset($parts['path'][1]) && ($parts['path'][1] === '/' || $parts['path'][1] === '\\'))
        ) {
            return '';
        }
        return $parts['path']
            . (isset($parts['query']) ? '?' . $parts['query'] : '')
            . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
    }
}
