<?php

/**
 * A value in a URL segment, both ways.
 *
 * The Value Intelligence page's subject is an arbitrary string — a hash, a
 * domain, a URL with slashes in it — so it travels base64-encoded. Two
 * controllers need the same encoding: `ValuesController` mints it and
 * `AnalystProfilesController`'s simulator takes it as `?value=`.
 *
 * It lives here rather than on either of them for two reasons. One is
 * the ordinary one — two copies of an alphabet decision drift. The
 * other is `ACLComponent`: its
 * `findMissingFunctionNames()` reads controller files with a regex and
 * treats every method whose name does not begin with an underscore as
 * an action needing an ACL entry, so a controller's helpers have to be
 * `__`-prefixed to stay out of the report. A method named
 * `__decodeValue` that another class calls reads as private while being
 * shared API, and that is a wart the check's convention creates rather
 * than a design anybody chose. Out here the question does not arise.
 *
 * **Decoding does not throw.** It answers `null` for anything it cannot
 * read, and each caller raises its own 404 with its own wording — an
 * HTTP exception from a tool would put the transport layer's vocabulary
 * in the one place that has no transport.
 */
class ValueUrlTool
{
    /**
     * @param string $value
     * @return string URL-safe base64, so a value containing `/`
     *                survives a path segment.
     */
    public static function encode($value)
    {
        return strtr(base64_encode((string)$value), '+/', '-_');
    }

    /**
     * Both alphabets are accepted, and that is deliberate rather than
     * lenient: a raw `/` cannot survive a path segment, so callers
     * legitimately encode with `-_`, while anything that went through a
     * generic base64 helper arrives with `+/`.
     *
     * @param string|null $encoded
     * @return string|null The value, or null when there is not one
     */
    public static function decode($encoded)
    {
        if ($encoded === null || $encoded === '') {
            return null;
        }
        $value = base64_decode(strtr((string)$encoded, '-_', '+/'), true);
        return ($value === false || $value === '') ? null : $value;
    }
}
