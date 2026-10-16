<?php

/**
 * A value in a URL segment, both ways.
 *
 * The Value Intelligence page's subject is an arbitrary string — a hash, a
 * domain, a URL with slashes in it — so in a path segment it travels
 * base64-encoded, or as its SHA-256 when too long for a URL. Two
 * controllers need the same encoding: `ValuesController` mints `address()`
 * and `AnalystProfilesController` takes plain base64 in `pin`/`unpin`. A
 * `?value=` query parameter is raw text on both.
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
    const SHA256_PREFIX = 'sha256:';

    /** Apache caps a request line at 8190 bytes by default. */
    const MAX_BASE64 = 7800;

    /**
     * The value page's address for a value: its base64, which gives the
     * value back, or `sha256:<hex>` only where base64 cannot be used — too
     * long for a request line, or all digits, which `parse()` reads as a
     * dictionary id.
     *
     * @param string $value
     * @return string
     */
    public static function address($value)
    {
        $encoded = self::encode($value);
        if (strlen($encoded) > self::MAX_BASE64 || ctype_digit($encoded)) {
            return self::SHA256_PREFIX . hash('sha256', (string)$value);
        }
        return $encoded;
    }

    /**
     * What an address names: `['value' => text]`, `['sha256' => hex]` or
     * `['id' => int]`, the last two for the caller to look up.
     *
     * @param string|null $address
     * @return array|null Null when it names nothing
     */
    public static function parse($address)
    {
        if (!is_string($address) || $address === '') {
            return null;
        }
        if (strpos($address, self::SHA256_PREFIX) === 0) {
            $hex = strtolower(substr($address, strlen(self::SHA256_PREFIX)));
            return preg_match('/^[0-9a-f]{64}$/', $hex)
                ? array('sha256' => $hex)
                : null;
        }
        if (ctype_digit($address)) {
            $id = filter_var($address, FILTER_VALIDATE_INT,
                array('options' => array('min_range' => 1)));
            return $id === false ? null : array('id' => $id);
        }
        $value = self::decode($address);
        return $value === null ? null : array('value' => $value);
    }

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
