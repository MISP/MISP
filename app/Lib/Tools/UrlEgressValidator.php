<?php
App::uses('CidrTool', 'Tools');

/**
 * Validates outbound URLs before MISP fetches them.
 *
 * Two policies, because the two situations are not the same problem:
 *
 * - POLICY_DENY_INTERNAL is for URLs supplied by users who are not site
 *   admins. Such a user must not get to choose MISP's network position, so
 *   every internal range is refused.
 * - POLICY_DENY_LOOPBACK is for targets a site admin configured. Pointing
 *   MISP at an RFC1918 host is a supported deployment - internal sync and
 *   internal feeds rely on it - so only loopback and the cloud metadata
 *   endpoints are refused, matching the check this replaces.
 *
 * Hosts are resolved here and the caller is handed the address that was
 * actually validated, so the connection can be pinned to it. Without that,
 * a name whose record changes between the check and the fetch defeats the
 * check entirely.
 */
class UrlEgressValidator
{
    /** Refuse every internal range. For user-supplied URLs. */
    const POLICY_DENY_INTERNAL = 'deny_internal';

    /** Refuse loopback and cloud metadata only. For site-admin targets. */
    const POLICY_DENY_LOOPBACK = 'deny_loopback';

    /**
     * Refuse nothing; resolve and report the address so the caller can pin
     * it. For a target already authorised by other means - a redirect that
     * stays on the host the admin configured - where the value wanted is
     * protection against the name answering differently on the second
     * lookup, not an egress decision.
     */
    const POLICY_RESOLVE_ONLY = 'resolve_only';

    /**
     * Loopback, unspecified, and the link-local metadata addresses used by
     * the major cloud providers. Refused under every policy.
     */
    const RANGES_LOOPBACK = [
        '127.0.0.0/8',
        '0.0.0.0/8',
        '::1/128',
        '::/128',
        '::ffff:127.0.0.0/104', // IPv4-mapped loopback
        '169.254.169.254/32',   // AWS / Azure / GCP / DigitalOcean IMDS
        '169.254.170.2/32',     // AWS ECS task metadata
        'fd00:ec2::254/128',    // AWS IMDS over IPv6
    ];

    /**
     * Everything else that is not routable on the public internet. Refused
     * under POLICY_DENY_INTERNAL only.
     */
    const RANGES_INTERNAL = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '169.254.0.0/16',   // link-local generally
        '100.64.0.0/10',    // CGNAT
        '192.0.0.0/24',     // IETF protocol assignments
        '192.0.2.0/24',     // TEST-NET-1
        '198.18.0.0/15',    // benchmarking
        '198.51.100.0/24',  // TEST-NET-2
        '203.0.113.0/24',   // TEST-NET-3
        '224.0.0.0/4',      // multicast
        '240.0.0.0/4',      // reserved
        'fc00::/7',         // unique local
        'fe80::/10',        // link-local
        'ff00::/8',         // multicast
        '2001:db8::/32',    // documentation
        '::ffff:0:0/96',    // IPv4-mapped, so v4 rules cannot be dodged via v6
    ];

    /**
     * A DNS name. The final label must begin with a letter, which is what
     * separates a hostname from an address: it rejects `0x7f000001`,
     * `2130706433` and `127.1`, all of which curl and PHP's stream wrapper
     * happily connect to as 127.0.0.1 but which no resolver treats as names.
     */
    const HOSTNAME_REGEX = '/^(?=.{1,253}\.?$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z]([a-z0-9-]{0,61}[a-z0-9])?\.?$/i';

    /**
     * @param string $url
     * @param string $policy
     * @return array{scheme:string, host:string, port:int|null, ip:string, ips:array, pin:bool}
     * @throws InvalidArgumentException if the URL or host is malformed
     * @throws ForbiddenException if the target resolves into a refused range
     */
    public static function validate($url, $policy = self::POLICY_DENY_INTERNAL)
    {
        if (!is_string($url) || $url === '') {
            throw new InvalidArgumentException(__('No URL provided.'));
        }
        if (!preg_match('/^https?:\/\//i', $url)) {
            throw new InvalidArgumentException(
                __('Invalid URL scheme. Only HTTP and HTTPS are supported.')
            );
        }
        $parts = parse_url($url);
        if ($parts === false || empty($parts['host'])) {
            throw new InvalidArgumentException(__('Could not parse the URL.'));
        }

        $host = $parts['host'];
        $literal = self::asIpLiteral($host);

        if ($literal !== false) {
            // No name lookup happens, so there is no window to pin against.
            self::assertAllowed([$literal], $policy, $host);
            $ips = [$literal];
            $pin = false;
        } else {
            if (!preg_match(self::HOSTNAME_REGEX, $host)) {
                throw new InvalidArgumentException(
                    __('Invalid host "%s" - not an IP address or a valid hostname.', $host)
                );
            }
            $ips = self::resolve($host);
            if (empty($ips)) {
                throw new InvalidArgumentException(
                    __('Could not resolve host "%s".', $host)
                );
            }
            // Every address is checked, not just the first, so a name with
            // several records cannot slip an internal one past on a later
            // connection attempt.
            self::assertAllowed($ips, $policy, $host);
            $pin = true;
        }

        return [
            'scheme' => strtolower($parts['scheme']),
            'host' => $host,
            'port' => isset($parts['port']) ? (int)$parts['port'] : null,
            'ip' => $ips[0],
            'ips' => $ips,
            'pin' => $pin,
        ];
    }

    /**
     * May a fetch of $from be allowed to follow a redirect to $to?
     *
     * Anchored to the host rather than to an address range: a feed or server
     * an admin configured is *authorised* to be internal, but the admin
     * authorised one host, not wherever that host chooses to point. An
     * http -> https upgrade of the same host is allowed.
     *
     * @param string $from
     * @param string $to
     * @return bool
     */
    public static function isRedirectAllowed($from, $to)
    {
        if (!is_string($from) || !is_string($to)) {
            return false;
        }
        if (!preg_match('/^https?:\/\//i', $to)) {
            return false;
        }
        $fromParts = parse_url($from);
        $toParts = parse_url($to);
        if (empty($fromParts['host']) || empty($toParts['host'])) {
            return false;
        }
        if (self::normaliseHost($fromParts['host']) !== self::normaliseHost($toParts['host'])) {
            return false;
        }
        $fromScheme = strtolower($fromParts['scheme']);
        $toScheme = strtolower($toParts['scheme']);
        // Same scheme, or an upgrade to https. Never a downgrade, which would
        // strip transport security from a fetch that started off protected.
        // The port is deliberately not compared: the host is the boundary
        // being enforced, and it is already reachable by definition, so
        // pinning the port would break ordinary redirects without closing
        // anything.
        return $fromScheme === $toScheme || ($fromScheme === 'http' && $toScheme === 'https');
    }

    /**
     * @param string $from
     * @param string $to
     * @throws ForbiddenException
     */
    public static function assertRedirectAllowed($from, $to)
    {
        if (!self::isRedirectAllowed($from, $to)) {
            throw new ForbiddenException(
                __('Refusing to follow a redirect to a different host (%s).', $to)
            );
        }
    }

    /**
     * Resolve a Location header against the URL it came from.
     *
     * CR and LF are stripped first: a header value is parsed straight back
     * into a URL by the callers, and neither belongs in one.
     *
     * @param string $location
     * @param string $base
     * @return string|null null if there is nothing usable
     */
    public static function resolveLocation($location, $base)
    {
        $location = str_replace(["\r", "\n"], '', trim((string)$location));
        if ($location === '') {
            return null;
        }
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $location)) {
            return $location; // already absolute
        }
        $baseParts = parse_url($base);
        if (empty($baseParts['scheme']) || empty($baseParts['host'])) {
            return $location;
        }
        if (strpos($location, '//') === 0) {
            return $baseParts['scheme'] . ':' . $location; // scheme-relative
        }
        $origin = $baseParts['scheme'] . '://' . $baseParts['host']
            . (isset($baseParts['port']) ? ':' . $baseParts['port'] : '');
        if ($location[0] === '/') {
            return $origin . $location;
        }
        $basePath = isset($baseParts['path']) ? $baseParts['path'] : '/';
        $dir = substr($basePath, 0, strrpos($basePath, '/') + 1);
        return $origin . ($dir === '' ? '/' : $dir) . $location;
    }

    /**
     * @param string $policy
     * @return array
     */
    public static function refusedRanges($policy)
    {
        if ($policy === self::POLICY_RESOLVE_ONLY) {
            return [];
        }
        if ($policy === self::POLICY_DENY_INTERNAL) {
            return array_merge(self::RANGES_LOOPBACK, self::RANGES_INTERNAL);
        }
        return self::RANGES_LOOPBACK;
    }

    /**
     * @param array $ips
     * @param string $policy
     * @param string $host
     * @throws ForbiddenException
     */
    private static function assertAllowed(array $ips, $policy, $host)
    {
        $cidrTool = new CidrTool(self::refusedRanges($policy));
        foreach ($ips as $ip) {
            $match = $cidrTool->contains($ip);
            if ($match !== false) {
                throw new ForbiddenException(
                    __('The URL host "%s" resolves to %s, which is in the restricted range %s.', $host, $ip, $match)
                );
            }
        }
    }

    /**
     * Accepts a bare address or the bracketed IPv6 form used in URLs.
     *
     * @param string $host
     * @return string|false the address, or false if $host is not one
     */
    private static function asIpLiteral($host)
    {
        $candidate = $host;
        if (strlen($candidate) > 1 && $candidate[0] === '[' && substr($candidate, -1) === ']') {
            $candidate = substr($candidate, 1, -1);
        }
        return filter_var($candidate, FILTER_VALIDATE_IP) === false ? false : $candidate;
    }

    /**
     * All addresses for a name. gethostbynamel covers /etc/hosts, which a
     * DNS-only lookup misses - `localhost` being the obvious case.
     *
     * @param string $host
     * @return array
     */
    private static function resolve($host)
    {
        $ips = [];
        $v4 = @gethostbynamel($host);
        if (!empty($v4)) {
            $ips = $v4;
        }
        $v6 = @dns_get_record($host, DNS_AAAA);
        if (!empty($v6)) {
            foreach ($v6 as $record) {
                if (!empty($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }
        return array_values(array_unique($ips));
    }

    /**
     * @param string $host
     * @return string
     */
    private static function normaliseHost($host)
    {
        $host = strtolower($host);
        if (substr($host, -1) === '.') {
            $host = substr($host, 0, -1);
        }
        return $host;
    }
}
