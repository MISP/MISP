<?php
App::uses('RailCard', 'Tools/RailCards');
App::uses('CidrTool', 'Tools');

/**
 * Rail cards for one auth key. The caller has already checked that the
 * user may view the key (AuthKeysController::__prepareConditions).
 */
class AuthKeyRailCards
{
    const ACTIVITY_DAYS = 90;
    const EXPIRY_WARNING_DAYS = 14;

    /** @var array date => ip => count */
    private $usage;

    /** @var int|null */
    private $lastUsed;

    /**
     * @param array $usage AuthKey::getKeyUsageByIp()'s requests, date => ip => count
     * @param int|null $lastUsed its last usage timestamp
     */
    public function __construct(array $usage = [], $lastUsed = null)
    {
        $this->usage = $usage;
        $this->lastUsed = $lastUsed;
    }

    /**
     * @return bool
     */
    public function isUsageLogged()
    {
        return Configure::read('MISP.log_user_ips') && Configure::read('MISP.log_user_ips_authkeys');
    }

    /**
     * @param array $authKey ['AuthKey' => [...]]
     * @return array
     */
    public function activity(array $authKey)
    {
        $options = ['empty' => __('Not used in the last %s days.', self::ACTIVITY_DAYS)];
        if (!$this->isUsageLogged()) {
            $options['note'] = __('Usage logging for auth keys is off on this instance.');
            return RailCard::activity('authkey-activity', __('Usage'), 'fas fa-chart-column', 'day',
                RailCard::series([], 'day', self::ACTIVITY_DAYS),
                ['count' => 0, 'label' => __('requests')], null, [], $options);
        }
        $perDay = [];
        foreach ($this->usage as $date => $ips) {
            $perDay[$date] = array_sum($ips);
        }
        $series = RailCard::series($perDay, 'day', self::ACTIVITY_DAYS);
        $counts = array_column($series, 'count');
        $total = array_sum($counts);
        $last30 = array_sum(array_slice($counts, -30));
        $activeDays = count(array_filter($counts));
        return RailCard::activity(
            'authkey-activity',
            __('Usage'),
            'fas fa-chart-column',
            'day',
            $series,
            ['count' => $total, 'label' => __n('request in %s days', 'requests in %s days', $total, self::ACTIVITY_DAYS)],
            RailCard::last($this->lastUsed, __('Last used')),
            [
                ['label' => __('Last 30 days'), 'value' => $last30],
                ['label' => __('Active days'), 'value' => $activeDays],
            ],
            $options
        );
    }

    /**
     * Every address the key was used from, with its request count when
     * usage is logged. Addresses outside the key's allowlist were refused.
     *
     * @param array $authKey
     * @param bool $mayPin
     * @return array
     */
    public function addresses(array $authKey, $mayPin)
    {
        $key = $authKey['AuthKey'];
        $counts = [];
        if ($this->isUsageLogged()) {
            foreach ($this->usage as $ips) {
                foreach ($ips as $ip => $count) {
                    $counts[$ip] = ($counts[$ip] ?? 0) + $count;
                }
            }
        }
        foreach ((array)($key['unique_ips'] ?? []) as $ip) {
            $counts += [$ip => null];
        }
        uasort($counts, function ($a, $b) {
            return ($b ?? -1) <=> ($a ?? -1);
        });
        $allowed = array_values(array_filter((array)($key['allowed_ips'] ?? [])));
        $cidr = empty($allowed) ? null : new CidrTool($allowed);
        $rows = [];
        foreach ($counts as $ip => $count) {
            $ip = (string)$ip;
            $refused = $cidr !== null && !$cidr->contains($ip);
            $row = [
                'label' => $ip,
                'count' => $count,
                'icon' => 'fas fa-network-wired',
                'tone' => $refused ? 'warn' : null,
                'badge' => $refused ? ['label' => __('Not allowed'), 'tone' => 'warn'] : null,
            ];
            if ($mayPin && $cidr === null) {
                $row['action'] = [
                    'label' => __('Pin'),
                    'href' => '/auth_keys/pin/' . (int)$key['id'] . '?ip=' . rawurlencode($ip),
                    'method' => 'post',
                    'confirm' => __('Accept this key only from %s?', $ip),
                ];
            }
            $rows[] = $row;
        }
        return RailCard::rows(
            'authkey-addresses',
            __('Used from'),
            'fas fa-network-wired',
            $rows,
            null,
            [
                'empty' => __('No address recorded yet.'),
                'note' => Configure::read('MISP.disable_seen_ips_authkeys')
                    ? __('Recording the addresses keys are used from is off on this instance.')
                    : null,
            ]
        );
    }

    /**
     * @param array $authKey
     * @param array $owner ['User' => [...], 'Role' => [...]]
     * @return array
     */
    public function lifecycle(array $authKey, array $owner)
    {
        $key = $authKey['AuthKey'];
        $now = time();
        $expiration = (int)$key['expiration'];
        $created = (int)$key['created'];
        $lastUsed = $this->isUsageLogged() ? $this->lastUsed : null;
        $allowed = array_values(array_filter((array)($key['allowed_ips'] ?? [])));

        if ($expiration && $expiration < $now) {
            $state = 'danger';
            $headline = __('Expired %s.', RailCard::ago($expiration));
        } else if (!empty($owner['User']['disabled'])) {
            $state = 'danger';
            $headline = __('Its owner is disabled, so the key cannot be used.');
        } else if (empty($owner['Role']['perm_auth'])) {
            $state = 'danger';
            $headline = __('Its owner\'s role cannot use auth keys.');
        } else if ($expiration && $expiration - $now < self::EXPIRY_WARNING_DAYS * 86400) {
            $state = 'warn';
            $headline = __('Expires %s.', RailCard::ago($expiration));
        } else if ($this->isUsageLogged() && $lastUsed === null) {
            $state = 'warn';
            $headline = __('Never used since it was created.');
        } else {
            $state = 'ok';
            $headline = $lastUsed
                ? __('Active, last used %s.', RailCard::ago($lastUsed))
                : __('Active.');
        }

        $items = [
            ['label' => __('Created'), 'value' => date('Y-m-d', $created)],
            [
                'label' => __('Expires'),
                'value' => $expiration ? date('Y-m-d', $expiration) : __('Never'),
                'tone' => $expiration && $expiration - $now < self::EXPIRY_WARNING_DAYS * 86400 ? 'warn' : null,
            ],
            ['label' => __('Age'), 'value' => __n('%s day', '%s days', $this->days($now - $created), $this->days($now - $created))],
            ['label' => __('Read only'), 'value' => $key['read_only'] ? __('Yes') : __('No')],
            [
                'label' => __('Allowed from'),
                'value' => empty($allowed) ? __('Anywhere') : implode(', ', $allowed),
            ],
        ];
        return RailCard::status('authkey-lifecycle', __('Lifecycle'), 'fas fa-hourglass-half', $state, $headline, $items);
    }

    private function days($seconds)
    {
        return max(0, (int)floor($seconds / 86400));
    }
}
