<?php
App::uses('LazyRailCards', 'Tools/RailCards');

/**
 * Rail cards for a warninglist. $warninglist is ['Warninglist' => [...]]
 * without its entries, which can number in the millions.
 */
class WarninglistRailCards extends LazyRailCards
{
    const READ_CAP = 100000;
    const TLD_LIMIT = 5;

    protected function railCardUrl()
    {
        return '/warninglists/railCard/';
    }

    protected function lazyCards()
    {
        return [
            'warninglist-inventory' => ['inventory', __('Contents'), 'fas fa-list-check', 'inventory'],
        ];
    }

    /**
     * What kind of values the list holds and, for domains, under which
     * top-level domains. Entries are read up to READ_CAP.
     *
     * @param array $warninglist
     * @return array
     */
    public function inventory(array $warninglist)
    {
        $id = (int)$warninglist['Warninglist']['id'];
        $isRegex = $warninglist['Warninglist']['type'] === 'regex';
        $Entry = ClassRegistry::init('WarninglistEntry');
        $total = $Entry->find('count', [
            'recursive' => -1,
            'conditions' => ['WarninglistEntry.warninglist_id' => $id],
        ]);
        $values = $Entry->find('column', [
            'conditions' => ['WarninglistEntry.warninglist_id' => $id],
            'fields' => ['WarninglistEntry.value'],
            'limit' => self::READ_CAP,
        ]);
        $read = count($values);

        $kinds = [];
        $tlds = [];
        foreach ($values as $value) {
            $kind = $isRegex ? 'pattern' : $this->kind($value);
            $kinds[$kind] = ($kinds[$kind] ?? 0) + 1;
            if ($kind === 'domain') {
                $tld = strtolower(substr(strrchr(rtrim($value, '.'), '.'), 1));
                $tlds[$tld] = ($tlds[$tld] ?? 0) + 1;
            }
        }
        unset($values);

        $groups = [];
        if ($read) {
            arsort($kinds);
            $labels = $this->kindLabels();
            $facets = [];
            foreach ($kinds as $kind => $count) {
                $facets[] = ['label' => $labels[$kind], 'count' => $count, 'tone' => $kind === 'other' ? 'muted' : null];
            }
            $groups[] = [
                'key' => 'kinds',
                'label' => __('Kinds of value'),
                'icon' => 'fas fa-shapes',
                'count' => $read,
                'partition' => true,
                'facets' => $facets,
            ];
        }
        if (count($tlds) > 1) {
            arsort($tlds);
            $facets = [];
            foreach (array_slice($tlds, 0, self::TLD_LIMIT, true) as $tld => $count) {
                $facets[] = ['label' => '.' . $tld, 'count' => $count];
            }
            $groups[] = [
                'key' => 'tlds',
                'label' => __n('%s top-level domain', '%s top-level domains', count($tlds), count($tlds)),
                'icon' => 'fas fa-globe',
                'count' => $kinds['domain'],
                'partition' => true,
                'facets' => $facets,
                'more' => max(0, count($tlds) - self::TLD_LIMIT),
            ];
        }
        list(, $title, $icon) = $this->head('warninglist-inventory');
        return RailCard::inventory(
            'warninglist-inventory',
            $title,
            $icon,
            ['count' => $total, 'label' => __n('entry', 'entries', $total)],
            $groups,
            false,
            [
                'link' => ['label' => __('Entries'), 'href' => '#tab-entries'],
                'empty' => __('This list has no entry.'),
                'note' => $read < $total ? __('Kinds counted over the first %s entries.', number_format($read)) : null,
                'lazy' => true,
            ]
        );
    }

    private function kindLabels()
    {
        return [
            'ipv4' => __('IPv4'),
            'ipv6' => __('IPv6'),
            'domain' => __('Domains'),
            'url' => __('URLs'),
            'email' => __('Email addresses'),
            'md5' => __('MD5'),
            'sha1' => __('SHA1'),
            'sha256' => __('SHA256'),
            'sha512' => __('SHA512'),
            'pattern' => __('Patterns'),
            'other' => __('Other'),
        ];
    }

    /**
     * @param string $value
     * @return string a key of kindLabels()
     */
    private function kind($value)
    {
        $value = trim($value);
        $address = explode('/', $value, 2)[0];
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 'ipv4';
        }
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 'ipv6';
        }
        if (strpos($value, '://') !== false) {
            return 'url';
        }
        if (strpos($value, '@') !== false) {
            return 'email';
        }
        if (ctype_xdigit($value)) {
            $hashes = [32 => 'md5', 40 => 'sha1', 64 => 'sha256', 128 => 'sha512'];
            if (isset($hashes[strlen($value)])) {
                return $hashes[strlen($value)];
            }
        }
        if (preg_match('/^\.?(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*\.?$/i', $value)) {
            return 'domain';
        }
        return 'other';
    }

    /**
     * Whether this list alone would flag $value, by its own matching rule.
     *
     * @param array $warninglist
     * @param string $value
     * @return array ['value', 'hit' => bool, 'matched' => string|null,
     *               'comment' => string|null, 'enabled' => bool]
     */
    public function test(array $warninglist, $value)
    {
        $Warninglist = ClassRegistry::init('Warninglist');
        $value = trim((string)$value);
        $type = $warninglist['Warninglist']['type'];
        if ($value === '') {
            $result = false;
        } else if ($type === 'string' || $type === 'hostname') {
            $result = $this->lookup($warninglist, $value);
        } else {
            $result = $Warninglist->checkValue($Warninglist->getFilteredEntries($warninglist), $value, '', $type);
        }
        $comment = null;
        if ($result !== false) {
            $candidates = [$result[0]];
            // CidrTool answers with the network; a single address is often stored bare
            if ($type === 'cidr' && preg_match('#^(.+)/(32|128)$#', $result[0], $m)) {
                $candidates[] = $m[1];
            }
            $entry = $Warninglist->WarninglistEntry->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'WarninglistEntry.warninglist_id' => $warninglist['Warninglist']['id'],
                    'WarninglistEntry.value' => $candidates,
                ],
                'fields' => ['WarninglistEntry.value', 'WarninglistEntry.comment'],
            ]);
            if (!empty($entry)) {
                $result[0] = $entry['WarninglistEntry']['value'];
                $comment = $entry['WarninglistEntry']['comment'];
            }
        }
        return [
            'value' => $value,
            'hit' => $result !== false,
            'matched' => $result === false ? null : $result[0],
            'comment' => $comment === '' ? null : $comment,
            'enabled' => (bool)$warninglist['Warninglist']['enabled'],
        ];
    }

    /**
     * Warninglist::checkValue's string and hostname rules, answered through
     * the (warninglist_id, value) index instead of loading the whole list.
     *
     * @param array $warninglist
     * @param string $value
     * @return array|false [matched entry, value]
     */
    private function lookup(array $warninglist, $value)
    {
        $Entry = ClassRegistry::init('WarninglistEntry');
        $find = function (array $candidates) use ($Entry, $warninglist) {
            return $Entry->find('column', [
                'conditions' => [
                    'WarninglistEntry.warninglist_id' => $warninglist['Warninglist']['id'],
                    'WarninglistEntry.value' => array_values(array_unique($candidates)),
                ],
                'fields' => ['WarninglistEntry.value'],
            ]);
        };
        if ($warninglist['Warninglist']['type'] === 'string') {
            return in_array($value, $find([$value]), true) ? [$value, $value] : false;
        }
        $parts = explode('/', $value);
        $hostname = strpos($value, '//') === false ? $parts[0] : ($parts[2] ?? null);
        if ($hostname === null) {
            return false;
        }
        $suffixes = [];
        $rebuilt = '';
        foreach (array_reverse(explode('.', rtrim($hostname, '.'))) as $piece) {
            $rebuilt = $rebuilt === '' ? $piece : $piece . '.' . $rebuilt;
            $suffixes[] = $rebuilt;
        }
        $candidates = [];
        foreach ($suffixes as $suffix) {
            array_push($candidates, $suffix, ".$suffix", "$suffix.", ".$suffix.");
        }
        $listed = [];
        foreach ($find($candidates) as $entry) {
            $listed[strtolower(trim($entry, '.'))] = $entry;
        }
        foreach ($suffixes as $suffix) {
            if (isset($listed[$suffix])) {
                return [$listed[$suffix], $value];
            }
        }
        return false;
    }
}
