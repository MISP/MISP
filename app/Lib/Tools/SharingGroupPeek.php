<?php

/**
 * What a sharing group's popover says about it: who owns it, who is in it
 * and how far it travels. Pure: the controller does the queries.
 */
class SharingGroupPeek
{
    /** Members listed before the "+N more" note. */
    const LIMIT = 8;

    /**
     * @param array $sg SharingGroup row with Organisation and SharingGroupServer
     * @param array|null $members SharingGroupOrg rows with Organisation, or null
     *  when the reader may not see who the members are
     * @param int $memberCount every member row, listed or not
     * @param int $readerOrgId
     * @return array
     */
    public static function build(array $sg, $members, $memberCount, $readerOrgId)
    {
        $group = $sg['SharingGroup'];
        $owner = $sg['Organisation'] ?? [];
        $ownerId = (int)($owner['id'] ?? $group['org_id'] ?? 0);
        $readerOrgId = (int)$readerOrgId;

        $pills = [];
        if (empty($group['active'])) {
            $pills[] = ['label' => __('Inactive'), 'icon' => 'fas fa-pause', 'warn' => true];
        }
        if (empty($group['local'])) {
            $pills[] = ['label' => __('Received through sync'), 'icon' => 'fas fa-arrow-down', 'warn' => false];
        }

        $peek = [
            'id' => (int)$group['id'],
            'name' => (string)$group['name'],
            'owner' => ['id' => $ownerId, 'name' => (string)($owner['name'] ?? ''), 'uuid' => (string)($owner['uuid'] ?? '')],
            'pills' => $pills,
            'member_count' => (int)$memberCount,
            'members' => null,
            'more' => 0,
            'everyone' => false,
            'reach' => null,
            'notes' => self::notes($group),
        ];
        if ($members === null) {
            return $peek;
        }

        $listed = [];
        foreach ($members as $row) {
            $org = $row['Organisation'] ?? [];
            $id = (int)($row['SharingGroupOrg']['org_id'] ?? $org['id'] ?? 0);
            if (!$id || isset($listed[$id])) {
                continue;
            }
            $listed[$id] = [
                'id' => $id,
                'name' => (string)($org['name'] ?? ''),
                'uuid' => (string)($org['uuid'] ?? ''),
                'owner' => $id === $ownerId,
                'you' => $id === $readerOrgId,
                'extend' => !empty($row['SharingGroupOrg']['extend']),
            ];
        }
        $listed = array_values($listed);
        usort($listed, function ($a, $b) {
            $rank = function ($m) {
                return $m['owner'] ? 0 : ($m['you'] ? 1 : 2);
            };
            return $rank($a) - $rank($b) ?: strnatcasecmp($a['name'], $b['name']);
        });
        $peek['members'] = $listed;
        $peek['more'] = max(0, (int)$memberCount - count($listed));

        $servers = $sg['SharingGroupServer'] ?? [];
        $remote = 0;
        foreach ($servers as $server) {
            if ((int)$server['server_id'] === 0) {
                $peek['everyone'] = $peek['everyone'] || !empty($server['all_orgs']);
            } else {
                $remote++;
            }
        }
        if (!empty($group['roaming'])) {
            $peek['reach'] = ['mode' => __('Roaming'), 'text' => __('it travels to any instance its members connect to.')];
        } elseif ($remote) {
            $peek['reach'] = ['mode' => null, 'text' => __n('Pushed to %s other instance.', 'Pushed to %s other instances.', $remote, $remote)];
        } else {
            $peek['reach'] = ['mode' => null, 'text' => __('Stays on this instance.')];
        }
        return $peek;
    }

    /**
     * Releasability and description, each only when it says more than the
     * name (many groups repeat their name in both).
     *
     * @param array $group
     * @return array label, text
     */
    private static function notes(array $group)
    {
        $said = [self::flat($group['name'] ?? '')];
        $notes = [];
        foreach (['releasability' => __('Releasable to'), 'description' => __('Description')] as $field => $label) {
            $text = trim((string)($group[$field] ?? ''));
            if ($text === '' || in_array(self::flat($text), $said, true)) {
                continue;
            }
            $said[] = self::flat($text);
            $notes[] = ['label' => $label, 'text' => $text];
        }
        return $notes;
    }

    private static function flat($text)
    {
        return strtolower(preg_replace('/\s+/u', ' ', trim((string)$text)));
    }
}
