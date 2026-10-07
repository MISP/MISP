<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Represents normalized Sharing Group Blueprint rules.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
readonly final class MsgdBlueprintRulesDTO
{
    /**
     * @var array<string, mixed>
     */
    public array $raw;

    /**
     * @var array<int, int>
     */
    public array $sharingGroupsIds;

    /**
     * @var array<int, string>
     */
    public array $sharingGroupsUuids;

    /**
     * @var array<int, int|string>
     */
    public array $allSharingGroupIdentifiers;

    /**
     * Initializes DTO from an array or JSON string of rules.
     *
     * @param string|array<string, mixed> $rules
     */
    public function __construct(string|array $rules = [])
    {
        /** @var array<string, mixed> $parsed */
        $parsed = [];

        if (is_string($rules)) {
            try {
                $decoded = json_decode($rules, true);
                if (is_array($decoded)) {
                    /** @var array<string, mixed> $decoded */
                    $parsed = $decoded;
                }
            } catch (Throwable) {
                $parsed = [];
            }
        } else {
            /** @var array<string, mixed> $parsed */
            $parsed = $rules;
        }

        $andConditions = isset($parsed['AND']) && is_array($parsed['AND']) ? $parsed['AND'] : [];
        $orConditions = isset($andConditions['OR']) && is_array($andConditions['OR']) ? $andConditions['OR'] : [];

        $ids = $orConditions['sharing_group_id'] ?? [];
        $uuids = $orConditions['sharing_group_uuid'] ?? [];

        $rawIds = is_array($ids) ? array_values($ids) : (is_scalar($ids) ? [$ids] : []);
        $rawUuids = is_array($uuids) ? array_values($uuids) : (is_scalar($uuids) ? [$uuids] : []);

        try {
            /** @var array<int|string> $rawIds */
            $sharingGroupsIds = self::cleanIds($rawIds);

            /** @var array<string> $rawUuids */
            $sharingGroupsUuids = self::cleanUuids($rawUuids);

            $allSharingGroupIdentifiers = array_values(
                array_unique(
                    array_merge($sharingGroupsIds, $sharingGroupsUuids),
                    SORT_REGULAR
                )
            );
        } catch (Throwable) {
            $sharingGroupsIds = [];
            $sharingGroupsUuids = [];
            $allSharingGroupIdentifiers = [];
        }

        $this->raw = $parsed;
        $this->sharingGroupsIds = $sharingGroupsIds;
        $this->sharingGroupsUuids = $sharingGroupsUuids;
        $this->allSharingGroupIdentifiers = $allSharingGroupIdentifiers;
    }

    /**
     * Creates blueprint rules from Sharing Group identifiers.
     *
     * @param array<int|string> $identifiers
     *
     * @return MsgdBlueprintRulesDTO
     *
     * @throws InvalidArgumentException
     */
    public static function generateFromIdentifiers(array $identifiers): MsgdBlueprintRulesDTO
    {
        $ids = [];
        $uuids = [];

        foreach ($identifiers as $identifier) {
            if (is_int($identifier) && $identifier > 0) {
                $ids[] = $identifier;
                continue;
            }

            if (!is_string($identifier)) {
                continue;
            }

            $identifier = trim($identifier);

            if ($identifier === '') {
                continue;
            }

            if (ctype_digit($identifier) && (int)$identifier > 0) {
                $ids[] = (int)$identifier;
                continue;
            }

            if (MsgdSanitizerUtility::isValidUuid($identifier)) {
                $uuids[] = $identifier;
            }
        }

        $ids = array_values(array_unique($ids));
        $uuids = array_values(array_unique($uuids));

        $orConditions = [];

        if ($ids !== []) {
            $orConditions['sharing_group_id'] = count($ids) === 1 ? $ids[0] : $ids;
        }

        if ($uuids !== []) {
            $orConditions['sharing_group_uuid'] = count($uuids) === 1 ? $uuids[0] : $uuids;
        }

        return new self(['AND' => ['OR' => $orConditions]]);
    }

    /**
     * Normalizes Sharing Group IDs.
     *
     * @param array<int|string> $items
     *
     * @return array<int, int>
     */
    private static function cleanIds(array $items): array
    {
        $result = [];

        foreach ($items as $item) {
            if (is_int($item) && $item > 0) {
                $result[] = $item;
                continue;
            }

            if (is_string($item) && ctype_digit($item) && (int)$item > 0) {
                $result[] = (int)$item;
            }
        }

        return array_values(array_unique($result));
    }

    /**
     * Normalizes and validates Sharing Group UUIDs.
     *
     * @param array<string> $items
     *
     * @return array<int, string>
     */
    private static function cleanUuids(array $items): array
    {
        $result = [];

        foreach ($items as $item) {
            $trimmed = trim($item);
            if (MsgdSanitizerUtility::isValidUuid($trimmed)) {
                $result[] = $trimmed;
            }
        }

        return array_values(array_unique($result));
    }
}
