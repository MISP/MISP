<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Represents a normalized Sharing Group entity return.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
final class MsgdSharingGroupDTO
{
    public readonly int $id;
    public readonly string $uuid;
    public readonly string $name;

    /**
     * Constructs DTO directly from CakePHP array structure.
     *
     * @param array<string, mixed> $data
     */
    public function __construct(array $data)
    {
        $rawGroupData = $data['SharingGroup'] ?? $data;
        $groupData = is_array($rawGroupData) ? $rawGroupData : $data;

        $rawId = $groupData['id'] ?? 0;
        $this->id = is_numeric($rawId) ? (int)$rawId : 0;

        $rawUuid = $groupData['uuid'] ?? '';
        $uuid = is_scalar($rawUuid) ? (string)$rawUuid : '';

        $rawName = $groupData['name'] ?? '';
        $name = is_scalar($rawName) ? (string)$rawName : '';

        $this->uuid = MsgdSanitizerUtility::sanitizeString($uuid);
        $this->name = MsgdSanitizerUtility::sanitizeString($name);
    }
}
