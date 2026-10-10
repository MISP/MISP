<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Represents a normalized Sharing Group Blueprint.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
class MsgdBlueprintDTO
{
    /**
     * @var MsgdBlueprintRulesDTO
     */
    public readonly MsgdBlueprintRulesDTO $rules;
    /**
     * @var int
     */
    public readonly int $id;
    /**
     * @var string
     */
    public readonly string $uuid;
    /**
     * @var string
     */
    public string $name;
    /**
     * @var int
     */
    public readonly int $userId;
    /**
     * @var int
     */
    public readonly int $orgId;
    /**
     * @var int
     */
    public int $sharingGroupId;

    /**
     * Constructs a DTO from a MISP SharingGroupBlueprint record or data array.
     *
     * @param array<string, mixed> $data
     *
     * @throws InvalidArgumentException
     */
    public function __construct(array $data = [])
    {
        $groupData = $data['SharingGroupBlueprint'] ?? $data;

        if (!is_array($groupData)) {
            throw new InvalidArgumentException('Sharing Group Blueprint data must be an array.');
        }

        $rawUuid = $groupData['uuid'] ?? '';
        $uuid = is_scalar($rawUuid) ? (string)$rawUuid : '';

        if ($uuid !== '' && !MsgdSanitizerUtility::isValidUuid($uuid)) {
            throw new InvalidArgumentException('Sharing Group Blueprint contains an invalid UUID.');
        }
        $this->uuid = $uuid;

        $rawName = $groupData['name'] ?? '';
        $this->name = MsgdSanitizerUtility::sanitizeString(is_scalar($rawName) ? (string)$rawName : '');

        $rawId = $groupData['id'] ?? 0;
        $this->id = is_numeric($rawId) ? (int)$rawId : 0;

        $rawUserId = $groupData['user_id'] ?? 0;
        $this->userId = is_numeric($rawUserId) ? (int)$rawUserId : 0;

        $rawOrgId = $groupData['org_id'] ?? 0;
        $this->orgId = is_numeric($rawOrgId) ? (int)$rawOrgId : 0;

        $rawSharingGroupId = $groupData['sharing_group_id'] ?? 0;
        $this->sharingGroupId = is_numeric($rawSharingGroupId) ? (int)$rawSharingGroupId : 0;

        $rawRules = $groupData['rules'] ?? [];

        if ($rawRules instanceof MsgdBlueprintRulesDTO) {
            $this->rules = $rawRules;
        } else {
            if (!is_array($rawRules) && !is_string($rawRules)) {
                $rawRules = [];
            }

            /** @var array<string, mixed>|string $rules */
            $rules = $rawRules;
            $this->rules = new MsgdBlueprintRulesDTO($rules);
        }
    }

    /**
     * Converts this DTO into the array expected by MISP.
     *
     * @return array<string, array<string, mixed>>
     */
    public function toModelArray(): array
    {
        return [
            'SharingGroupBlueprint' => [
                'id' => $this->id,
                'uuid' => $this->uuid,
                'name' => $this->name,
                'user_id' => $this->userId,
                'org_id' => $this->orgId,
                'sharing_group_id' => $this->sharingGroupId,
                'rules' => json_encode($this->rules->raw),
            ],
        ];
    }
}
