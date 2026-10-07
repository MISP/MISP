<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Represents the result of a single or multiple Sharing Group processing execution.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
readonly final class MsgdProcessResultDTO
{
    /**
     * @var bool
     */
    public bool $isNew;

    /**
     * @var bool
     */
    public bool $hasBlueprint;

    /**
     * @var int
     */
    public int $sharingGroupId;

    /**
     * @var string
     */
    public string $sharingGroupName;

    /**
     * Creates a DTO from the service result array.
     *
     * @param array<string, mixed> $data
     */
    public function __construct(array $data = [])
    {
        $rawGroupId = $data['sharing_group_id'] ?? 0;
        $sharingGroupId = is_numeric($rawGroupId) ? (int)$rawGroupId : 0;

        $rawGroupName = $data['sharing_group_name'] ?? '';
        $sharingGroupName = is_scalar($rawGroupName) ? (string)$rawGroupName : '';

        $this->isNew = (bool)($data['is_new'] ?? false);
        $this->hasBlueprint = (bool)($data['has_blueprint'] ?? false);
        $this->sharingGroupId = $sharingGroupId;
        $this->sharingGroupName = MsgdSanitizerUtility::sanitizeString($sharingGroupName);
    }
}
