<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Represents a normalized MISP User entity.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.DTO
 */
readonly final class MsgdUserDTO
{
    /**
     * @var int
     */
    public int $id;
    /**
     * @var int
     */
    public int $orgId;
    /**
     * @var string
     */
    public string $email;
    /**
     * @var string|null
     */
    public ?string $orgName;
    /**
     * @var string|null
     */
    public ?string $orgUuid;
    /**
     * @var bool
     */
    public bool $isSiteAdmin;
    /**
     * @var bool
     */
    public bool $canUseSharingGroups;
    /**
     * @var bool
     */
    public bool $canSync;
    /**
     * @var bool
     */
    public bool $disabled;

    /**
     * Constructs a normalized user DTO from the authenticated MISP user data.
     *
     * @param array<string, mixed> $data
     */
    public function __construct(array $data)
    {
        $role = is_array($data['Role'] ?? null)
            ? $data['Role']
            : [];

        $organisation = is_array($data['Organisation'] ?? null)
            ? $data['Organisation']
            : [];

        $rawId = $data['id'] ?? 0;
        $this->id = is_numeric($rawId) ? (int)$rawId : 0;

        $rawOrgId = $data['org_id'] ?? 0;
        $this->orgId = is_numeric($rawOrgId) ? (int)$rawOrgId : 0;

        $rawEmail = $data['email'] ?? '';
        $email = is_scalar($rawEmail) ? (string)$rawEmail : '';
        $this->email = MsgdSanitizerUtility::sanitizeString($email);

        $rawOrgName = $organisation['name'] ?? '';
        $orgName = is_scalar($rawOrgName) ? (string)$rawOrgName : '';
        $this->orgName = MsgdSanitizerUtility::sanitizeString($orgName);

        $rawOrgUuid = $organisation['uuid'] ?? '';
        $orgUuid = is_scalar($rawOrgUuid) ? (string)$rawOrgUuid : '';
        $this->orgUuid = MsgdSanitizerUtility::sanitizeString($orgUuid);

        $this->isSiteAdmin = (bool)($role['perm_site_admin'] ?? false);
        $this->canUseSharingGroups = (bool)($role['perm_sharing_group'] ?? false);
        $this->canSync = (bool)($role['perm_sync'] ?? false);
        $this->disabled = (bool)($data['disabled'] ?? false);
    }

    /**
     * Converts the DTO into the normalized user structure expected
     * by plugin services and native MISP model methods.
     *
     * @return array<string, mixed>
     */
    public function toModelArray(): array
    {
        return [
            'id' => $this->id,
            'org_id' => $this->orgId,
            'email' => $this->email,
            'disabled' => $this->disabled,
            'Role' => [
                'perm_site_admin' => $this->isSiteAdmin,
                'perm_sharing_group' => $this->canUseSharingGroups,
                'perm_sync' => $this->canSync,
            ],
            'Organisation' => [
                'id' => $this->orgId,
                'name' => $this->orgName,
                'uuid' => $this->orgUuid,
            ],
        ];
    }
}
