<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/Lib/Utility/MsgdSanitizerUtility.php';
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdUserDTO.php';

/**
 * Test suite for MsgdUserDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdUserDTOTest extends TestCase
{
    private const ORG_UUID = '11111111-1111-4111-8111-111111111111';

    /**
     * Tests successful normalization of a MISP user.
     *
     * @return void
     */
    public function testFromArraySuccess(): void
    {
        $dto = new MsgdUserDTO([
            'id' => 1,
            'org_id' => 10,
            'email' => 'user@example.com',
            'disabled' => false,
            'Role' => [
                'perm_site_admin' => true,
                'perm_sharing_group' => true,
                'perm_sync' => true,
            ],
            'Organisation' => [
                'id' => 10,
                'name' => 'Test Organisation',
                'uuid' => self::ORG_UUID,
            ],
        ]);

        $this->assertSame(1, $dto->id);
        $this->assertSame(10, $dto->orgId);
        $this->assertSame('user@example.com', $dto->email);
        $this->assertSame('Test Organisation', $dto->orgName);
        $this->assertSame(self::ORG_UUID, $dto->orgUuid);
        $this->assertTrue($dto->isSiteAdmin);
        $this->assertTrue($dto->canUseSharingGroups);
        $this->assertTrue($dto->canSync);
        $this->assertFalse($dto->disabled);
    }

    /**
     * Tests default values for missing fields.
     *
     * @return void
     */
    public function testFromArrayUsesDefaults(): void
    {
        $dto = new MsgdUserDTO([]);

        $this->assertSame(0, $dto->id);
        $this->assertSame(0, $dto->orgId);
        $this->assertSame('', $dto->email);
        $this->assertSame('', $dto->orgName);
        $this->assertSame('', $dto->orgUuid);
        $this->assertFalse($dto->isSiteAdmin);
        $this->assertFalse($dto->canUseSharingGroups);
        $this->assertFalse($dto->canSync);
        $this->assertFalse($dto->disabled);
    }

    /**
     * Tests normalization when Role is not an array.
     *
     * @return void
     */
    public function testFromArrayHandlesInvalidRoleStructure(): void
    {
        $dto = new MsgdUserDTO([
            'id' => 5,
            'Role' => 'invalid',
        ]);

        $this->assertSame(5, $dto->id);
        $this->assertFalse($dto->isSiteAdmin);
        $this->assertFalse($dto->canUseSharingGroups);
        $this->assertFalse($dto->canSync);
    }

    /**
     * Tests normalization when Organisation is not an array.
     *
     * @return void
     */
    public function testFromArrayHandlesInvalidOrganisationStructure(): void
    {
        $dto = new MsgdUserDTO([
            'id' => 5,
            'Organisation' => 'invalid',
        ]);

        $this->assertSame(5, $dto->id);
        $this->assertSame('', $dto->orgName);
        $this->assertSame('', $dto->orgUuid);
    }

    /**
     * Tests disabled users.
     *
     * @return void
     */
    public function testFromArrayHandlesDisabledUser(): void
    {
        $dto = new MsgdUserDTO([
            'id' => 1,
            'org_id' => 10,
            'disabled' => true,
        ]);

        $this->assertTrue($dto->disabled);
    }

    /**
     * Tests that email and organization values are sanitized.
     *
     * @return void
     */
    public function testFromArraySanitizesStringValues(): void
    {
        $dto = new MsgdUserDTO([
            'email' => '<script>alert(1)</script>user@example.com',
            'Organisation' => [
                'name' => '<script>Organisation</script>',
                'uuid' => '<script>' . self::ORG_UUID . '</script>',
            ],
        ]);

        assert(is_string($dto->orgName));
        assert(is_string($dto->orgUuid));

        $this->assertStringNotContainsString('<script>', $dto->email);
        $this->assertStringNotContainsString('<script>', $dto->orgName);
        $this->assertStringNotContainsString('<script>', $dto->orgUuid);
    }

    /**
     * Tests conversion to the normalized MISP model structure.
     *
     * @return void
     */
    public function testToModelArray(): void
    {
        $dto = new MsgdUserDTO([
            'id' => 1,
            'org_id' => 10,
            'email' => 'user@example.com',
            'disabled' => false,
            'Role' => [
                'perm_site_admin' => true,
                'perm_sharing_group' => true,
                'perm_sync' => false,
            ],
            'Organisation' => [
                'id' => 10,
                'name' => 'Test Organisation',
                'uuid' => self::ORG_UUID,
            ],
        ]);

        $this->assertSame([
            'id' => 1,
            'org_id' => 10,
            'email' => 'user@example.com',
            'disabled' => false,
            'Role' => [
                'perm_site_admin' => true,
                'perm_sharing_group' => true,
                'perm_sync' => false,
            ],
            'Organisation' => [
                'id' => 10,
                'name' => 'Test Organisation',
                'uuid' => self::ORG_UUID,
            ],
        ], $dto->toModelArray());
    }

    /**
     * Tests direct construction with nullable organization fields.
     *
     * @return void
     */
    public function testDirectConstructorAcceptsNullableOrganisationFields(): void
    {
        $dto = new MsgdUserDTO([
            'id' => 1,
            'org_id' => 10,
            'email' => 'user@example.com',
            'disabled' => false,
            'Role' => [
                'perm_site_admin' => false,
                'perm_sharing_group' => false,
                'perm_sync' => false,
            ],
            'Organisation' => [
                'id' => 10,
                'name' => '',
                'uuid' => '',
            ],
        ]);

        $this->assertEmpty($dto->orgName);
        $this->assertEmpty($dto->orgUuid);
    }
}
