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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdProcessResultDTO.php';

/**
 * Test suite for MsgdProcessResultDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdProcessResultDTOTest extends TestCase
{
    /**
     * Tests successful creation from a service result.
     *
     * @return void
     */
    public function testFromArraySuccess(): void
    {
        $dto = new MsgdProcessResultDTO([
            'is_new' => true,
            'has_blueprint' => true,
            'sharing_group_id' => 10,
            'sharing_group_name' => 'Test Group',
        ]);

        $this->assertTrue($dto->isNew);
        $this->assertTrue($dto->hasBlueprint);
        $this->assertSame(10, $dto->sharingGroupId);
        $this->assertSame('Test Group', $dto->sharingGroupName);
    }

    /**
     * Tests false boolean values.
     *
     * @return void
     */
    public function testFromArrayHandlesFalseValues(): void
    {
        $dto = new MsgdProcessResultDTO([
            'is_new' => false,
            'has_blueprint' => false,
            'sharing_group_id' => 20,
            'sharing_group_name' => 'Existing Group',
        ]);

        $this->assertFalse($dto->isNew);
        $this->assertFalse($dto->hasBlueprint);
        $this->assertSame(20, $dto->sharingGroupId);
    }

    /**
     * Tests default values for missing fields.
     *
     * @return void
     */
    public function testFromArrayUsesDefaults(): void
    {
        $dto = new MsgdProcessResultDTO([]);

        $this->assertFalse($dto->isNew);
        $this->assertFalse($dto->hasBlueprint);
        $this->assertSame(0, $dto->sharingGroupId);
        $this->assertSame('', $dto->sharingGroupName);
    }

    /**
     * Tests conversion of scalar values.
     *
     * @return void
     */
    public function testFromArrayCastsScalarValues(): void
    {
        $dto = new MsgdProcessResultDTO([
            'is_new' => 1,
            'has_blueprint' => 0,
            'sharing_group_id' => '42',
            'sharing_group_name' => 'Group',
        ]);

        $this->assertTrue($dto->isNew);
        $this->assertFalse($dto->hasBlueprint);
        $this->assertSame(42, $dto->sharingGroupId);
    }

    /**
     * Tests that the sharing group name is sanitized.
     *
     * @return void
     */
    public function testFromArraySanitizesSharingGroupName(): void
    {
        $dto = new MsgdProcessResultDTO([
            'sharing_group_name' => '<script>alert(1)</script>Group',
        ]);

        $this->assertStringNotContainsString(
            '<script>',
            $dto->sharingGroupName
        );
    }

    /**
     * Tests direct construction.
     *
     * @return void
     */
    public function testDirectConstructorInstantiation(): void
    {
        $dto = new MsgdProcessResultDTO(
            [
                'is_new' => true,
                'has_blueprint' => false,
                'sharing_group_id' => 15,
                'sharing_group_name' => 'Group',
            ]
        );

        $this->assertTrue($dto->isNew);
        $this->assertFalse($dto->hasBlueprint);
        $this->assertSame(15, $dto->sharingGroupId);
        $this->assertSame('Group', $dto->sharingGroupName);
    }
}
