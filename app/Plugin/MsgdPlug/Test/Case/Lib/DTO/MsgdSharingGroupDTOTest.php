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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdSharingGroupDTO.php';

/**
 * Test suite for MsgdSharingGroupDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdSharingGroupDTOTest extends TestCase
{
    private const UUID = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';

    /**
     * Tests creation from a CakePHP SharingGroup structure.
     *
     * @return void
     */
    public function testFromArraySuccess(): void
    {
        $dto = new MsgdSharingGroupDTO([
            'SharingGroup' => [
                'id' => 10,
                'uuid' => self::UUID,
                'name' => 'Test Group',
            ],
        ]);

        $this->assertSame(10, $dto->id);
        $this->assertSame(self::UUID, $dto->uuid);
        $this->assertSame('Test Group', $dto->name);
    }

    /**
     * Tests creation from an unwrapped structure.
     *
     * @return void
     */
    public function testFromArrayAcceptsUnwrappedData(): void
    {
        $dto = new MsgdSharingGroupDTO([
            'id' => '20',
            'uuid' => self::UUID,
            'name' => 'Group',
        ]);

        $this->assertSame(20, $dto->id);
        $this->assertSame(self::UUID, $dto->uuid);
        $this->assertSame('Group', $dto->name);
    }

    /**
     * Tests default values.
     *
     * @return void
     */
    public function testFromArrayUsesDefaults(): void
    {
        $dto = new MsgdSharingGroupDTO([]);

        $this->assertSame(0, $dto->id);
        $this->assertSame('', $dto->uuid);
        $this->assertSame('', $dto->name);
    }

    /**
     * Tests sanitization of the UUID and name.
     *
     * @return void
     */
    public function testFromArraySanitizesValues(): void
    {
        $dto = new MsgdSharingGroupDTO([
            'uuid' => '  ' . self::UUID . '  ',
            'name' => '<script>alert(1)</script>Group',
        ]);

        $this->assertStringNotContainsString(
            '<script>',
            $dto->name
        );
    }

    /**
     * Tests direct construction.
     *
     * @return void
     */
    public function testDirectConstructorInstantiation(): void
    {
        $dto = new MsgdSharingGroupDTO(
            ['SharingGroup' => ['id' => 10, 'uuid' => self::UUID, 'name' => 'Group']]
        );

        $this->assertSame(10, $dto->id);
        $this->assertSame(self::UUID, $dto->uuid);
        $this->assertSame('Group', $dto->name);
    }
}
