<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdMirrorGroupsDTO.php';

/**
 * Test suite for MsgdMirrorGroupsDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdMirrorGroupsDTOTest extends TestCase
{
    private const UUID_1 = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';

    private const UUID_2 = 'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22';

    /**
     * Tests direct construction.
     *
     * @return void
     */
    public function testDirectConstructorInstantiation(): void
    {
        $dto = new MsgdMirrorGroupsDTO(
            ids: [10, 20],
            uuids: [self::UUID_1, self::UUID_2]
        );

        $this->assertSame([10, 20], $dto->ids);
        $this->assertSame([self::UUID_1, self::UUID_2], $dto->uuids);
    }

    /**
     * Tests default constructor values.
     *
     * @return void
     */
    public function testDirectConstructorDefaults(): void
    {
        $dto = new MsgdMirrorGroupsDTO();

        $this->assertSame([], $dto->ids);
        $this->assertSame([], $dto->uuids);
    }

    /**
     * Tests creation from resolved identifiers.
     *
     * @return void
     */
    public function testFromArray(): void
    {
        $dto = new MsgdMirrorGroupsDTO(
            [10, 20, 10],
            [self::UUID_1, self::UUID_2, self::UUID_1]
        );

        $this->assertSame([10, 20], $dto->ids);
        $this->assertSame([self::UUID_1, self::UUID_2], $dto->uuids);
    }

    /**
     * Tests creation from empty arrays.
     *
     * @return void
     */
    public function testFromArrayAcceptsEmptyArrays(): void
    {
        $dto = new MsgdMirrorGroupsDTO([], []);

        $this->assertSame([], $dto->ids);
        $this->assertSame([], $dto->uuids);
    }

    /**
     * Tests that identifier order is preserved while duplicates are removed.
     *
     * @return void
     */
    public function testFromArrayPreservesOrder(): void
    {
        $dto = new MsgdMirrorGroupsDTO(
            [20, 10, 20],
            [self::UUID_2, self::UUID_1, self::UUID_2]
        );

        $this->assertSame([20, 10], $dto->ids);
        $this->assertSame([self::UUID_2, self::UUID_1], $dto->uuids);
    }
}
