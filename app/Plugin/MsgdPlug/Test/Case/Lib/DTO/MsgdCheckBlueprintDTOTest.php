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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdCheckBlueprintDTO.php';

/**
 * Test suite for MsgdCheckBlueprintDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdCheckBlueprintDTOTest extends TestCase
{
    private const UUID_1 = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';

    private const UUID_2 = 'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22';

    /**
     * Tests successful instantiation with valid integer IDs.
     *
     * @return void
     */
    public function testFromRequestDataSuccessWithIntegerIds(): void
    {
        $dto = new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [10, '25', 42],
            ],
        ], true);

        $this->assertSame([10, 25, 42], $dto->groups);
    }

    /**
     * Tests successful instantiation with valid UUIDs.
     *
     * @return void
     */
    public function testFromRequestDataSuccessWithUuids(): void
    {
        $dto = new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [self::UUID_1, self::UUID_2],
            ],
        ]);

        $this->assertSame([self::UUID_1, self::UUID_2], $dto->groups);
    }

    /**
     * Tests that UUID mode is the default.
     *
     * @return void
     */
    public function testFromRequestDataDefaultsToUuidMode(): void
    {
        $dto = new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [self::UUID_1],
            ],
        ]);

        $this->assertSame([self::UUID_1], $dto->groups);
    }

    /**
     * Tests exception for missing root key.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionMissingRootKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Payload must be enclosed under the "MsgdPlug" root key.'
        );

        new MsgdCheckBlueprintDTO(['groups' => [1]]);
    }

    /**
     * Tests exception when the root key is not an array.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionWhenRootKeyIsNotArray(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => 'invalid',
        ]);
    }

    /**
     * Tests exception for an empty groups array.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionWithEmptyGroups(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "groups" is required and must be a non-empty array.'
        );

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [],
            ],
        ]);
    }

    /**
     * Tests exception when groups is missing.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionWhenGroupsKeyIsMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [],
        ]);
    }

    /**
     * Tests exception for unauthorized fields.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionWithUnauthorizedFields(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unauthorized fields detected in payload: [unauthorized_key].'
        );

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [10],
                'unauthorized_key' => 'value',
            ],
        ], true);
    }

    /**
     * Tests exception for non-scalar group values.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionWithNonScalarInGroups(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "groups" contains invalid non-scalar values.'
        );

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [[123]],
            ],
        ]);
    }

    /**
     * Tests exception for empty group values.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionWithEmptyGroup(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "groups" contains empty values.'
        );

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => ['   '],
            ],
        ]);
    }

    /**
     * Tests exception for invalid integer IDs.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionWithInvalidIntegerId(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "groups" contains invalid integer IDs.'
        );

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => ['abc'],
            ],
        ], true);
    }

    /**
     * Tests that zero IDs are rejected.
     *
     * @return void
     */
    public function testFromRequestDataRejectsZeroId(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [0],
            ],
        ], true);
    }

    /**
     * Tests that negative IDs are rejected.
     *
     * @return void
     */
    public function testFromRequestDataRejectsNegativeId(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [-1],
            ],
        ], true);
    }

    /**
     * Tests that zero-padded IDs are rejected.
     *
     * @return void
     */
    public function testFromRequestDataRejectsZeroPaddedId(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => ['01'],
            ],
        ], true);
    }

    /**
     * Tests exception for invalid UUIDs.
     *
     * @return void
     */
    public function testFromRequestDataThrowsExceptionWithInvalidUuid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "groups" contains invalid UUIDs.'
        );

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => ['not-a-uuid'],
            ],
        ]);
    }

    /**
     * Tests that integer IDs are rejected in UUID mode.
     *
     * @return void
     */
    public function testFromRequestDataRejectsIdsInUuidMode(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [10, 20],
            ],
        ]);
    }

    /**
     * Tests direct construction.
     *
     * @return void
     */
    public function testDirectConstructorInstantiation(): void
    {
        $dto = new MsgdCheckBlueprintDTO([
            'MsgdPlug' => [
                'groups' => [1, 2, 3],
            ]
        ], true);

        $this->assertSame([1, 2, 3], $dto->groups);
    }
}
