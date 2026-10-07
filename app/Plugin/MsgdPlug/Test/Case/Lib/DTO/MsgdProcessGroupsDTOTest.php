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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdProcessGroupsDTO.php';

/**
 * Test suite for MsgdProcessGroupsDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdProcessGroupsDTOTest extends TestCase
{
    private const UUID_1 = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';

    private const UUID_2 = 'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22';

    /**
     * Tests successful parsing of integer IDs.
     *
     * @return void
     */
    public function testFromRequestDataSuccessWithIntegerIds(): void
    {
        $dto = new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [1, '2', 3],
                'customName' => ' Blueprint Group ',
            ],
        ], true);

        $this->assertSame([1, 2, 3], $dto->groups);
        $this->assertSame('Blueprint Group', $dto->customName);
    }

    /**
     * Tests successful parsing of UUIDs.
     *
     * @return void
     */
    public function testFromRequestDataSuccessWithUuids(): void
    {
        $dto = new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [self::UUID_1, self::UUID_2],
            ],
        ]);

        $this->assertSame([self::UUID_1, self::UUID_2], $dto->groups);
        $this->assertSame('', $dto->customName);
    }

    /**
     * Tests that custom names are trimmed and sanitized.
     *
     * @return void
     */
    public function testFromRequestDataSanitizesCustomName(): void
    {
        $dto = new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [1],
                'customName' => '  <b>Blueprint</b>  ',
            ],
        ], true);

        $this->assertSame('Blueprint', $dto->customName);
    }

    /**
     * Tests missing root validation.
     *
     * @return void
     */
    public function testFromRequestDataRejectsMissingRoot(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Payload must be enclosed under the "MsgdPlug" root key.'
        );

        new MsgdProcessGroupsDTO([
            'groups' => [1],
        ]);
    }

    /**
     * Tests invalid root type validation.
     *
     * @return void
     */
    public function testFromRequestDataRejectsNonArrayRoot(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => 'invalid',
        ]);
    }

    /**
     * Tests empty groups validation.
     *
     * @return void
     */
    public function testFromRequestDataRejectsEmptyGroups(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "groups" is required and must be an array.'
        );

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [],
            ],
        ]);
    }

    /**
     * Tests unauthorized field validation.
     *
     * @return void
     */
    public function testFromRequestDataRejectsUnauthorizedFields(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unauthorized fields in MsgdPlug payload: [invalid_key].'
        );

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [1],
                'invalid_key' => 'value',
            ],
        ], true);
    }

    /**
     * Tests non-scalar group validation.
     *
     * @return void
     */
    public function testFromRequestDataRejectsNonScalarGroup(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [[1]],
            ],
        ]);
    }

    /**
     * Tests invalid ID validation.
     *
     * @dataProvider invalidIdProvider
     *
     * @param mixed $group
     *
     * @return void
     */
    public function testFromRequestDataRejectsInvalidIds(mixed $group): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "groups" contains invalid integer IDs.'
        );

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [$group],
            ],
        ], true);
    }

    /**
     * Provides invalid ID values.
     *
     * @return array<string, array<int, mixed>>
     */
    public function invalidIdProvider(): array
    {
        return [
            'zero' => [0],
            'negative' => [-1],
            'letters' => ['abc'],
            'decimal' => ['1.5'],
            'scientific notation' => ['1e2'],
            'zero padded' => ['01'],
        ];
    }

    /**
     * Tests invalid UUID validation.
     *
     * @return void
     */
    public function testFromRequestDataRejectsInvalidUuid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "groups" contains invalid UUIDs.'
        );

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => ['invalid-uuid'],
            ],
        ]);
    }

    /**
     * Tests non-scalar custom name validation.
     *
     * @return void
     */
    public function testFromRequestDataRejectsNonScalarCustomName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "customName" must be a scalar value.'
        );

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [1],
                'customName' => ['invalid'],
            ],
        ], true);
    }

    /**
     * Tests custom name length validation.
     *
     * @return void
     */
    public function testFromRequestDataRejectsTooLongCustomName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "customName" cannot exceed 191 characters.'
        );

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [1],
                'customName' => str_repeat('a', 192),
            ],
        ], true);
    }

    /**
     * Tests that a maximum-length custom name is accepted.
     *
     * @return void
     */
    public function testFromRequestDataAcceptsMaximumCustomNameLength(): void
    {
        $name = str_repeat('a', 191);

        $dto = new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [1],
                'customName' => $name,
            ],
        ], true);

        $this->assertSame($name, $dto->customName);
    }

    /**
     * Tests that a whitespace-only custom name is rejected.
     *
     * @return void
     */
    public function testFromRequestDataRejectsWhitespaceCustomName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Field "customName" cannot be empty when provided.'
        );

        new MsgdProcessGroupsDTO([
            'MsgdPlug' => [
                'groups' => [1],
                'customName' => '   ',
            ],
        ], true);
    }

    /**
     * Tests direct construction.
     *
     * @return void
     */
    public function testDirectConstructorInstantiation(): void
    {
        $dto = new MsgdProcessGroupsDTO(
            ['MsgdPlug' => ['groups' => [1, 2], 'customName' => 'Blueprint']],
            true
        );

        $this->assertSame([1, 2], $dto->groups);
        $this->assertSame('Blueprint', $dto->customName);
    }
}
