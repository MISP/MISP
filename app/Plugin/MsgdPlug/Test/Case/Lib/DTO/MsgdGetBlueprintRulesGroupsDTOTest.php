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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdGetBlueprintRulesGroupsDTO.php';

/**
 * Test suite for MsgdGetBlueprintRulesGroupsDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdGetBlueprintRulesGroupsDTOTest extends TestCase
{
    /**
     * Tests successful parsing of a direct group parameter.
     *
     * @return void
     */
    public function testFromRequestQuerySuccess(): void
    {
        $dto = new MsgdGetBlueprintRulesGroupsDTO([
            'group' => 42,
        ]);

        $this->assertSame(42, $dto->group);
    }

    /**
     * Tests successful parsing of a wrapped group parameter.
     *
     * @return void
     */
    public function testFromRequestQuerySuccessWithMsgdPlugWrapper(): void
    {
        $dto = new MsgdGetBlueprintRulesGroupsDTO([
            'MsgdPlug' => [
                'group' => '15',
            ],
        ]);

        $this->assertSame(15, $dto->group);
    }

    /**
     * Tests framework parameters are ignored.
     *
     * @return void
     */
    public function testFromRequestQueryIgnoresFrameworkParameters(): void
    {
        $dto = new MsgdGetBlueprintRulesGroupsDTO([
            'group' => 10,
            'url' => 'msgd_plug/api/rules',
            '_' => '123',
        ]);

        $this->assertSame(10, $dto->group);
    }

    /**
     * Tests framework parameters are ignored inside the wrapper.
     *
     * @return void
     */
    public function testFromRequestQueryIgnoresFrameworkParametersInsideWrapper(): void
    {
        $dto = new MsgdGetBlueprintRulesGroupsDTO([
            'MsgdPlug' => [
                'group' => 10,
                'url' => 'msgd_plug/api/rules',
                '_' => '123',
            ],
        ]);

        $this->assertSame(10, $dto->group);
    }

    /**
     * Tests exception for missing group.
     *
     * @return void
     */
    public function testFromRequestQueryThrowsExceptionForMissingGroup(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Query parameter "group" is required and cannot be empty.'
        );

        new MsgdGetBlueprintRulesGroupsDTO([]);
    }

    /**
     * Tests exception for empty group.
     *
     * @return void
     */
    public function testFromRequestQueryThrowsExceptionForEmptyGroup(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdGetBlueprintRulesGroupsDTO([
            'group' => '',
        ]);
    }

    /**
     * Tests exception for invalid group values.
     *
     * @dataProvider invalidGroupProvider
     *
     * @param mixed $group
     *
     * @return void
     */
    public function testFromRequestQueryRejectsInvalidGroup(mixed $group): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MsgdGetBlueprintRulesGroupsDTO([
            'group' => $group,
        ]);
    }

    /**
     * Provides invalid group values.
     *
     * @return array<string, array<int, mixed>>
     */
    public function invalidGroupProvider(): array
    {
        return [
            'zero' => [0],
            'negative' => [-1],
            'decimal' => ['1.5'],
            'scientific notation' => ['1e2'],
            'zero padded' => ['01'],
            'letters' => ['abc'],
            'array' => [[10]],
            'boolean' => [true],
            'float' => [10.5],
        ];
    }

    /**
     * Tests exception for unauthorized parameters.
     *
     * @return void
     */
    public function testFromRequestQueryRejectsUnauthorizedParameters(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unauthorized parameters detected in query: [invalid_param].'
        );

        new MsgdGetBlueprintRulesGroupsDTO([
            'group' => 10,
            'invalid_param' => 'value',
        ]);
    }

    /**
     * Tests fallback behavior for a non-array MsgdPlug parameter.
     *
     * @return void
     */
    public function testFromRequestQueryRejectsNonArrayMsgdPlug(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unauthorized parameters detected in query: [MsgdPlug].'
        );

        new MsgdGetBlueprintRulesGroupsDTO([
            'MsgdPlug' => 'invalid',
            'group' => 10,
        ]);
    }

    /**
     * Tests direct construction.
     *
     * @return void
     */
    public function testDirectConstructorInstantiation(): void
    {
        $dto = new MsgdGetBlueprintRulesGroupsDTO(['MsgdPlug' => ['group' => 88]]);

        $this->assertSame(88, $dto->group);
    }
}
