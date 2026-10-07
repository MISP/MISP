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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdGetSharingGroupsDTO.php';

/**
 * Test suite for MsgdGetSharingGroupsDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdGetSharingGroupsDTOTest extends TestCase
{
    /**
     * Tests the default value.
     *
     * @return void
     */
    public function testFromRequestQueryDefaultsToFalse(): void
    {
        $dto = new MsgdGetSharingGroupsDTO([]);

        $this->assertFalse($dto->all);
    }

    /**
     * Tests true boolean representations.
     *
     * @dataProvider trueValueProvider
     *
     * @param mixed $value
     *
     * @return void
     */
    public function testFromRequestQueryParsesTrueValues(mixed $value): void
    {
        $dto = new MsgdGetSharingGroupsDTO([
            'all' => $value,
        ]);

        $this->assertTrue($dto->all);
    }

    /**
     * Tests false boolean representations.
     *
     * @dataProvider falseValueProvider
     *
     * @param mixed $value
     *
     * @return void
     */
    public function testFromRequestQueryParsesFalseValues(mixed $value): void
    {
        $dto = new MsgdGetSharingGroupsDTO([
            'all' => $value,
        ]);

        $this->assertFalse($dto->all);
    }

    /**
     * Provides true boolean representations.
     *
     * @return array<string, array<int, mixed>>
     */
    public function trueValueProvider(): array
    {
        return [
            'true string' => ['true'],
            'one string' => ['1'],
            'yes string' => ['yes'],
            'on string' => ['on'],
            'true boolean' => [true],
            'one integer' => [1],
        ];
    }

    /**
     * Provides false boolean representations.
     *
     * @return array<string, array<int, mixed>>
     */
    public function falseValueProvider(): array
    {
        return [
            'false string' => ['false'],
            'zero string' => ['0'],
            'no string' => ['no'],
            'off string' => ['off'],
            'false boolean' => [false],
            'zero integer' => [0],
        ];
    }

    /**
     * Tests the MsgdPlug wrapper.
     *
     * @return void
     */
    public function testFromRequestQuerySupportsMsgdPlugWrapper(): void
    {
        $dto = new MsgdGetSharingGroupsDTO([
            'MsgdPlug' => [
                'all' => '1',
            ],
        ]);

        $this->assertTrue($dto->all);
    }

    /**
     * Tests framework parameters are ignored.
     *
     * @return void
     */
    public function testFromRequestQueryIgnoresFrameworkParameters(): void
    {
        $dto = new MsgdGetSharingGroupsDTO([
            'all' => 'true',
            'url' => 'msgd_plug/api/sharing_groups',
            '_' => '123',
        ]);

        $this->assertTrue($dto->all);
    }

    /**
     * Tests framework parameters are ignored inside the wrapper.
     *
     * @return void
     */
    public function testFromRequestQueryIgnoresFrameworkParametersInsideWrapper(): void
    {
        $dto = new MsgdGetSharingGroupsDTO([
            'MsgdPlug' => [
                'all' => 'true',
                'url' => 'msgd_plug/api/sharing_groups',
                '_' => '123',
            ],
        ]);

        $this->assertTrue($dto->all);
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

        new MsgdGetSharingGroupsDTO([
            'all' => 'true',
            'invalid_param' => 'value',
        ]);
    }

    /**
     * Tests exception for non-scalar values.
     *
     * @return void
     */
    public function testFromRequestQueryRejectsNonScalarValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Query parameter "all" must be a scalar value.'
        );

        new MsgdGetSharingGroupsDTO([
            'all' => ['invalid'],
        ]);
    }

    /**
     * Tests exception for invalid boolean strings.
     *
     * @return void
     */
    public function testFromRequestQueryRejectsInvalidBoolean(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Query parameter "all" must be a valid boolean value.'
        );

        new MsgdGetSharingGroupsDTO([
            'all' => 'maybe',
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

        new MsgdGetSharingGroupsDTO([
            'MsgdPlug' => 'invalid',
            'all' => 'true',
        ]);
    }

    /**
     * Tests direct construction.
     *
     * @return void
     */
    public function testDirectConstructorInstantiation(): void
    {
        $this->assertFalse((new MsgdGetSharingGroupsDTO(['MsgdPlug' => ['all' => false]]))->all);
        $this->assertTrue((new MsgdGetSharingGroupsDTO(['MsgdPlug' => ['all' => true]]))->all);
    }
}
