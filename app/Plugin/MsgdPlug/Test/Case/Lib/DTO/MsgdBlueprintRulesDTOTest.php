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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdBlueprintRulesDTO.php';

/**
 * Test suite for MsgdBlueprintRulesDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdBlueprintRulesDTOTest extends TestCase
{
    private const UUID_1 = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';

    private const UUID_2 = 'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22';

    /**
     * Tests extraction of Sharing Group IDs.
     *
     * @return void
     */
    public function testConstructorExtractsIds(): void
    {
        $dto = new MsgdBlueprintRulesDTO([
            'AND' => [
                'OR' => [
                    'sharing_group_id' => [10, '20', 10],
                ],
            ],
        ]);

        $this->assertSame([10, 20], $dto->sharingGroupsIds);
        $this->assertSame([], $dto->sharingGroupsUuids);
        $this->assertSame([10, 20], $dto->allSharingGroupIdentifiers);
    }

    /**
     * Tests extraction of Sharing Group UUIDs.
     *
     * @return void
     */
    public function testConstructorExtractsUuids(): void
    {
        $dto = new MsgdBlueprintRulesDTO([
            'AND' => [
                'OR' => [
                    'sharing_group_uuid' => [
                        self::UUID_1,
                        self::UUID_2,
                        self::UUID_1,
                    ],
                ],
            ],
        ]);

        $this->assertSame([], $dto->sharingGroupsIds);
        $this->assertSame(
            [self::UUID_1, self::UUID_2],
            $dto->sharingGroupsUuids
        );
        $this->assertSame(
            [self::UUID_1, self::UUID_2],
            $dto->allSharingGroupIdentifiers
        );
    }

    /**
     * Tests extraction when identifiers are scalar values.
     *
     * @return void
     */
    public function testConstructorAcceptsScalarIdentifiers(): void
    {
        $dto = new MsgdBlueprintRulesDTO([
            'AND' => [
                'OR' => [
                    'sharing_group_id' => 10,
                    'sharing_group_uuid' => self::UUID_1,
                ],
            ],
        ]);

        $this->assertSame([10], $dto->sharingGroupsIds);
        $this->assertSame([self::UUID_1], $dto->sharingGroupsUuids);
    }

    /**
     * Tests JSON input.
     *
     * @return void
     *
     * @throws JsonException
     */
    public function testConstructorAcceptsJson(): void
    {
        $json = json_encode([
            'AND' => [
                'OR' => [
                    'sharing_group_id' => [10, 20],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $dto = new MsgdBlueprintRulesDTO($json);

        $this->assertSame([10, 20], $dto->sharingGroupsIds);
        $this->assertSame($json, json_encode($dto->raw));
    }

    /**
     * Tests that raw rules are preserved.
     *
     * @return void
     */
    public function testToArrayReturnsRawRules(): void
    {
        $rules = [
            'AND' => [
                'OR' => [
                    'sharing_group_id' => [10],
                ],
            ],
        ];

        $dto = new MsgdBlueprintRulesDTO($rules);

        $this->assertSame($rules, $dto->raw);
    }

    /**
     * Tests creation from mixed identifiers.
     *
     * @return void
     */
    public function testFromIdentifiers(): void
    {
        $rules = MsgdBlueprintRulesDTO::generateFromIdentifiers([
            10,
            '20',
            self::UUID_1,
            '',
            0,
            -5,
            'invalid',
            self::UUID_1,
        ]);

        $this->assertSame([10, 20], $rules->sharingGroupsIds);
        $this->assertSame([self::UUID_1], $rules->sharingGroupsUuids);
    }

    /**
     * Tests creation from a single identifier.
     *
     * @return void
     */
    public function testFromIdentifiersUsesScalarForSingleIdentifier(): void
    {
        $rules = MsgdBlueprintRulesDTO::generateFromIdentifiers([10])->raw;

        $this->assertSame(
            ['AND' => ['OR' => ['sharing_group_id' => 10]]],
            $rules
        );
    }

    /**
     * Tests creation from an empty identifier list.
     *
     * @return void
     */
    public function testFromIdentifiersAcceptsEmptyArray(): void
    {
        $rules = MsgdBlueprintRulesDTO::generateFromIdentifiers([])->raw;

        $this->assertSame(
            ['AND' => ['OR' => []]],
            $rules
        );

        $dto = new MsgdBlueprintRulesDTO($rules);

        $this->assertSame([], $dto->allSharingGroupIdentifiers);
    }

    /**
     * Tests invalid identifiers are ignored.
     *
     * @return void
     */
    public function testFromIdentifiersIgnoresInvalidIdentifiers(): void
    {
        /** @var array<int|string> $invalidIdentifiers */
        $invalidIdentifiers = [
            [],
            new stdClass(),
            null,
            false,
            'invalid',
        ];

        $rules = MsgdBlueprintRulesDTO::generateFromIdentifiers($invalidIdentifiers);

        $this->assertSame([], $rules->sharingGroupsIds);
        $this->assertSame([], $rules->sharingGroupsUuids);
    }

    /**
     * Tests invalid nested rule structures are normalized to empty arrays.
     *
     * @return void
     */
    public function testConstructorHandlesInvalidNestedStructures(): void
    {
        $dto = new MsgdBlueprintRulesDTO([
            'AND' => 'invalid',
        ]);

        $this->assertSame([], $dto->sharingGroupsIds);
        $this->assertSame([], $dto->sharingGroupsUuids);
    }

    /**
     * Tests JSON serialization of rules.
     *
     * @return void
     *
     * @throws JsonException
     */
    public function testToJsonReturnsValidJson(): void
    {
        $dto = new MsgdBlueprintRulesDTO([
            'AND' => [
                'OR' => [
                    'sharing_group_uuid' => self::UUID_1,
                ],
            ],
        ]);

        $json = json_encode($dto->raw, JSON_THROW_ON_ERROR);

        $this->assertSame(
            [
                'AND' => [
                    'OR' => [
                        'sharing_group_uuid' => self::UUID_1,
                    ],
                ],
            ],
            json_decode($json, true, 512, JSON_THROW_ON_ERROR)
        );
    }
}
