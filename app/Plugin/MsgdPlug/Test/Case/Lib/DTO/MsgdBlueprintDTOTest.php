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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdBlueprintDTO.php';

/**
 * Test suite for MsgdBlueprintDTO.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.DTO
 */
final class MsgdBlueprintDTOTest extends TestCase
{
    private const UUID = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';

    /**
     * Tests successful creation from a MISP model structure.
     *
     * @return void
     */
    public function testFromArraySuccess(): void
    {
        $data = [
            'SharingGroupBlueprint' => [
                'id' => 10,
                'uuid' => self::UUID,
                'name' => 'Test Blueprint',
                'user_id' => 5,
                'org_id' => 20,
                'sharing_group_id' => 30,
                'rules' => [
                    'AND' => [
                        'OR' => [
                            'sharing_group_id' => [30],
                        ],
                    ],
                ],
            ],
        ];

        $dto = new MsgdBlueprintDTO($data);

        $this->assertSame(10, $dto->id);
        $this->assertSame(self::UUID, $dto->uuid);
        $this->assertSame('Test Blueprint', $dto->name);
        $this->assertSame(5, $dto->userId);
        $this->assertSame(20, $dto->orgId);
        $this->assertSame(30, $dto->sharingGroupId);
        $this->assertInstanceOf(MsgdBlueprintRulesDTO::class, $dto->rules);
        $this->assertSame([30], $dto->rules->sharingGroupsIds);
    }

    /**
     * Tests creation from an unwrapped blueprint structure.
     *
     * @return void
     */
    public function testFromArrayAcceptsUnwrappedData(): void
    {
        $dto = new MsgdBlueprintDTO([
            'id' => '10',
            'uuid' => self::UUID,
            'name' => 'Blueprint',
            'user_id' => '5',
            'org_id' => '20',
            'sharing_group_id' => '30',
            'rules' => [],
        ]);

        $this->assertSame(10, $dto->id);
        $this->assertSame(5, $dto->userId);
        $this->assertSame(20, $dto->orgId);
        $this->assertSame(30, $dto->sharingGroupId);
    }

    /**
     * Tests that the blueprint name is sanitized.
     *
     * @return void
     */
    public function testFromArraySanitizesName(): void
    {
        $dto = new MsgdBlueprintDTO([
            'name' => '<script>alert(1)</script>Blueprint',
            'rules' => [],
        ]);

        $this->assertStringNotContainsString('<script>', $dto->name);
    }

    /**
     * Tests exception for an invalid UUID.
     *
     * @return void
     */
    public function testFromArrayThrowsExceptionForInvalidUuid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Sharing Group Blueprint contains an invalid UUID.'
        );

        new MsgdBlueprintDTO([
            'uuid' => 'invalid-uuid',
            'rules' => [],
        ]);
    }

    /**
     * Tests that an empty UUID is accepted.
     *
     * @return void
     */
    public function testFromArrayAcceptsEmptyUuid(): void
    {
        $dto = new MsgdBlueprintDTO([
            'uuid' => '',
            'rules' => [],
        ]);

        $this->assertSame('', $dto->uuid);
    }

    /**
     * Tests default values.
     *
     * @return void
     */
    public function testFromArrayUsesDefaultValues(): void
    {
        $dto = new MsgdBlueprintDTO([]);

        $this->assertSame(0, $dto->id);
        $this->assertSame('', $dto->uuid);
        $this->assertSame('', $dto->name);
        $this->assertSame(0, $dto->userId);
        $this->assertSame(0, $dto->orgId);
        $this->assertSame(0, $dto->sharingGroupId);
        $this->assertSame([], $dto->rules->raw);
    }

    /**
     * Tests serialization to the expected MISP model structure.
     *
     * @return void
     *
     * @throws JsonException
     */
    public function testToModelArray(): void
    {
        $rules = [
            'AND' => [
                'OR' => [
                    'sharing_group_id' => [10, 20],
                ],
            ],
        ];

        $dto = new MsgdBlueprintDTO([
            'rules' => $rules,
            'id' => 1,
            'uuid' => self::UUID,
            'name' => 'Blueprint',
            'user_id' => 2,
            'org_id' => 3,
            'sharing_group_id' => 4,
        ]);

        $result = $dto->toModelArray();

        $this->assertSame(1, $result['SharingGroupBlueprint']['id']);
        $this->assertSame(self::UUID, $result['SharingGroupBlueprint']['uuid']);
        $this->assertSame('Blueprint', $result['SharingGroupBlueprint']['name']);
        $this->assertSame(2, $result['SharingGroupBlueprint']['user_id']);
        $this->assertSame(3, $result['SharingGroupBlueprint']['org_id']);
        $this->assertSame(4, $result['SharingGroupBlueprint']['sharing_group_id']);
        $this->assertSame(
            '{"AND":{"OR":{"sharing_group_id":[10,20]}}}',
            $result['SharingGroupBlueprint']['rules']
        );
    }

    /**
     * Tests direct DTO instantiation with explicit values.
     *
     * @return void
     */
    public function testDirectConstructorInstantiation(): void
    {
        $rules = [
            'AND' => [
                'OR' => [
                    'sharing_group_id' => 42,
                ],
            ],
        ];

        $dto = new MsgdBlueprintDTO([
            'rules' => $rules,
            'id' => 1,
            'uuid' => '11111111-1111-4111-8111-111111111111',
            'name' => 'Test Blueprint',
            'user_id' => 10,
            'org_id' => 20,
            'sharing_group_id' => 30,
        ]);

        $this->assertSame(1, $dto->id);
        $this->assertSame('11111111-1111-4111-8111-111111111111', $dto->uuid);
        $this->assertSame('Test Blueprint', $dto->name);
        $this->assertSame(10, $dto->userId);
        $this->assertSame(20, $dto->orgId);
        $this->assertSame(30, $dto->sharingGroupId);
        $this->assertSame([42], $dto->rules->sharingGroupsIds);
    }
}
