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
require_once dirname(__DIR__, 4) . '/Lib/Utility/MsgdLoggerUtility.php';
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdUserDTO.php';
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdBlueprintDTO.php';
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdBlueprintRulesDTO.php';
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdProcessGroupsDTO.php';
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdMirrorGroupsDTO.php';
require_once dirname(__DIR__, 4) . '/Lib/Service/MsgdBlueprintService.php';
require_once dirname(__DIR__, 6) . '/Model/SharingGroupBlueprint.php';

App::uses('DataSource', 'Model/Datasource');

/**
 * Tests for the blueprint service.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.Service
 */
final class MsgdBlueprintServiceTest extends TestCase
{
    private const UUID_1 = '11111111-1111-4111-8111-111111111111';
    private const UUID_2 = '22222222-2222-4222-8222-222222222222';

    /**
     * Creates a test user DTO.
     *
     * @return MsgdUserDTO
     */
    private function createUser(): MsgdUserDTO
    {
        return new MsgdUserDTO([
            'id' => 1,
            'org_id' => 10,
            'email' => 'user@example.com',
            'Role' => [
                'perm_site_admin' => false,
                'perm_sharing_group' => true,
            ],
            'Organisation' => [
                'id' => 10,
                'name' => 'Test Organisation',
                'uuid' => self::UUID_1,
            ],
        ]);
    }

    /**
     * Creates a blueprint DTO.
     *
     * @param int $id
     * @param int $sharingGroupId
     * @param array<int, string|int> $identifiers
     *
     * @return MsgdBlueprintDTO
     */
    private function createBlueprint(
        int $id,
        int $sharingGroupId,
        array $identifiers = []
    ): MsgdBlueprintDTO {
        $model = [
            'SharingGroupBlueprint' => [
                'id' => $id,
                'uuid' => self::UUID_1,
                'name' => 'Test Blueprint',
                'user_id' => 1,
                'org_id' => 10,
                'sharing_group_id' => $sharingGroupId,
                'rules' => MsgdBlueprintRulesDTO::generateFromIdentifiers($identifiers),
            ],
        ];

        return new MsgdBlueprintDTO($model);
    }

    /**
     * Creates a model record with decoded blueprint rules.
     *
     * @param MsgdBlueprintDTO $blueprint
     *
     * @return array<string, mixed>
     */
    private function createModelRecord(MsgdBlueprintDTO $blueprint): array
    {
        return [
            'SharingGroupBlueprint' => [
                'id' => $blueprint->id,
                'uuid' => $blueprint->uuid,
                'name' => $blueprint->name,
                'user_id' => $blueprint->userId,
                'org_id' => $blueprint->orgId,
                'sharing_group_id' => $blueprint->sharingGroupId,
                'rules' => [
                    'AND' => [
                        'OR' => [
                            'sharing_group_id' => 30,
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * Tests finding a blueprint by ID.
     *
     * @return void
     * @throws JsonException
     */
    public function testFindById(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);
        $blueprint = $this->createBlueprint(5, 20);

        $model->method('find')->willReturn($blueprint->toModelArray());

        $result = (new MsgdBlueprintService($model))
            ->findById(5);

        $this->assertInstanceOf(MsgdBlueprintDTO::class, $result);
        $this->assertSame(5, $result->id);
        $this->assertSame(20, $result->sharingGroupId);
    }

    /**
     * Tests finding a blueprint by sharing group ID.
     *
     * @return void
     * @throws JsonException
     */
    public function testFindBySharingGroupId(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);
        $blueprint = $this->createBlueprint(5, 20);

        $model->method('find')->willReturn($blueprint->toModelArray());

        $result = (new MsgdBlueprintService($model))
            ->findBySharingGroupId(20);

        $this->assertInstanceOf(MsgdBlueprintDTO::class, $result);
        $this->assertSame(20, $result->sharingGroupId);
    }

    /**
     * Tests finding a blueprint by sharing group rules.
     *
     * @return void
     */
    public function testFindBySharingGroupRules(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);
        $blueprint = $this->createBlueprint(5, 20, [30]);

        $model->method('find')->willReturn(
            [$this->createModelRecord($blueprint)]
        );

        $mirrors = new MsgdMirrorGroupsDTO(ids: [30]);

        $result = (new MsgdBlueprintService($model))
            ->findBySharingGroupRules($this->createUser(), $mirrors);

        $this->assertInstanceOf(MsgdBlueprintDTO::class, $result);
        $this->assertSame(5, $result->id);
    }

    /**
     * Tests empty mirror groups.
     *
     * @return void
     */
    public function testFindBySharingGroupRulesReturnsNullForEmptyMirrors(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);

        $result = (new MsgdBlueprintService($model))
            ->findBySharingGroupRules(
                $this->createUser(),
                new MsgdMirrorGroupsDTO()
            );

        $this->assertNull($result);
    }

    /**
     * Tests generated sharing groups.
     *
     * @return void
     */
    public function testGetGeneratedGroups(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);

        $model->method('find')->willReturn([
            '1' => '10',
            '2' => '20',
            '3' => '10',
        ]);

        $result = (new MsgdBlueprintService($model))
            ->getGeneratedGroups();

        $this->assertSame([10, 20], $result);
    }

    /**
     * Tests datasource retrieval.
     *
     * @return void
     */
    public function testGetDataSource(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);
        $dataSource = $this->createMock(DataSource::class);

        $model->method('getDataSource')->willReturn($dataSource);

        $this->assertSame(
            $dataSource,
            (new MsgdBlueprintService($model))->getDataSource()
        );
    }

    /**
     * Tests blueprint creation.
     *
     * @return void
     */
    public function testCreate(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);

        $model->method('validateBlueprintPermissions')->willReturn(true);
        $model->expects($this->once())->method('create')->with(false);
        $model->expects($this->once())
            ->method('save')
            ->willReturnCallback(function () use ($model): array {
                $model->id = 77;

                return [
                    'SharingGroupBlueprint' => [
                        'id' => 77,
                    ],
                ];
            });

        $payload = new MsgdProcessGroupsDTO(
            ['MsgdPlug' => ['groups' => [self::UUID_2], 'customName' => 'Custom Name']]
        );

        $result = (new MsgdBlueprintService($model))
            ->create($this->createUser(), $payload);

        $this->assertSame(77, $result);
    }

    /**
     * Tests resetting the sharing group reference.
     *
     * @return void
     *
     * @throws JsonException
     */
    public function testResetSharingGroupRef(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);
        $blueprint = $this->createBlueprint(5, 20);

        $model->method('validateBlueprintPermissions')->willReturn(true);
        $model->expects($this->once())->method('create')->with(false);
        $model->expects($this->once())->method('save')->willReturn(true);

        $result = (new MsgdBlueprintService($model))
            ->resetSharingGroupRef(
                $this->createUser(),
                $blueprint,
                'New Name'
            );

        $this->assertTrue($result);
        $this->assertSame(0, $blueprint->sharingGroupId);
        $this->assertSame('New Name', $blueprint->name);
    }

    /**
     * Tests blueprint execution.
     *
     * @return void
     *
     * @throws JsonException
     */
    public function testExecute(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);
        $before = $this->createBlueprint(5, 0);
        $after = $this->createBlueprint(5, 20);

        $model->expects($this->exactly(2))
            ->method('find')
            ->willReturnOnConsecutiveCalls(
                $before->toModelArray(),
                $after->toModelArray()
            );

        $model->expects($this->once())
            ->method('execute')
            ->with([$before->toModelArray()]);

        $result = (new MsgdBlueprintService($model))
            ->execute(5);

        $this->assertSame(20, $result);
    }

    /**
     * Tests execution failure when no sharing group is generated.
     *
     * @return void
     *
     * @throws JsonException
     */
    public function testExecuteThrowsWhenSharingGroupIsMissing(): void
    {
        $model = $this->createMock(SharingGroupBlueprint::class);
        $blueprint = $this->createBlueprint(5, 0);

        $model->method('find')->willReturn($blueprint->toModelArray());

        $this->expectException(RuntimeException::class);

        (new MsgdBlueprintService($model))
            ->execute(5);
    }
}
