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
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdSharingGroupDTO.php';
require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdMirrorGroupsDTO.php';
require_once dirname(__DIR__, 6) . '/Model/SharingGroup.php';

App::uses('DataSource', 'Model/Datasource');

/**
 * Tests for the sharing group service.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.Service
 */
final class MsgdSharingGroupServiceTest extends TestCase
{
    private const UUID_1 = '11111111-1111-4111-8111-111111111111';
    private const UUID_2 = '22222222-2222-4222-8222-222222222222';

    /**
     * Creates a user DTO.
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
     * Tests findById.
     *
     * @return void
     */
    public function testFindById(): void
    {
        $model = $this->createMock(SharingGroup::class);

        $model->method('checkIfAuthorised')->willReturn(true);
        $model->method('find')->willReturn([
            'SharingGroup' => [
                'id' => 10,
                'uuid' => self::UUID_1,
                'name' => 'Test Group',
            ],
        ]);

        $result = (new MsgdSharingGroupService($model))->findById(
            $this->createUser(),
            10
        );

        $this->assertInstanceOf(MsgdSharingGroupDTO::class, $result);
        $this->assertSame(10, $result->id);
        $this->assertSame('Test Group', $result->name);
    }

    /**
     * Tests findById when authorization fails.
     *
     * @return void
     */
    public function testFindByIdReturnsNullWhenUnauthorized(): void
    {
        $model = $this->createMock(SharingGroup::class);

        $model->method('checkIfAuthorised')->willReturn(false);

        $result = (new MsgdSharingGroupService($model))->findById(
            $this->createUser(),
            10
        );

        $this->assertNull($result);
    }

    /**
     * Tests findByUuid.
     *
     * @return void
     */
    public function testFindByUuid(): void
    {
        $model = $this->createMock(SharingGroup::class);

        $model->method('checkIfAuthorised')->willReturn(true);
        $model->method('find')->willReturn([
            'SharingGroup' => [
                'id' => 10,
                'uuid' => self::UUID_2,
                'name' => 'Test Group',
            ],
        ]);

        $service = new MsgdSharingGroupService($model);

        $result = $service->findByUuid(
            $this->createUser(),
            self::UUID_2
        );

        $this->assertInstanceOf(MsgdSharingGroupDTO::class, $result);
        $this->assertSame(10, $result->id);

        $this->expectException(InvalidArgumentException::class);

        $service->findByUuid(
            $this->createUser(),
            'invalid'
        );
    }

    /**
     * Tests getMirrorGroups.
     *
     * @return void
     */
    public function testGetMirrorGroups(): void
    {
        $model = $this->createMock(SharingGroup::class);

        $model->method('authorizedIds')->willReturn([10, 20]);
        $model->method('find')->willReturn([
            [
                'SharingGroup' => [
                    'id' => 10,
                    'uuid' => self::UUID_1,
                ],
            ],
            [
                'SharingGroup' => [
                    'id' => 20,
                    'uuid' => self::UUID_2,
                ],
            ],
        ]);

        $service = new MsgdSharingGroupService($model);

        $this->assertNull(
            $service->getMirrorGroups($this->createUser(), [])
        );

        $result = $service->getMirrorGroups(
            $this->createUser(),
            [10, self::UUID_2]
        );

        $this->assertInstanceOf(MsgdMirrorGroupsDTO::class, $result);
        $this->assertSame(
            [10, 20],
            $result->ids
        );
        $this->assertSame(
            [self::UUID_1, self::UUID_2],
            $result->uuids
        );
    }

    /**
     * Tests getMirrorGroups without authorized groups.
     *
     * @return void
     */
    public function testGetMirrorGroupsReturnsNullWithoutAuthorization(): void
    {
        $model = $this->createMock(SharingGroup::class);

        $model->method('authorizedIds')->willReturn([]);

        $result = (new MsgdSharingGroupService($model))
            ->getMirrorGroups(
                $this->createUser(),
                [10]
            );

        $this->assertNull($result);
    }

    /**
     * Tests getList.
     *
     * @return void
     */
    public function testGetList(): void
    {
        $model = $this->createMock(SharingGroup::class);

        $model->method('authorizedIds')->willReturn([10, 20]);
        $model->method('find')->willReturn([
            [
                'SharingGroup' => [
                    'id' => 10,
                    'uuid' => self::UUID_1,
                    'name' => 'Alpha',
                ],
            ],
            [
                'SharingGroup' => [
                    'id' => 20,
                    'uuid' => self::UUID_2,
                    'name' => 'Beta',
                ],
            ],
        ]);

        $result = (new MsgdSharingGroupService($model))
            ->getList($this->createUser());

        $this->assertCount(2, $result);
        $this->assertSame(10, $result[0]->id);
        $this->assertSame(20, $result[1]->id);
    }

    /**
     * Tests getList without authorized groups.
     *
     * @return void
     */
    public function testGetListReturnsEmptyWithoutAuthorization(): void
    {
        $model = $this->createMock(SharingGroup::class);

        $model->method('authorizedIds')->willReturn([]);

        $result = (new MsgdSharingGroupService($model))
            ->getList($this->createUser());

        $this->assertSame([], $result);
    }

    /**
     * Tests getDataSource.
     *
     * @return void
     */
    public function testGetDataSource(): void
    {
        $model = $this->createMock(SharingGroup::class);
        $dataSource = $this->createMock(DataSource::class);

        $model->method('getDataSource')->willReturn($dataSource);

        $this->assertSame(
            $dataSource,
            (new MsgdSharingGroupService($model))->getDataSource()
        );
    }

    /**
     * Tests model exception handling.
     *
     * @return void
     */
    public function testFindByIdWrapsModelException(): void
    {
        $model = $this->createMock(SharingGroup::class);

        $model->method('checkIfAuthorised')
            ->willThrowException(new RuntimeException('Database error'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Database error');

        (new MsgdSharingGroupService($model))->findById(
            $this->createUser(),
            10
        );
    }
}
