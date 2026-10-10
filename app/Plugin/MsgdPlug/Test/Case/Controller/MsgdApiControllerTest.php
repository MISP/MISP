<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

use PHPUnit\Framework\MockObject\Builder\InvocationMocker;
use PHPUnit\Framework\MockObject\MockBuilder;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/Lib/Utility/MsgdSanitizerUtility.php';
require_once dirname(__DIR__, 3) . '/Lib/Utility/MsgdLoggerUtility.php';
require_once dirname(__DIR__, 3) . '/Lib/DTO/MsgdUserDTO.php';
require_once dirname(__DIR__, 3) . '/Lib/DTO/MsgdCheckBlueprintDTO.php';
require_once dirname(__DIR__, 3) . '/Lib/DTO/MsgdGetBlueprintRulesGroupsDTO.php';
require_once dirname(__DIR__, 3) . '/Lib/DTO/MsgdGetSharingGroupsDTO.php';
require_once dirname(__DIR__, 3) . '/Lib/DTO/MsgdProcessGroupsDTO.php';
require_once dirname(__DIR__, 3) . '/Lib/DTO/MsgdProcessResultDTO.php';
require_once dirname(__DIR__, 3) . '/Lib/DTO/MsgdSharingGroupDTO.php';
require_once dirname(__DIR__, 3) . '/Lib/Enum/MsgdPluginConfigEnum.php';
require_once dirname(__DIR__, 3) . '/Lib/Voter/MsgdSharingGroupVoter.php';
require_once dirname(__DIR__, 3) . '/Lib/Service/MsgdSharingGroupService.php';
require_once dirname(__DIR__, 3) . '/Lib/Service/MsgdApiControllerService.php';
require_once dirname(__DIR__, 3) . '/Controller/MsgdPlugAppController.php';
require_once dirname(__DIR__, 3) . '/Controller/MsgdApiController.php';

if (class_exists('App')) {
    App::uses('CakePlugin', 'Core');
    App::uses('CakeRequest', 'Network');
    App::uses('CakeResponse', 'Network');
    App::uses('Controller', 'Controller');
    App::uses('AuthComponent', 'Controller/Component');
}

/**
 * Test suite for MsgdApiController.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Controller
 */
final class MsgdApiControllerTest extends TestCase
{
    private const UUID_1 = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11';
    private const UUID_2 = 'b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22';

    private const GROUP_ID_1 = 10;
    private const GROUP_ID_2 = 20;

    /**
     * Creates a partially mocked MsgdApiController instance.
     *
     * @param MockObject $serviceMock Controller service mock.
     * @param MockObject|null $voterMock Voter mock.
     * @param string $method HTTP request method.
     * @param bool $isRequestValid Mock result for request validation.
     * @param bool $useIds Mock result for identifier mode.
     *
     * @return MsgdApiController
     */
    private function createController(
        MockObject $serviceMock,
        ?MockObject $voterMock = null,
        string $method = 'GET',
        bool $isRequestValid = true,
        bool $useIds = false
    ): MsgdApiController {
        $_SERVER['REQUEST_METHOD'] = $method;

        /** @var MockBuilder<MsgdApiController> $builder */
        $builder = $this->getMockBuilder(MsgdApiController::class);

        /** @var MsgdApiController&MockObject $controller */
        $controller = $builder
            ->onlyMethods(['validateRequest'])
            ->getMock();

        /** @var InvocationMocker $validateMocker */
        $validateMocker = $controller->method('validateRequest');
        $validateMocker->willReturn($isRequestValid);

        $controller->request = new CakeRequest();
        $controller->response = new CakeResponse();

        /** @var MockBuilder<stdClass> $authBuilder */
        $authBuilder = $this->getMockBuilder(stdClass::class);

        /** @var MockObject $authMock */
        $authMock = $authBuilder
            ->addMethods(['user'])
            ->getMock();

        /** @var InvocationMocker $userMocker */
        $userMocker = $authMock->method('user');
        $userMocker->willReturn($this->validUser());

        /** @var AuthComponent $authComponent */
        $authComponent = $authMock;
        $controller->Auth = $authComponent;

        /** @var InvocationMocker $isUsingIdsMocker */
        $isUsingIdsMocker = $serviceMock->method('isUsingIds');
        $isUsingIdsMocker->willReturn($useIds);

        $reflection = new ReflectionClass(MsgdApiController::class);

        $serviceProperty = $reflection->getProperty('msgdService');
        $serviceProperty->setAccessible(true);
        $serviceProperty->setValue($controller, $serviceMock);

        $voterProperty = $reflection->getProperty('voter');
        $voterProperty->setAccessible(true);
        $voterProperty->setValue($controller, $voterMock ?? $this->createVoterMock());

        return $controller;
    }

    /**
     * Creates a controller service mock.
     *
     * @return MockObject
     */
    private function createServiceMock(): MockObject
    {
        /** @var MockBuilder<MsgdApiControllerService> $builder */
        $builder = $this->getMockBuilder(MsgdApiControllerService::class);

        /** @var MockObject $mock */
        $mock = $builder
            ->disableOriginalConstructor()
            ->getMock();

        return $mock;
    }

    /**
     * Creates a voter mock.
     *
     * @return MockObject
     */
    private function createVoterMock(): MockObject
    {
        /** @var MockBuilder<MsgdSharingGroupVoter> $builder */
        $builder = $this->getMockBuilder(MsgdSharingGroupVoter::class);

        /** @var MockObject $mock */
        $mock = $builder
            ->disableOriginalConstructor()
            ->getMock();

        return $mock;
    }

    /**
     * Returns valid authenticated user data.
     *
     * @return array<string, mixed>
     */
    private function validUser(): array
    {
        return [
            'id' => 1,
            'org_id' => 10,
            'email' => 'test@example.com',
            'disabled' => false,
            'Role' => [
                'perm_site_admin' => false,
                'perm_sharing_group' => true,
                'perm_sync' => true,
            ],
            'Organisation' => [
                'id' => 10,
                'name' => 'Test Organisation',
                'uuid' => '11111111-1111-4111-8111-111111111111',
            ],
        ];
    }

    /**
     * Decodes a JSON response body.
     *
     * @param CakeResponse $response Controller response.
     *
     * @return array<string, mixed>
     */
    private function decodeResponse(CakeResponse $response): array
    {
        $body = $response->body();
        $bodyString = $body;
        $decoded = json_decode($bodyString, true);

        $this->assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * Tests unauthorized access for checkUserPermission.
     *
     * @return void
     */
    public function testCheckUserPermissionReturns403WhenUnauthorized(): void
    {
        $serviceMock = $this->createServiceMock();
        $controller = $this->createController($serviceMock, null, 'GET', false);

        $response = $controller->checkUserPermission();

        $this->assertSame(403, $response->statusCode());
        $this->assertSame(
            'Unauthorized access.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests successful permission verification (granted).
     *
     * @return void
     */
    public function testCheckUserPermissionReturns200WhenGranted(): void
    {
        $serviceMock = $this->createServiceMock();
        $voterMock = $this->createVoterMock();

        /** @var InvocationMocker $expectation */
        $expectation = $voterMock->expects($this->once());
        $expectation->method('vote')
            ->with(
                $this->isInstanceOf(MsgdUserDTO::class),
                MsgdSharingGroupVoter::USE_SHARING_GROUPS
            )
            ->willReturn(true);

        $controller = $this->createController($serviceMock, $voterMock);

        $response = $controller->checkUserPermission();

        $this->assertSame(200, $response->statusCode());

        $payload = $this->decodeResponse($response);

        $this->assertSame('success', $payload['status']);
        $this->assertTrue($payload['allowed']);
    }

    /**
     * Tests permission verification when access is not granted.
     *
     * @return void
     */
    public function testCheckUserPermissionReturns200WhenDenied(): void
    {
        $serviceMock = $this->createServiceMock();
        $voterMock = $this->createVoterMock();

        /** @var InvocationMocker $expectation */
        $expectation = $voterMock->expects($this->once());
        $expectation->method('vote')
            ->with(
                $this->isInstanceOf(MsgdUserDTO::class),
                MsgdSharingGroupVoter::USE_SHARING_GROUPS
            )
            ->willReturn(false);

        $controller = $this->createController($serviceMock, $voterMock);

        $response = $controller->checkUserPermission();

        $this->assertSame(200, $response->statusCode());

        $payload = $this->decodeResponse($response);

        $this->assertSame('success', $payload['status']);
        $this->assertFalse($payload['allowed']);
    }

    /**
     * Tests internal errors during permission verification.
     *
     * @return void
     */
    public function testCheckUserPermissionReturns500OnThrowable(): void
    {
        $serviceMock = $this->createServiceMock();
        $voterMock = $this->createVoterMock();

        /** @var InvocationMocker $expectation */
        $expectation = $voterMock->expects($this->once());
        $expectation->method('vote')
            ->with(
                $this->isInstanceOf(MsgdUserDTO::class),
                MsgdSharingGroupVoter::USE_SHARING_GROUPS
            )
            ->willThrowException(new RuntimeException('Voter failure.'));

        $controller = $this->createController($serviceMock, $voterMock);

        $response = $controller->checkUserPermission();

        $this->assertSame(500, $response->statusCode());

        $payload = $this->decodeResponse($response);

        $this->assertSame('error', $payload['status']);
        $this->assertFalse($payload['allowed']);
        $this->assertSame(
            'Failed to verify user permissions.',
            $payload['message']
        );
    }

    /**
     * Tests successful blueprint rules group retrieval.
     *
     * @return void
     */
    public function testGetBlueprintRulesGroupsReturns200(): void
    {
        $serviceMock = $this->createServiceMock();
        $groups = [
            ['id' => 1, 'name' => 'Group 1'],
        ];

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('getSharingGroupsByGeneratedBlueprintGroup')
            ->with($this->isInstanceOf(MsgdUserDTO::class), self::GROUP_ID_1)
            ->willReturn($groups);

        $controller = $this->createController($serviceMock);
        $controller->request->query = [
            'group' => self::GROUP_ID_1,
        ];

        $response = $controller->getBlueprintRulesGroups();

        $this->assertSame(200, $response->statusCode());

        $payload = $this->decodeResponse($response);

        $this->assertSame('success', $payload['status']);
        $this->assertSame($groups, $payload['groups']);
    }

    /**
     * Tests invalid blueprint rules group parameters.
     *
     * @return void
     */
    public function testGetBlueprintRulesGroupsReturns400ForInvalidQuery(): void
    {
        $serviceMock = $this->createServiceMock();
        $controller = $this->createController($serviceMock);
        $controller->request->query = [
            'group' => 'invalid',
        ];

        $response = $controller->getBlueprintRulesGroups();

        $this->assertSame(400, $response->statusCode());
        $this->assertSame(
            'Invalid parameters provided for blueprint rules.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests successful sharing group retrieval.
     *
     * @return void
     */
    public function testGetSharingGroupsReturns200(): void
    {
        $serviceMock = $this->createServiceMock();
        $groups = [
            ['id' => 1, 'name' => 'Group 1'],
        ];

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('getAvailableSharingGroups')
            ->with($this->isInstanceOf(MsgdUserDTO::class), false)
            ->willReturn($groups);

        $controller = $this->createController($serviceMock);

        $response = $controller->getSharingGroups();

        $this->assertSame(200, $response->statusCode());

        $payload = $this->decodeResponse($response);

        $this->assertSame('success', $payload['status']);
        $this->assertSame($groups, $payload['groups']);
    }

    /**
     * Tests unauthorized access for sharing group retrieval.
     *
     * @return void
     */
    public function testGetSharingGroupsReturns403WhenUnauthorized(): void
    {
        $serviceMock = $this->createServiceMock();
        $controller = $this->createController($serviceMock, null, 'GET', false);

        $response = $controller->getSharingGroups();

        $this->assertSame(403, $response->statusCode());
        $this->assertSame(
            'Unauthorized access.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests invalid sharing group parameters.
     *
     * @return void
     */
    public function testGetSharingGroupsReturns400ForInvalidQuery(): void
    {
        $serviceMock = $this->createServiceMock();
        $controller = $this->createController($serviceMock);
        $controller->request->query = [
            'all' => 'invalid',
        ];

        $response = $controller->getSharingGroups();

        $this->assertSame(400, $response->statusCode());
        $this->assertSame(
            'Invalid parameters provided for sharing groups.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests internal errors during sharing group retrieval.
     *
     * @return void
     */
    public function testGetSharingGroupsReturns500OnThrowable(): void
    {
        $serviceMock = $this->createServiceMock();

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('getAvailableSharingGroups')
            ->with($this->isInstanceOf(MsgdUserDTO::class), false)
            ->willThrowException(new RuntimeException('Service failure.'));

        $controller = $this->createController($serviceMock);

        $response = $controller->getSharingGroups();

        $this->assertSame(500, $response->statusCode());
        $this->assertSame(
            'Failed to retrieve sharing groups data.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Provides identifier modes for blueprint checks.
     *
     * @return array<string, array{bool, array<int, int|string>}>
     */
    public function blueprintIdentifierProvider(): array
    {
        return [
            'UUIDs' => [
                false,
                [self::UUID_1, self::UUID_2],
            ],
            'IDs' => [
                true,
                [self::GROUP_ID_1, self::GROUP_ID_2],
            ],
        ];
    }

    /**
     * Tests successful blueprint verification.
     *
     * @param bool $useIds Identifier mode.
     * @param array<int, int|string> $groups Groups to verify.
     *
     * @return void
     *
     * @dataProvider blueprintIdentifierProvider
     */
    public function testCheckBlueprintReturns200(
        bool $useIds,
        array $groups
    ): void {
        $serviceMock = $this->createServiceMock();

        /** @var InvocationMocker $expectation1 */
        $expectation1 = $serviceMock->expects($this->once());
        $expectation1->method('isUsingIds')
            ->willReturn($useIds);

        /** @var InvocationMocker $expectation2 */
        $expectation2 = $serviceMock->expects($this->once());
        $expectation2->method('isBlueprint')
            ->with(
                $this->isInstanceOf(MsgdUserDTO::class),
                $this->isInstanceOf(MsgdCheckBlueprintDTO::class)
            )
            ->willReturn(true);

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST',
            true,
            $useIds
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => $groups,
            ],
        ];

        $controller->request->params['_Token'] = ['key' => 'next-token'];

        $response = $controller->checkBlueprint();

        $this->assertSame(200, $response->statusCode());

        $payload = $this->decodeResponse($response);

        $this->assertSame('success', $payload['status']);
        $this->assertTrue($payload['exists']);
        $this->assertSame('next-token', $payload['nextToken']);
    }

    /**
     * Tests invalid blueprint payload handling.
     *
     * @return void
     */
    public function testCheckBlueprintReturns400ForInvalidPayload(): void
    {
        $serviceMock = $this->createServiceMock();

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST'
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => 'invalid',
            ],
        ];

        $response = $controller->checkBlueprint();

        $this->assertSame(400, $response->statusCode());
        $this->assertSame(
            'Invalid payload format for blueprint verification.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests rejection of numeric identifiers in UUID mode.
     *
     * @return void
     */
    public function testCheckBlueprintRejectsIdInUuidMode(): void
    {
        $serviceMock = $this->createServiceMock();

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST'
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => [self::GROUP_ID_1],
            ],
        ];

        $response = $controller->checkBlueprint();

        $this->assertSame(400, $response->statusCode());
        $this->assertSame(
            'Invalid payload format for blueprint verification.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests rejection of UUID identifiers in ID mode.
     *
     * @return void
     */
    public function testCheckBlueprintRejectsUuidInIdMode(): void
    {
        $serviceMock = $this->createServiceMock();

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST',
            true,
            true
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => [self::UUID_1],
            ],
        ];

        $response = $controller->checkBlueprint();

        $this->assertSame(400, $response->statusCode());
        $this->assertSame(
            'Invalid payload format for blueprint verification.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests forbidden blueprint verification.
     *
     * @return void
     */
    public function testCheckBlueprintReturns403OnForbiddenException(): void
    {
        $serviceMock = $this->createServiceMock();

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('isBlueprint')
            ->with(
                $this->isInstanceOf(MsgdUserDTO::class),
                $this->isInstanceOf(MsgdCheckBlueprintDTO::class)
            )
            ->willThrowException(new ForbiddenException('Access denied.'));

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST'
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => [self::UUID_1],
            ],
        ];

        $response = $controller->checkBlueprint();

        $this->assertSame(403, $response->statusCode());
        $this->assertSame(
            'Access denied.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests internal errors during blueprint verification.
     *
     * @return void
     */
    public function testCheckBlueprintReturns500OnThrowable(): void
    {
        $serviceMock = $this->createServiceMock();

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('isUsingIds')
            ->willThrowException(new RuntimeException('Service failure.'));

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST'
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => [self::UUID_1],
            ],
        ];

        $response = $controller->checkBlueprint();

        $this->assertSame(500, $response->statusCode());
        $this->assertSame(
            'Failed to verify blueprint existence.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests unauthorized access for group processing.
     *
     * @return void
     */
    public function testProcessGroupsReturns403WhenUnauthorized(): void
    {
        $serviceMock = $this->createServiceMock();

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST',
            false
        );

        $response = $controller->processGroups();

        $this->assertSame(403, $response->statusCode());
        $this->assertSame(
            'Unauthorized access.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests invalid group processing payload handling.
     *
     * @return void
     */
    public function testProcessGroupsReturns400ForInvalidPayload(): void
    {
        $serviceMock = $this->createServiceMock();

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST'
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => 'invalid',
            ],
        ];

        $response = $controller->processGroups();

        $this->assertSame(400, $response->statusCode());
        $this->assertSame(
            'Invalid payload format for processing groups.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests the missing result for single group processing.
     *
     * @param bool $useIds Identifier mode.
     * @param array<int, int|string> $groups Groups to process.
     *
     * @return void
     *
     * @dataProvider blueprintIdentifierProvider
     */
    public function testProcessGroupsSingleReturns404(
        bool $useIds,
        array $groups
    ): void {
        $serviceMock = $this->createServiceMock();

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('processSingleGroup')
            ->with(
                $this->isInstanceOf(MsgdUserDTO::class),
                $groups[0]
            )
            ->willReturn(null);

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST',
            true,
            $useIds
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => [$groups[0]],
            ],
        ];

        $response = $controller->processGroups();

        $this->assertSame(404, $response->statusCode());
        $this->assertSame(
            'Target sharing group could not be found.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests successful processing of multiple groups.
     *
     * @return void
     */
    public function testProcessGroupsMultipleReturns200(): void
    {
        $serviceMock = $this->createServiceMock();
        $result = new MsgdProcessResultDTO(
            [
                'group' => [
                    'is_new' => true,
                    'has_blueprint' => true,
                    'sharing_group_id' => 10,
                    'sharing_group_name' => 'Test Group',
                ]
            ]
        );

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('processMultiple')
            ->with(
                $this->isInstanceOf(MsgdUserDTO::class),
                $this->isInstanceOf(MsgdProcessGroupsDTO::class)
            )
            ->willReturn($result);

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST',
            true,
            false
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => [self::UUID_1, self::UUID_2],
            ],
        ];

        $response = $controller->processGroups();

        $this->assertSame(200, $response->statusCode());

        $payload = $this->decodeResponse($response);

        $this->assertSame('success', $payload['status']);
        $this->assertIsArray($payload['group']);
    }

    /**
     * Tests forbidden group processing.
     *
     * @return void
     */
    public function testProcessGroupsReturns403OnForbiddenException(): void
    {
        $serviceMock = $this->createServiceMock();

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('processSingleGroup')
            ->with(
                $this->isInstanceOf(MsgdUserDTO::class),
                self::UUID_1
            )
            ->willThrowException(new ForbiddenException('Access denied.'));

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST'
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => [self::UUID_1],
            ],
        ];

        $response = $controller->processGroups();

        $this->assertSame(403, $response->statusCode());
        $this->assertSame(
            'Access denied.',
            $this->decodeResponse($response)['message']
        );
    }

    /**
     * Tests internal errors during group processing.
     *
     * @return void
     */
    public function testProcessGroupsReturns500OnThrowable(): void
    {
        $serviceMock = $this->createServiceMock();

        /** @var InvocationMocker $expectation */
        $expectation = $serviceMock->expects($this->once());
        $expectation->method('isUsingIds')
            ->willThrowException(new RuntimeException('Service failure.'));

        $controller = $this->createController(
            $serviceMock,
            null,
            'POST'
        );

        $controller->request->data = [
            'MsgdPlug' => [
                'groups' => [self::UUID_1],
            ],
        ];

        $response = $controller->processGroups();

        $this->assertSame(500, $response->statusCode());
        $this->assertSame(
            'System error while processing blueprint.',
            $this->decodeResponse($response)['message']
        );
    }
}
