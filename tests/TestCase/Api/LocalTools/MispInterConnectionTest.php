<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\LocalTools;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Fixture\RolesFixture;
use App\Test\Helper\ApiTestTrait;
use App\Test\Helper\WireMockTestTrait;
use \WireMock\Client\WireMock;

class MispInterConnectionTest extends TestCase
{
    use ApiTestTrait;
    use WireMockTestTrait;

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Broods',
        'app.LocalTools',
        'app.RemoteToolConnections',
        'app.Inbox'
    ];

    /** constants related to the local Cerebrate instance */
    private const LOCAL_CEREBRATE_URL = 'http://127.0.0.1';

    /** constants related to the local MISP instance */
    private const LOCAL_MISP_INSTANCE_URL = 'http://localhost:8080/MISP_LOCAL';
    private const LOCAL_MISP_ADMIN_USER_AUTHKEY = 'b17ce79ac0f05916f382ab06ea4790665dbc174c';

    /** constants related to the remote Cerebrate instance */
    private const REMOTE_CEREBRATE_URL = 'http://127.0.0.1:8080/CEREBRATE_REMOTE';
    private const REMOTE_CEREBRATE_AUTHKEY = 'a192ba3c749b545f9cec6b6bba0643736f6c3022';

    /** constants related to the remote MISP instance */
    private const REMOTE_MISP_SYNC_USER_ID = 333;
    private const REMOTE_MISP_SYNC_USER_EMAIL = 'sync@misp.remote';
    private const REMOTE_MISP_INSTANCE_URL = 'http://localhost:8080/MISP_REMOTE';
    private const REMOTE_MISP_AUTHKEY = '19ca57ecebd2fe34c1c17d729980678eb648d541';


    public function testInterConnectMispViaCerebrate(): void
    {
        $this->initializeWireMock();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();

        /**
         * 1. Create LocalTool connection to `MISP LOCAL` (local MISP instance)
         */
        $this->post(
            sprintf('%s/localTools/add', self::LOCAL_CEREBRATE_URL),
            [
                'name' => 'MISP_LOCAL',
                'connector' => 'MispConnector',
                'settings' => json_encode([
                    'url' => self::LOCAL_MISP_INSTANCE_URL,
                    'authkey' => self::LOCAL_MISP_ADMIN_USER_AUTHKEY,
                    'skip_ssl' => true,
                ]),
                'description' => 'MISP local instance',
                'exposed' => true
            ]
        );
        $this->assertResponseOk();
        $this->assertDbRecordExists('LocalTools', ['name' => 'MISP_LOCAL']);

        /**
         * 2. Create a new Brood (connect to a remote Cerebrate instance)
         * This step assumes that the remote Cerebrate instance is already 
         * running and has a user created for the local Cerebrate instance.
         * 
         * NOTE: Uses OrganisationsFixture::ORGANISATION_A_ID from the 
         * fixtures as the local Organisation.
         */
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $LOCAL_BROOD_UUID = $faker->uuid;
        $this->post(
            '/broods/add',
            [
                'uuid' => $LOCAL_BROOD_UUID,
                'name' => 'Local Brood',
                'url' => self::REMOTE_CEREBRATE_URL,
                'description' => $faker->text,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'trusted' => true,
                'pull' => true,
                'skip_proxy' => true,
                'authkey' => self::REMOTE_CEREBRATE_AUTHKEY,
            ]
        );
        $this->assertResponseOk();
        $this->assertDbRecordExists('Broods', ['uuid' => $LOCAL_BROOD_UUID]);
        $brood = $this->getJsonResponseAsArray();

        /**
         * 3. Create a new Cerebrate local user for the remote Cerebrate
         * These includes:
         *  - 3.a: Create a new Organisation
         *  - 3.b: Create a new Individual
         *  - 3.c: Create a new User
         *  - 3.d: Create a new Authkey
         */
        // Create Organisation
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $remoteOrgUuid = $faker->uuid;
        $this->post(
            '/organisations/add',
            [
                'name' => 'Remote Organisation',
                'description' => $faker->text,
                'uuid' => $remoteOrgUuid,
                'url' => 'http://cerebrate.remote',
                'nationality' => 'US',
                'sector' => 'sector',
                'type' => 'type',
            ]
        );
        $this->assertResponseOk();
        $this->assertDbRecordExists('Organisations', ['uuid' => $remoteOrgUuid]);
        $remoteOrg = $this->getJsonResponseAsArray();

        // Create Individual
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->post(
            '/individuals/add',
            [
                'email' => 'sync@cerebrate.remote',
                'first_name' => 'Remote',
                'last_name' => 'Cerebrate'
            ]
        );
        $this->assertResponseOk();
        $this->assertDbRecordExists('Individuals', ['email' => 'sync@cerebrate.remote']);
        $remoteIndividual = $this->getJsonResponseAsArray();

        // Create User
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->post(
            '/users/add',
            [
                'individual_id' => $remoteIndividual['id'],
                'organisation_id' => $remoteOrg['id'],
                'role_id' => RolesFixture::ROLE_SYNC_ID,
                'disabled' => false,
                'username' => 'remote_cerebrate',
                'password' => 'Password123456!',
            ]
        );
        $this->assertResponseOk();
        $this->assertDbRecordExists('Users', ['username' => 'remote_cerebrate']);
        $user = $this->getJsonResponseAsArray();

        // Create Authkey
        $remoteCerebrateAuthkey = $faker->sha1;
        $remoteAuthkeyUuid = $faker->uuid;
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->post(
            '/authKeys/add',
            [
                'uuid' => $remoteAuthkeyUuid,
                'authkey' => $remoteCerebrateAuthkey,
                'expiration' => 0,
                'user_id' => $user['id'],
                'comment' => $faker->text
            ]
        );
        $this->assertResponseOk();
        $this->assertDbRecordExists('AuthKeys', ['uuid' => $remoteAuthkeyUuid]);

        /**
         * 4. Get remote Cerebrate exposed tools
         */
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->mockCerebrateGetExposedToolsResponse('CEREBRATE_REMOTE', self::REMOTE_CEREBRATE_AUTHKEY);
        $this->get(sprintf('/localTools/broodTools/%s', $brood['id']));
        $this->assertResponseOk();
        $tools = $this->getJsonResponseAsArray();

        /**
         * 5. Issue a connection request to the remote MISP instance
         */
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->mockCerebrateGetExposedToolsResponse('CEREBRATE_REMOTE', self::REMOTE_CEREBRATE_AUTHKEY);
        $this->mockMispViewOrganisationByUuid(
            'MISP_LOCAL',
            self::LOCAL_MISP_ADMIN_USER_AUTHKEY,
            OrganisationsFixture::ORGANISATION_A_UUID,
            OrganisationsFixture::ORGANISATION_A_ID
        );
        $this->mockMispCreateSyncUser(
            'MISP_LOCAL',
            self::LOCAL_MISP_ADMIN_USER_AUTHKEY,
            self::REMOTE_MISP_SYNC_USER_ID,
            self::REMOTE_MISP_SYNC_USER_EMAIL
        );
        $this->mockCerebrateCreateMispIncommingConnectionRequest(
            'CEREBRATE_REMOTE',
            UsersFixture::USER_ADMIN_ID,
            self::LOCAL_CEREBRATE_URL,
            self::REMOTE_CEREBRATE_AUTHKEY,
            self::LOCAL_MISP_INSTANCE_URL
        );
        $this->post(
            sprintf('/localTools/connectionRequest/%s/%s', $brood['id'], $tools[0]['id']),
            [
                'local_tool_id' => 1
            ]
        );
        $this->assertResponseOk();

        /**
         * 6. Remote Cerebrate accepts the connection request
         */
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->post(
            '/inbox/createEntry/LocalTool/AcceptedRequest',
            [
                'email' => self::REMOTE_MISP_SYNC_USER_EMAIL,
                'authkey' => self::REMOTE_MISP_AUTHKEY,
                'url' => self::REMOTE_MISP_INSTANCE_URL,
                'reflected_user_id' => self::REMOTE_MISP_SYNC_USER_ID,
                'connectorName' => 'MispConnector',
                'cerebrateURL' => self::REMOTE_CEREBRATE_URL,
                'local_tool_id' => 1,
                'remote_tool_id' => 1,
                'tool_name' => 'MISP_REMOTE'
            ]
        );
        $this->assertResponseOk();
        $acceptRequest = $this->getJsonResponseAsArray();

        /**
         * 7. Finalize the connection
         */
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->mockEnableMispSyncUser('MISP_LOCAL', self::LOCAL_MISP_ADMIN_USER_AUTHKEY, self::REMOTE_MISP_SYNC_USER_ID);
        $this->mockAddMispServer(
            'MISP_LOCAL',
            self::LOCAL_MISP_ADMIN_USER_AUTHKEY,
            [
                'authkey' => self::REMOTE_MISP_AUTHKEY,
                'url' => self::REMOTE_MISP_INSTANCE_URL,
                'name' => 'MISP_REMOTE',
                'remote_org_id' => OrganisationsFixture::ORGANISATION_A_ID
            ]
        );
        $this->post(sprintf('/inbox/process/%s', $acceptRequest['data']['id']));
        $this->assertResponseOk();
        $this->assertResponseContains('"success": true');
        $this->verifyAllStubsCalled();
    }

    private function mockCerebrateGetExposedToolsResponse(string $instance, string $cerebrateAuthkey): \WireMock\Stubbing\StubMapping
    {
        return $this->getWireMock()->stubFor(
            WireMock::get(WireMock::urlEqualTo("/$instance/localTools/exposedTools"))
                ->withHeader('Authorization', WireMock::equalTo($cerebrateAuthkey))
                ->willReturn(WireMock::aResponse()
                    ->withHeader('Content-Type', 'application/json')
                    ->withBody((string)json_encode(
                        [
                            [
                                "id" => 1,
                                "name" => "MISP ($instance)",
                                "connector" => "MispConnector",
                            ]
                        ]
                    )))
        );
    }

    private function mockMispViewOrganisationByUuid(string $instance, string $mispAuthkey, string $orgUuid, int $orgId): \WireMock\Stubbing\StubMapping
    {
        return $this->getWireMock()->stubFor(
            WireMock::get(WireMock::urlEqualTo("/$instance/organisations/view/$orgUuid/limit:50"))
                ->withHeader('Authorization', WireMock::equalTo($mispAuthkey))
                ->willReturn(WireMock::aResponse()
                    ->withHeader('Content-Type', 'application/json')
                    ->withBody((string)json_encode(
                        [
                            "Organisation" => [
                                "id" => $orgId,
                                "name" => $instance . ' Organisation',
                                "uuid" => $orgUuid,
                                "local" => true
                            ]
                        ]
                    )))
        );
    }

    private function mockMispCreateSyncUser(string $instance, string $mispAuthkey, int $userId, string $email): \WireMock\Stubbing\StubMapping
    {
        $faker = \Faker\Factory::create();
        return $this->getWireMock()->stubFor(
            WireMock::post(WireMock::urlEqualTo("/$instance/admin/users/add"))
                ->withHeader('Authorization', WireMock::equalTo($mispAuthkey))
                ->willReturn(WireMock::aResponse()
                    ->withHeader('Content-Type', 'application/json')
                    ->withBody((string)json_encode(
                        [
                            "User" => [
                                "id" => $userId,
                                "email" => $email,
                                "authkey" => $faker->sha1
                            ]
                        ]
                    )))
        );
    }

    private function mockCerebrateCreateMispIncommingConnectionRequest(
        string $instance,
        int $userId,
        string $cerebrateUrl,
        string $cerebrateAuthkey,
        string $mispUrl
    ): \WireMock\Stubbing\StubMapping {
        $faker = \Faker\Factory::create();

        return $this->getWireMock()->stubFor(
            WireMock::post(WireMock::urlEqualTo("/$instance/inbox/createEntry/LocalTool/IncomingConnectionRequest"))
                ->withHeader('Authorization', WireMock::equalTo($cerebrateAuthkey))
                ->willReturn(WireMock::aResponse()
                    ->withHeader('Content-Type', 'application/json')
                    ->withBody((string)json_encode(
                        [
                            'data' => [
                                'id' => $faker->randomNumber(),
                                'uuid' => $faker->uuid,
                                'origin' => $cerebrateUrl,
                                'user_id' => $userId,
                                'data' => [
                                    'connectorName' => 'MispConnector',
                                    'cerebrateURL' => $cerebrateUrl,
                                    'url' => $mispUrl,
                                    'tool_connector' => 'MispConnector',
                                    'local_tool_id' => 1,
                                    'remote_tool_id' => 1,
                                ],
                                'title' => 'Request for MISP Inter-connection',
                                'scope' => 'LocalTool',
                                'action' => 'IncomingConnectionRequest',
                                'description' => 'Handle Phase I of inter-connection when another cerebrate instance performs the request.',
                                'local_tool_connector_name' => 'MispConnector',
                                'created' => date('c'),
                                'modified' => date('c')
                            ],
                            'success' => true,
                            'message' => 'LocalTool request for IncomingConnectionRequest created',
                            'errors' => [],
                        ]
                    )))
        );
    }

    private function mockEnableMispSyncUser(string $instance, string $mispAuthkey, int $userId): \WireMock\Stubbing\StubMapping
    {
        return $this->getWireMock()->stubFor(
            WireMock::post(WireMock::urlEqualTo("/$instance/admin/users/edit/$userId"))
                ->withHeader('Authorization', WireMock::equalTo($mispAuthkey))
                ->withRequestBody(WireMock::equalToJson(json_encode(['disabled' => false])))
                ->willReturn(WireMock::aResponse()
                    ->withHeader('Content-Type', 'application/json')
                    ->withBody((string)json_encode(
                        [
                            "User" => [
                                "id" => $userId,
                            ]
                        ]
                    )))
        );
    }

    private function mockAddMispServer(string $instance, string $mispAuthkey, array $body): \WireMock\Stubbing\StubMapping
    {
        $faker = \Faker\Factory::create();

        return $this->getWireMock()->stubFor(
            WireMock::post(WireMock::urlEqualTo("/$instance/servers/add"))
                ->withHeader('Authorization', WireMock::equalTo($mispAuthkey))
                ->withRequestBody(WireMock::equalToJson(json_encode($body)))
                ->willReturn(WireMock::aResponse()
                    ->withHeader('Content-Type', 'application/json')
                    ->withBody((string)json_encode(
                        [
                            'Server' => [
                                'id' => $faker->randomNumber()
                            ]
                        ]
                    )))
        );
    }
}
