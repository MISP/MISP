<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EventsFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Core\Configure;
use Cake\Http\TestSuite\HttpClientTrait;
use Cake\TestSuite\TestCase;

class PushServerApiTest extends TestCase
{
    use ApiTestTrait;
    use HttpClientTrait;

    protected const ENDPOINT = '/servers/push';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.Events',
        'app.Attributes',
    ];

    public function testPushToServer(): void
    {
        $this->skipOpenApiValidations();

        Configure::write('BackgroundJobs.enabled', false);

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, ServersFixture::SERVER_B_ID);

        $headers = [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: MISP 3.0.0 - #cc1f8cc2e89ec692168ffbfea8ed49cc879c469b',
            'ETag: W/"2a-1b6e3e8e"',
        ];

        // mock the /servers/getVersion request
        $getVersionBody = json_encode(
            [
                "version" => "3.0.0",
                "pymisp_recommended_version" => "3.0.0",
                "perm_sync" => true,
                "perm_sighting" => true,
                "perm_galaxy_editor" => true,
                "request_encoding" => [
                    "gzip",
                    "br"
                ],
                "filter_sightings" => true
            ]
        );

        $this->mockClientGet(
            ServersFixture::SERVER_B_URL . '/servers/getVersion',
            $this->newClientResponse(200, $headers, $getVersionBody)
        );

        // mock the /events/filterEventIdsForPush request
        $filterEventIdsForPushBody = json_encode(
            [
                EventsFixture::EVENT_1_UUID
            ]
        );
        $this->mockClientPost(
            ServersFixture::SERVER_B_URL . '/events/filterEventIdsForPush',
            $this->newClientResponse(200, $headers, $filterEventIdsForPushBody)
        );

        // mock the /events/index request, triggered by syncProposals()
        $this->mockClientPost(
            ServersFixture::SERVER_B_URL . '/events/index',
            $this->newClientResponse(200, $headers, '[]')
        );

        // mock the /events/view/[uuid] request
        $this->mockClientGet(
            ServersFixture::SERVER_B_URL . '/events/view/' . EventsFixture::EVENT_1_UUID,
            $this->newClientResponse(200, $headers, '[]')
        );

        // mock the /events/add/metadata:1
        $this->mockClientPost(
            ServersFixture::SERVER_B_URL . '/events/add/metadata:1',
            $this->newClientResponse(200, $headers, '[]')
        );

        $this->post($url);
        $this->assertResponseOk();

        $response = $this->getJsonResponseAsArray();
        $this->assertEquals(
            'Push complete. 1 events pushed, 0 events could not be pushed.',
            $response['message']
        );
    }
}
