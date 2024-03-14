<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Core\Configure;
use Cake\Http\TestSuite\HttpClientTrait;
use Cake\TestSuite\TestCase;

class PullServerApiTest extends TestCase
{
    use ApiTestTrait;
    use HttpClientTrait;

    protected const ENDPOINT = '/servers/pull';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.Events',
        'app.Attributes',
    ];

    public function testPullFromServer(): void
    {
        $this->skipOpenApiValidations();

        Configure::write('BackgroundJobs.enabled', false);

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, ServersFixture::SERVER_A_ID);

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
            ServersFixture::SERVER_A_URL . '/servers/getVersion',
            $this->newClientResponse(200, $headers, $getVersionBody)
        );

        // mock the /events/index request
        $eventsIndexBody = json_encode(
            [
                [
                    "id" => "10",
                    "timestamp" => "1700488705",
                    "sighting_timestamp" => "0",
                    "published" => true,
                    "uuid" => "56bf399d-c46c-4fdb-a9cf-d9bb02de0b81",
                    "orgc_uuid" => "55f6ea5e-2c60-40e5-964f-47a8950d210f"
                ]
            ]
        );

        $this->mockClientPost(
            ServersFixture::SERVER_A_URL . '/events/index',
            $this->newClientResponse(200, $headers, $eventsIndexBody)
        );

        // mock the /events/view/[uuid] request
        $eventBody = json_encode(
            [
                "Event" => [
                    "analysis" => "2",
                    "date" => "2015-12-18",
                    "extends_uuid" => "",
                    "info" => "OSINT - Hunting for Malware with Machine Learning",
                    "publish_timestamp" => "1455373314",
                    "sharing_group_id" => "0",
                    "distribution" => "0",
                    "published" => true,
                    "threat_level_id" => "3",
                    "timestamp" => "1455373240",
                    "uuid" => "56bf399d-c46c-4fdb-a9cf-d9bb02de0b81",
                    "Orgc" => [
                        "name" => "CIRCL",
                        "uuid" => "55f6ea5e-2c60-40e5-964f-47a8950d210f"
                    ],
                    "Tag" => [
                        [
                            "colour" => "#004646",
                            "local" => "0",
                            "name" => "type:OSINT",
                            "relationship_type" => ""
                        ],
                        [
                            "colour" => "#ffffff",
                            "local" => "0",
                            "name" => "tlp:white",
                            "relationship_type" => ""
                        ]
                    ],
                    "Attribute" => [
                        [
                            "category" => "External analysis",
                            "comment" => "",
                            "deleted" => false,
                            "disable_correlation" => false,
                            "sharing_group_id" => "0",
                            "distribution" => "0",
                            "timestamp" => "1455372745",
                            "to_ids" => false,
                            "type" => "link",
                            "uuid" => "56bf39c9-c078-4368-9555-6cf802de0b81",
                            "value" => "http://blog.cylance.com/hunting-for-malware-with-machine-learning"
                        ]
                    ]
                ]
            ]
        );

        // mock the event [uuid].json request
        $this->mockClientGet(
            'http://aaa.local/events/view/56bf399d-c46c-4fdb-a9cf-d9bb02de0b81/deleted%5B%5D:0/deleted%5B%5D:1/excludeGalaxy:1/includeEventCorrelations:0/includeFeedCorrelations:0/includeWarninglistHits:0/excludeLocalTags:1',
            $this->newClientResponse(200, $headers, $eventBody)
        );

        // mock the /galaxy_clusters/restSearch request
        $this->mockClientPost(
            ServersFixture::SERVER_A_URL . '/galaxy_clusters/restSearch',
            $this->newClientResponse(200, $headers, '[]')
        );

        $this->post($url);
        $this->assertResponseOk();

        $response = $this->getJsonResponseAsArray();
        $this->assertEquals(
            'Pull completed. 1 events pulled, 0 events could not be pulled, 0 proposals pulled, 0 sightings pulled, 0 clusters pulled.',
            $response['message']
        );

        // check that the event was added
        $this->assertDbRecordExists('Events', ['uuid' => '56bf399d-c46c-4fdb-a9cf-d9bb02de0b81']);
        $this->assertDbRecordExists('Attributes', ['uuid' => '56bf39c9-c078-4368-9555-6cf802de0b81']);

        // TODO: check that the proposals were added
        // TODO: check that the objects were added
        // TODO: check that the event reports were added
        // TODO: check that the sightings were added
        // TODO: check that the tags were added
        // TODO: check that the galaxies were added
        // TODO: check that the cryptographic keys were added
    }
}
