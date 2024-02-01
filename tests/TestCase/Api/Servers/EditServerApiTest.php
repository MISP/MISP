<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\FeedsFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class EditServerApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/servers/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers'
    ];

    public function testEditServer(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%s', self::ENDPOINT, ServersFixture::SERVER_A_ID);

        $faker = \Faker\Factory::create();
        $newUrl = $faker->url;

        $this->put(
            $url,
            [
                "url" => $newUrl,
                "push" => false,
                "pull" => true,
                "pull_rules" => [
                    "tags" => [
                        "OR" => [],
                        "NOT" => ["tlp:red"]
                    ],
                    "orgs" => [
                        "OR" => [],
                        "NOT" => []
                    ],
                    "type_attributes" => [
                        "NOT" => []
                    ], "type_objects" => [
                        "NOT" => []
                    ],
                    "url_params" => ""
                ]
            ]
        );

        $this->assertResponseOk();
        $response = $this->getJsonResponseAsArray();

        $this->assertDbRecordExists(
            'Servers',
            [
                'id' => ServersFixture::SERVER_A_ID,
                'url' => $newUrl,
                'push' => false,
                'pull' => true,
            ]
        );
        $this->assertEquals($response['pull_rules']['tags']['NOT'], ['tlp:red']);
    }
}
