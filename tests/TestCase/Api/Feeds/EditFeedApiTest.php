<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Feeds;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\FeedsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class EditFeedApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/feeds/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Feeds'
    ];

    public function testEditFeed(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%s', self::ENDPOINT, FeedsFixture::FEED_1_ID);

        $this->put(
            $url,
            [
                "name" => "feed-osint",
                "provider" => "CIRCL",
                "url" => "https://www.circl.lu/doc/misp/feed-osint",
                "rules" => [
                    "tags" => [
                        "OR" => [],
                        "NOT" => []
                    ],
                    "orgs" => [
                        "OR" => [],
                        "NOT" => []
                    ],
                    "url_params" => ""
                ],
                "settings" => [
                    "csv" => [
                        "value" => "",
                        "delimiter" => ""
                    ],
                    "common" => [
                        "excluderegex" => ""
                    ]
                ]
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'Feeds',
            [
                'id' => FeedsFixture::FEED_1_ID,
                'name' => 'feed-osint',
            ]
        );
    }
}
