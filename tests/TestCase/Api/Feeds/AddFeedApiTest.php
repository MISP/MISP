<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Feeds;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddFeedApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/feeds/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Feeds'
    ];

    public function testAddFeed(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->post(
            self::ENDPOINT,
            [
                "name" => "feed-osint",
                "provider" => "CIRCL",
                "url" => "https://www.circl.lu/doc/misp/feed-osint",
                "rules" => "{\"tags\":{\"OR\":[],\"NOT\":[]},\"orgs\":{\"OR\":[],\"NOT\":[]},\"url_params\":\"\"}",
                "source_format" => "1"
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('Feeds', ['name' => 'feed-osint']);
    }
}
