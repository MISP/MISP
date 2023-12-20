<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\EventBlocklists;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EventBlocklistsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexEventBlocklistsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/event-blocklists/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.EventBlocklists'
    ];

    public function testIndexEventBlocklists(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"event_uuid": "%s"', EventBlocklistsFixture::EVENT_BLOCK_LIST_1_EVENT_UUID));
    }
}
