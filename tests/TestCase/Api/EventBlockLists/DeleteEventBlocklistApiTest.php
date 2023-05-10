<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use App\Test\Fixture\EventBlocklistsFixture;

class DeleteEventBlocklistApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/event-blocklists/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.EventBlocklists'
    ];

    public function testDeleteEventBlocklistByUUID(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, EventBlocklistsFixture::EVENT_BLOCK_LIST_1_EVENT_UUID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('EventBlocklists', ['event_uuid' => EventBlocklistsFixture::EVENT_BLOCK_LIST_1_EVENT_UUID]);
    }

    public function testDeleteEventBlocklistById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, EventBlocklistsFixture::EVENT_BLOCK_LIST_1_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('EventBlocklists', ['event_uuid' => EventBlocklistsFixture::EVENT_BLOCK_LIST_1_EVENT_UUID]);
    }
}
