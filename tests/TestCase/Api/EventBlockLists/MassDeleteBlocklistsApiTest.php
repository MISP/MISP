<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use App\Test\Fixture\EventBlocklistsFixture;

class MassDeleteBlocklistsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/event-blocklists/massDelete';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.EventBlocklists'
    ];

    public function testMassDeleteEventBlocklists(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->post(
            self::ENDPOINT,
            [
                EventBlocklistsFixture::EVENT_BLOCK_LIST_1_ID,
                EventBlocklistsFixture::EVENT_BLOCK_LIST_2_ID
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('EventBlocklists', ['id' => EventBlocklistsFixture::EVENT_BLOCK_LIST_1_ID]);
        $this->assertDbRecordNotExists('EventBlocklists', ['id' => EventBlocklistsFixture::EVENT_BLOCK_LIST_2_ID]);
    }
}
