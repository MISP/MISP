<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\EventBlocklists;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class AddEventBlocklistApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/event-blocklists/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.EventBlocklists'
    ];

    public function testAddEventBlocklist(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $event_uuid = $faker->uuid();

        $this->post(
            self::ENDPOINT,
            [
                'uuids' => [$event_uuid],
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('EventBlocklists', ['event_uuid' => $event_uuid]);
    }
}
