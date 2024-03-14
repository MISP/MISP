<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Events;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EventsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexEventsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/events/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Events',
    ];

    public function testIndexEvents(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', EventsFixture::EVENT_1_ID));
    }
}
