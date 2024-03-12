<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Events;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EventsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewEventApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/events/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Events',
    ];

    public function testViewEvent(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, EventsFixture::EVENT_1_ID);

        $this->post($url);
        $this->assertResponseOk();

        $event = $this->getJsonResponseAsArray();

        $this->assertEquals(EventsFixture::EVENT_1_ID, $event['Event']['id']);
    }
}
