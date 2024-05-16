<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Events;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EventsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class RestSearchEventApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/events/restSearch';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Events',
    ];

    public function testRestSearchByInfo(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, EventsFixture::EVENT_1_ID);

        $this->post(
            self::ENDPOINT,
            [
                'info' => 'Event 1'
            ]
        );
        $this->assertResponseOk();

        $results = $this->getJsonResponseAsArray();

        $this->assertEquals(EventsFixture::EVENT_1_ID, $results['response'][0]['Event']['id']);
    }
}
