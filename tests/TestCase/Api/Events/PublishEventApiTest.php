<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Events;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EventsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;
use Cake\Core\Configure;

class PublishEventApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/events/publish';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Events',
    ];

    public function testPublishEvent(): void
    {
        $this->skipOpenApiValidations();

        Configure::write('BackgroundJobs.enabled', false);

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, EventsFixture::EVENT_1_ID);

        $this->assertDbRecordExists('Events', ['id' => EventsFixture::EVENT_1_ID, 'published' => false]);

        # publish
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Event published without alerts"');
        $this->assertDbRecordExists('Events', ['id' => EventsFixture::EVENT_1_ID, 'published' => true]);
    }
}
