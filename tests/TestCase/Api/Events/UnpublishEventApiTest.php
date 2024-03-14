<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Events;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EventsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;
use Cake\Core\Configure;

class UnpublishEventApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/events/unpublish';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Events',
    ];

    public function testUnpublishEvent(): void
    {
        $this->skipOpenApiValidations();

        Configure::write('BackgroundJobs.enabled', false);

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, EventsFixture::EVENT_2_ID);

        $this->assertDbRecordExists('Events', ['id' => EventsFixture::EVENT_2_ID, 'published' => true]);

        # unpublish
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Event unpublished."');
        $this->assertDbRecordExists('Events', ['id' => EventsFixture::EVENT_2_ID, 'published' => false]);
    }
}
