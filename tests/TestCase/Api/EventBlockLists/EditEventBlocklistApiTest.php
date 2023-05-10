<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\EventBlocklists;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use App\Test\Fixture\EventBlocklistsFixture;

class EditEventBlocklistApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/event-blocklists/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.EventBlocklists'
    ];

    public function testEditEventBlocklist(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $new_event_info = "NEW EVENT INFO";
        $new_comment = "NEW COMMENT";
        $new_event_orgc = "NEW ORGC";
        $url = sprintf('%s/%s', self::ENDPOINT, EventBlocklistsFixture::EVENT_BLOCK_LIST_1_EVENT_UUID);

        $this->post(
            $url,
            [
                'event_info' => $new_event_info,
                'comment' => $new_comment,
                'event_orgc' => $new_event_orgc,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('EventBlocklists', [
            'event_uuid' => EventBlocklistsFixture::EVENT_BLOCK_LIST_1_EVENT_UUID,
            'event_info' => $new_event_info,
            'comment' => $new_comment,
            'event_orgc' => $new_event_orgc
        ]);
    }
}
