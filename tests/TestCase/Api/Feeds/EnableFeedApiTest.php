<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Feeds;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\FeedsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class EnableFeedApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/feeds/enable';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Feeds',
    ];

    public function testEnableFeed(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, FeedsFixture::FEED_2_ID);

        $this->assertDbRecordExists('Feeds', ['id' => FeedsFixture::FEED_2_ID, 'enabled' => false]);

        # enable
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Feed enabled."');
        $this->assertDbRecordExists('Feeds', ['id' => FeedsFixture::FEED_2_ID, 'enabled' => true]);
    }
}
