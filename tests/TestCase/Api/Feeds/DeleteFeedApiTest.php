<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Feeds;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\FeedsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteFeedApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/feeds/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Feeds',
    ];

    public function testDeleteFeed(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, FeedsFixture::FEED_2_ID);

        $this->assertDbRecordExists('Feeds', ['id' => FeedsFixture::FEED_2_ID]);

        $this->post($url);
        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Feeds', ['id' => FeedsFixture::FEED_2_ID]);
    }
}
