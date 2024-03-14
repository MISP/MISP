<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Feeds;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\FeedsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewFeedApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/feeds/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Feeds',
    ];

    public function testViewFeed(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, FeedsFixture::FEED_1_ID);

        $this->post($url);
        $this->assertResponseOk();

        $feed = $this->getJsonResponseAsArray();

        $this->assertEquals(FeedsFixture::FEED_1_ID, $feed['id']);
    }
}
