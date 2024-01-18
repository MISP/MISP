<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Feeds;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\FeedsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class LoadDefaultFeedsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/feeds/loadDefaultFeeds';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Feeds',
    ];

    public function testLoadDefaultFeeds(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->assertDbRecordExists('Feeds', ['id' => FeedsFixture::FEED_2_ID, 'enabled' => false]);

        $totalFixtureFeeds = $this->getTableLocator()->get('Feeds')->find()->count();
        $totalDefaultFeeds = 73;

        $this->post(self::ENDPOINT);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Default feed metadata loaded."');

        $totalFeeds = $this->getTableLocator()->get('Feeds')->find()->count();
        $this->assertEquals($totalFixtureFeeds + $totalDefaultFeeds, $totalFeeds);
    }
}
