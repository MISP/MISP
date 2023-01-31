<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Broods;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\BroodsFixture;
use App\Test\Helper\ApiTestTrait;

class ViewBroodApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/broods/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Broods'
    ];

    public function testViewBroodGroupById(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, BroodsFixture::BROOD_A_ID);
        $this->get($url);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', BroodsFixture::BROOD_A_ID));
    }
}
