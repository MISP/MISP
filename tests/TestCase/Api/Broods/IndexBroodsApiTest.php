<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Broods;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\BroodsFixture;
use App\Test\Helper\ApiTestTrait;

class IndexBroodsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/users/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Broods'
    ];

    public function testIndexBroods(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', BroodsFixture::BROOD_A_ID));
    }
}
