<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CerebratesFixture;
use App\Test\Helper\ApiTestTrait;

class IndexCerebratesApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/cerebrates/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testIndexCerebrates(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', CerebratesFixture::SERVER_A_NAME));
    }

    public function testIndexNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseCode(405);
    }
}
