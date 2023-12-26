<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CerebratesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewCerebrateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/cerebrates/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testViewCerebrateById(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->get($url);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', CerebratesFixture::SERVER_A_NAME));
    }

    public function testViewByIdNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CerebratesFixture::SERVER_A_ID);
        $this->get($url);

        $this->assertResponseCode(405);
    }
}
