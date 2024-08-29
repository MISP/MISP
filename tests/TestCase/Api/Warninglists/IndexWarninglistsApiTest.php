<?php
declare(strict_types=1);

namespace App\Test\TestCase\Api\Warninglists;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\WarninglistsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexWarninglistsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/warninglists/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Warninglists',
        'app.WarninglistEntries',
        'app.WarninglistTypes',
    ];

    public function testIndexWarninglistsAsAdmin(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);
        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', WarninglistsFixture::WARNINGLIST_CIDR_1_NAME));
    }

    public function testIndexWarninglistsAsUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $this->get(self::ENDPOINT);
        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', WarninglistsFixture::WARNINGLIST_CIDR_1_NAME));
    }
}
