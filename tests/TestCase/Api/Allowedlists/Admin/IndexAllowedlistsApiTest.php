<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Allowedlists\Admin;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\AllowedlistsFixture;
use App\Test\Helper\ApiTestTrait;

class IndexAllowedlistsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/allowedlists/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Allowedlists',
    ];

    public function testIndexAllowed(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', AllowedlistsFixture::ALLOWED_LIST_1_ID));
    }
}
