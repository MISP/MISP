<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Allowedlists\Admin;

use App\Test\Fixture\AllowedlistsFixture;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteAllowedlistApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/allowedlists/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Allowedlists'
    ];

    public function testAdminDeleteAllowedlistById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, AllowedlistsFixture::ALLOWED_LIST_2_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Allowedlists', ['id' => AllowedlistsFixture::ALLOWED_LIST_2_ID]);
    }
}
