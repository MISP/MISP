<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Allowedlists\Admin;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class AddAllowedlistApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/allowedlists/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Allowedlists'
    ];

    public function testAdminAddAllowedlist(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $regex = '/127.0.0.\d+/';

        $this->post(
            self::ENDPOINT,
            [
                'name' => $regex,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('Allowedlists', ['name' => $regex]);
    }

    public function testAdminAddAllowedlistFailsOnInvalidRegex(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $regex = 'foobar';

        $this->post(
            self::ENDPOINT,
            [
                'name' => $regex,
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains("Allowedlist could not be added");
        $this->assertDbRecordNotExists('Allowedlists', ['name' => $regex]);
    }
}
