<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Allowedlists\Admin;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use App\Test\Fixture\AllowedlistsFixture;

class EditAllowedlistApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/allowedlists/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Allowedlists'
    ];

    public function testAdminEditAllowedlist(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $new_regex = "/10.0.0.\d+/";
        $url = sprintf('%s/%s', self::ENDPOINT, AllowedlistsFixture::ALLOWED_LIST_2_ID);

        $this->post(
            $url,
            [
                'name' => $new_regex
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('Allowedlists', [
            'id' => AllowedlistsFixture::ALLOWED_LIST_2_ID,
            'name' => $new_regex,
        ]);
    }
}
