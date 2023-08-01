<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuthKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class EditAuthKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/auth-keys/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testEditEventBlocklist(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $new_comment = 'test read only key';
        $url = sprintf('%s/%s', self::ENDPOINT, AuthKeysFixture::REGULAR_USER_API_ID);

        $this->post(
            $url,
            [
                'read_only' => true,
                'comment' => $new_comment,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('AuthKeys', [
            'id' => AuthKeysFixture::REGULAR_USER_API_ID,
            'read_only' => true,
            'comment' => $new_comment
        ]);
    }
}
