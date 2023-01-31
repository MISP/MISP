<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Inbox;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Authentication\PasswordHasher\DefaultPasswordHasher;

class CreateInboxEntryApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/inbox/createEntry';

    protected $fixtures = [
        'app.Inbox',
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testAddUserRegistrationInbox(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        // to avoid $this->request->clientIp() to return null
        $_SERVER['REMOTE_ADDR'] = '::1';

        $url = sprintf("%s/%s/%s", self::ENDPOINT, 'User', 'Registration');
        $password = 'Password12345!';
        $email = 'john@example.com';
        $this->post(
            $url,
            [
                'email' => $email,
                'password' => $password
            ]
        );
        $this->assertResponseOk();

        $response = $this->getJsonResponseAsArray();
        $userId = $response['data']['id'];

        $createdInboxMessage = $this->getRecordFromDb(
            'Inbox',
            [
                'id' => $userId,
                'scope' => 'User',
                'action' => 'Registration'
            ]
        );

        $this->assertTrue((new DefaultPasswordHasher())->check($password, $createdInboxMessage['data']['password']));
        $this->assertEquals($email, $createdInboxMessage['data']['email']);
    }

    public function testAddUserRegistrationInboxNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $url = sprintf("%s/%s/%s", self::ENDPOINT, 'User', 'Registration');
        $this->post(
            $url,
            [
                'email' => 'john@example.com',
                'password' => 'Password12345!'
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('Inbox', ['id' => 3]);
    }
}
