<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\Auth\FormAuthenticate;
use Cake\Http\ServerRequest;
use Cake\Http\Response;
use Cake\Controller\ComponentRegistry;

class ChangePasswordApiTest extends TestCase
{
    // use ApiTestTrait;

    // protected const ENDPOINT = '/users/edit';

    // /** @var \Cake\Auth\FormAuthenticate */
    // protected $auth;

    // /** @var \Cake\Controller\ComponentRegistry */
    // protected $collection;

    // protected $fixtures = [
    //     'app.Organisations',
    //     'app.Individuals',
    //     'app.Roles',
    //     'app.Users',
    //     'app.AuthKeys'
    // ];

    // public function setUp(): void
    // {
    //     parent::setUp();
    //     $this->initializeOpenApiValidator();

    //     $this->collection = new ComponentRegistry();
    //     $this->auth = new FormAuthenticate($this->collection, [
    //         'userModel' => 'Users',
    //     ]);
    // }

    // public function testChangePasswordOwnUser(): void
    // {
    //     $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
    //     $newPassword = 'Test12345678!';

    //     $this->put(
    //         self::ENDPOINT,
    //         [
    //             'password' => $newPassword,
    //         ]
    //     );

    //     $this->assertResponseOk();

    //     // Test new password with form login
    //     $request = new ServerRequest([
    //         'url' => 'users/login',
    //         'post' => [
    //             'username' => UsersFixture::USER_REGULAR_USER_USERNAME,
    //             'password' => $newPassword
    //         ],
    //     ]);
    //     $result = $this->auth->authenticate($request, new Response());

    //     $this->assertEquals(UsersFixture::USER_REGULAR_USER_ID, $result['id']);
    //     $this->assertEquals(UsersFixture::USER_REGULAR_USER_USERNAME, $result['username']);
    // }
}
