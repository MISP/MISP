<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Individuals;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class AddIndividualApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/individuals/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testAddIndividual(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->post(
            self::ENDPOINT,
            [
                'email' => 'john@example.com',
                'first_name' => 'John',
                'last_name' => 'Doe',
                'position' => 'Security Analyst'
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains('"email": "john@example.com"');
        $this->assertDbRecordExists('Individuals', ['email' => 'john@example.com']);
    }

    // public function testAddUserNotAllowedAsRegularUser(): void
    // {
    //     $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
    //     $this->post(
    //         self::ENDPOINT,
    //         [
    //             'email' => 'john@example.com',
    //             'first_name' => 'John',
    //             'last_name' => 'Doe',
    //             'position' => 'Security Analyst'
    //         ]
    //     );

    //     $this->assertResponseCode(405);
    //     $this->assertDbRecordNotExists('Individuals', ['email' => 'john@example.com']);
    // }
}
