<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Sightingdbs;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddSightingdbsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sightingdbs/add';

    protected $fixtures = [
        'app.Sightingdbs',
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testAddSightingdb(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->post(
            self::ENDPOINT,
            [
                'name' => 'sightingdbx',
                'description' => 'test db x',
                'owner' => 0,
                'host' => 'sightingdb3.misp-project.org',
                'port' => 27016,
                'enabled' => 1,
                'skip_proxy' => 0,
                'ssl_skip_verification' => 0,
                'namespace' => 'mispx'
            ],
        );
        $this->assertResponseOk();
        $this->assertDbRecordExists('Sightingdbs', ['name' => 'sightingdbx']);
    }
}
