<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\SightingdbsFixture;
use App\Test\Helper\ApiTestTrait;

class IndexSightingdbsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sightingdbs/index';

    protected $fixtures = [
        'app.Sightingdbs',
        'app.Organisations',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testIndexUsers(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', "sightingdb1"));
    }
}