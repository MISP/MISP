<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Allowedlists\Admin;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use App\Test\Fixture\SightingdbsFixture;

class DeleteSightingdbApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sightingdbs/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Sightingdbs'
    ];

    public function testAdminDeleteAllowedlistById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, SightingdbsFixture::SDB_1_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Sightingdbs', ['id' => SightingdbsFixture::SDB_1_ID]);
    }
}
