<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AccessLogs;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\AccessLogsFixture;
use App\Test\Helper\ApiTestTrait;

class IndexAccessLogsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/accessLogs/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.AccessLogs',
    ];

    public function testIndexAccessLogs(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', AccessLogsFixture::ACCESS_LOG_1_ID));
    }
}
