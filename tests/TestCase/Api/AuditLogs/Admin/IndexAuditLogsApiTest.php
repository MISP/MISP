<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuditLogs;

use App\Test\Fixture\AuditLogsFixture;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexAuditLogsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/auditLogs/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.AuditLogs',
    ];

    public function testIndexAuditLogs(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', AuditLogsFixture::AUDIT_LOG_1_ID));
    }
}
