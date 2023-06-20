<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Noticelists;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class UpdateNoticelistsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/noticelists/update';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Noticelists',
        'app.NoticelistEntries',
    ];

    public function testUpdateNoticelists(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->post(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertDbRecordExists('Noticelists', ['name' => 'gdpr']);
    }
}
