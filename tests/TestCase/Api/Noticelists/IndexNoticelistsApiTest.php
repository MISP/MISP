<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Noticelists;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\NoticelistsFixture;
use App\Test\Helper\ApiTestTrait;

class IndexNoticelistsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/noticelists/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Noticelists',
        'app.NoticelistEntries',
    ];

    public function testIndexNoticelists(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', NoticelistsFixture::NOTICELIST_1_NAME));
    }
}
