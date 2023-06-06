<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Noticelists;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\NoticelistsFixture;
use App\Test\Helper\ApiTestTrait;

class ToggleEnableNoticelistApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/noticelists/toggleEnable';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Noticelists',
        'app.NoticelistEntries',
    ];

    public function testToggleEnableNoticelist(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, NoticelistsFixture::NOTICELIST_1_ID);

        # enable
        $this->assertDbRecordExists('Noticelists', ['id' => NoticelistsFixture::NOTICELIST_1_ID, 'enabled' => false]);
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Noticelist enabled."');
        $this->assertDbRecordExists('Noticelists', ['id' => NoticelistsFixture::NOTICELIST_1_ID, 'enabled' => true]);
    }

    public function testToggleDisableNoticelist(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, NoticelistsFixture::NOTICELIST_2_ID);

        $this->assertDbRecordExists('Noticelists', ['id' => NoticelistsFixture::NOTICELIST_2_ID, 'enabled' => true]);
        $this->post($url);
        $this->assertResponseOk();
        $this->assertResponseContains('"message": "Noticelist disabled."');
        $this->assertDbRecordExists('Noticelists', ['id' => NoticelistsFixture::NOTICELIST_2_ID, 'enabled' => false]);
    }
}
