<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Noticelists;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\NoticelistsFixture;
use App\Test\Fixture\NoticelistEntriesFixture;
use App\Test\Helper\ApiTestTrait;

class ViewNoticelistApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/noticelists/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Noticelists',
        'app.NoticelistEntries',
    ];

    public function testViewNoticelistById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, NoticelistsFixture::NOTICELIST_1_ID);
        $this->get($url);

        $this->assertResponseOk();
        $noticelist = $this->getJsonResponseAsArray();

        $this->assertEquals(NoticelistsFixture::NOTICELIST_1_ID, $noticelist['id']);
        $this->assertEquals(NoticelistsFixture::NOTICELIST_1_NAME, $noticelist['name']);

        $this->assertArrayHasKey('noticelist_entries', $noticelist);
        $this->assertCount(1, $noticelist['noticelist_entries']);
        $this->assertEquals(NoticelistEntriesFixture::NOTICELIST_ENTRY_1_ID, $noticelist['noticelist_entries'][0]['id']);
    }
}
