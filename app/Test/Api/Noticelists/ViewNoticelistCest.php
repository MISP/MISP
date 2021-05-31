<?php

declare(strict_types=1);

use \Helper\Fixture\Data\NoticelistFixture;
use \Helper\Fixture\Data\UserFixture;

class ViewNoticelistCest
{

    private const URL = '/noticelists/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $noticelistId = 1;
        $I->sendGet(sprintf(self::URL, $noticelistId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedNoticelist(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $noticelistId = 1;
        $fakeNoticelist = NoticelistFixture::fake(['id' => $noticelistId]);
        $I->haveInDatabase('noticelists', $fakeNoticelist->toDatabase());

        $I->sendGet(sprintf(self::URL, $noticelistId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Noticelist' => $fakeNoticelist->toResponse()]);
    }
}
