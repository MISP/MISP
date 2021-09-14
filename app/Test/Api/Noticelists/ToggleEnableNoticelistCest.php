<?php

declare(strict_types=1);

use \Helper\Fixture\Data\NoticelistFixture;
use \Helper\Fixture\Data\UserFixture;

class ToggleEnableNoticelistCest
{

    private const URL = '/noticelists/toggleEnable/%s';

    public function testToggleEnableReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $noticelistId = 1;
        $I->sendPost(sprintf(self::URL, $noticelistId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testToggleEnable(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $noticelistId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeNoticelist = NoticelistFixture::fake(
            [
                'id' => $noticelistId,
                'enabled' => false
            ]
        );
        $I->haveInDatabase('noticelists', $fakeNoticelist->toDatabase());

        $I->sendPost(sprintf(self::URL, $noticelistId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'message' => 'Noticelist enabled.'
            ]
        );
        $I->seeInDatabase('noticelists', ['id' => $noticelistId, 'enabled' => true]);
    }

    public function testToggleEnableDisable(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $noticelistId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeNoticelist = NoticelistFixture::fake(
            [
                'id' => $noticelistId,
                'enabled' => true
            ]
        );
        $I->haveInDatabase('noticelists', $fakeNoticelist->toDatabase());

        $I->sendPost(sprintf(self::URL, $noticelistId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'message' => 'Noticelist disabled.'
            ]
        );
        $I->seeInDatabase('noticelists', ['id' => $noticelistId, 'enabled' => false]);
    }
}
