<?php

declare(strict_types=1);

use \Helper\Fixture\Data\NoticelistFixture;
use \Helper\Fixture\Data\UserFixture;

class ToggleEnableNoticelistCest
{

    private const URL = '/noticelists/toggleEnable';

    public function testToggleEnableReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

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

        $I->sendPost(
            self::URL,
            [
                'Noticelist' => [
                    'data' => $noticelistId
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => 'Noticelist enabled'
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

        $I->sendPost(
            self::URL,
            [
                'Noticelist' => [
                    'data' => $noticelistId
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => 'Noticelist disabled'
            ]
        );
        $I->seeInDatabase('noticelists', ['id' => $noticelistId, 'enabled' => false]);
    }
}
