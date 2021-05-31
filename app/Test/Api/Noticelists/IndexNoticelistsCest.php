<?php

declare(strict_types=1);

use \Helper\Fixture\Data\NoticelistFixture;
use \Helper\Fixture\Data\UserFixture;

class IndexNoticelistsCest
{

    private const URL = '/noticelists';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedNoticelist(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeNoticelist = NoticelistFixture::fake();
        $I->haveInDatabase('noticelists', $fakeNoticelist->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                [
                    'Noticelist' => $fakeNoticelist->toResponse()
                ]
            ]
        );
    }
}
