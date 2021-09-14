<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class UpdateNoticelistsCest
{

    private const URL = '/noticelists/update';

    public function testUpdateReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testUpdate(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'url' => "/noticelists/update"
            ]
        );
        $I->seeResponseMatchesJsonType([
            'message' => 'string:regex(/^Successfully updated \d+ noticelists.$/)'
        ]);
    }
}
