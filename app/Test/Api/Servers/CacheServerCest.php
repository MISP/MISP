<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class CacheServerCest
{

    private const URL = '/servers/cache';

    public function testCacheReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testCache(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '0');

        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Caching the servers has successfully completed.',
                'message' => 'Caching the servers has successfully completed.',
                'url' => self::URL
            ]
        );
    }
}
