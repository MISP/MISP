<?php

declare(strict_types=1);

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class IndexEventsCest
{

    private const URL = '/events';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedEvent(ApiTester $I)
    {
        $orgId = 1;

        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);
        $fakeEvent = EventFixture::fake(['org_id' => $orgId, 'orgc_id' => $orgId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([$fakeEvent->toResponse()]);
    }
}
