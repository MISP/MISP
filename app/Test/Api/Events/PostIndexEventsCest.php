<?php

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class PostIndexEventsCest
{

    private const URL = '/events/index';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedEvent(ApiTester $I)
    {
        $orgId = 1;

        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);
        $fakeEvent1 = EventFixture::fake(['org_id' => $orgId, 'orgc_id' => $orgId, 'timestamp' => 10]);
        $fakeEvent2 = EventFixture::fake(['org_id' => $orgId, 'orgc_id' => $orgId, 'timestamp' => 20]);
        $I->haveInDatabase('events', $fakeEvent1->toDatabase());
        $I->haveInDatabase('events', $fakeEvent2->toDatabase());

        $I->sendPost(
            self::URL,
            [
                'page' => 1,
                'limit' => 1,
                'sort' => 'timestamp',
                'direction' => 'asc'
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([$fakeEvent1->toResponse()]);
    }

    public function testIndexMinimalReturnsExpectedEvent(ApiTester $I)
    {
        $orgId = 1;

        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);
        $fakeEvent1 = EventFixture::fake(
            [
                'org_id' => $orgId,
                'orgc_id' => $orgId,
                'timestamp' => 10,
                'attribute_count' => 1
            ]
        );
        $fakeEvent2 = EventFixture::fake(
            [
                'org_id' => $orgId,
                'orgc_id' => $orgId,
                'timestamp' => 20,
                'attribute_count' => 1,
            ]
        );
        $I->haveInDatabase('events', $fakeEvent1->toDatabase());
        $I->haveInDatabase('events', $fakeEvent2->toDatabase());

        $I->sendPost(
            self::URL,
            [
                'page' => 1,
                'limit' => 1,
                'sort' => 'timestamp',
                'direction' => 'desc',
                'minimal' => true
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([$fakeEvent2->toMinimalResponse()]);
    }
}
