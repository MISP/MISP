<?php

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class RestSearchEventsCest
{

    private const URL = '/events/restSearch?returnFormat=json';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testRestSearchReturnsExpectedAttribute(ApiTester $I)
    {
        $orgId = 1;
        $userId = 1;

        $I->haveAuthorizationKey($orgId, $userId);

        $fakeEventFoo = EventFixture::fake(
            [
                'org_id' => $orgId,
                'orgc_id' => $orgId,
                'info' => 'foo'
            ]
        );
        $fakeEventBar = EventFixture::fake(
            [
                'org_id' => $orgId,
                'orgc_id' => $orgId,
                'info' => 'bar'
            ]
        );
        $I->haveInDatabase('events', $fakeEventFoo->toDatabase());
        $I->haveInDatabase('events', $fakeEventBar->toDatabase());

        // TODO: add a more complex search e.g. use tags, timestamps/dates
        $I->sendPost(self::URL, [
            'page' => 1,
            'limit' => 1,
            'eventinfo' => 'foo'
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'response' => [
                    [
                        'Event' => $fakeEventFoo->toResponse()
                    ]
                ]
            ]
        );
    }
}
