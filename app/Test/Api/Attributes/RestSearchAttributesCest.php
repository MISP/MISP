<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;

class RestSearchAttributesCest
{

    private const URL = '/attributes/restSearch?returnFormat=json';

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
        $eventId = 1;
        $orgId = 1;
        $userId = 1;

        $I->haveAuthorizationKey($orgId, $userId);

        $fakeEvent = EventFixture::fake([
            'id' => $eventId,
            'org_id' => $orgId,
            'user_id' => $userId,
        ]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeAttributeFoo = AttributeFixture::fake([
            'event_id' => $eventId,
            'value1' => 'foo'
        ]);
        $fakeAttributeBar = AttributeFixture::fake(['event_id' => $eventId, 'value1' => 'bar']);
        $I->haveInDatabase('attributes', $fakeAttributeFoo->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttributeBar->toDatabase());

        // TODO: add a more complex search e.g. use tags, timestamps/dates
        $I->sendPost(self::URL, [
            'page' => 1,
            'limit' => 1,
            'value' => 'foo'
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['response' => ['Attribute' => $fakeAttributeFoo->toResponse()]]);
    }
}
