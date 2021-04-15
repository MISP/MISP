<?php

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class GetAttributeStatisticsCest
{

    private const URL = '/attributes/attributeStatistics/%s/%s';

    public function testGetAttributeStatisticsReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendGet(sprintf(self::URL, 'type', '0'));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testGetAttributeStatisticsReturnsExpectedCount(ApiTester $I)
    {
        $eventId = 1;

        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);
        $fakeEvent = EventFixture::fake(['id' => $eventId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeAttribute1 = AttributeFixture::fake(['event_id' => $eventId, 'type' => 'attachment']);
        $fakeAttribute2 = AttributeFixture::fake(['event_id' => $eventId, 'type' => 'ip-src']);
        $I->haveInDatabase('attributes', $fakeAttribute1->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute2->toDatabase());

        $I->sendGet(sprintf(self::URL, 'type', '0'));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['attachment' => 1, 'ip-src' => 1]);
    }

    public function testGetAttributeStatisticsReturnsExpectedPercentage(ApiTester $I)
    {
        $eventId = 1;

        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);
        $fakeEvent = EventFixture::fake(['id' => $eventId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeAttribute1 = AttributeFixture::fake(['event_id' => $eventId, 'type' => 'attachment']);
        $fakeAttribute2 = AttributeFixture::fake(['event_id' => $eventId, 'type' => 'ip-src']);
        $I->haveInDatabase('attributes', $fakeAttribute1->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute2->toDatabase());

        $I->sendGet(sprintf(self::URL, 'type', '1'));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['attachment' => '50%', 'ip-src' => '50%']);
    }
}
