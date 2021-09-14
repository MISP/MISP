<?php

declare(strict_types=1);

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\AttributeFixture;

class AddSightingsByValueCest
{

    private const URL = '/sightings/add?XDEBUG_SESSION_START';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $attributeId = 1;
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAddReturnsExpectedSighting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $attribute1Id = 1;
        $attribute2Id = 2;
        $fakeEvent = EventFixture::fake(
            [
                'id' => $eventId,
                'org_id' => $orgId,
                'orgc_id' => $orgId
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $fakeAttribute1 = AttributeFixture::fake(
            [
                'id' => $attribute1Id,
                'event_id' => (string)$eventId,
                'value1' => 'test value',
                'to_ids' => true
            ]
        );
        $fakeAttribute2 = AttributeFixture::fake(
            [
                'id' => $attribute2Id,
                'event_id' => (string)$eventId,
                'value1' => 'test value',
                'to_ids' => false
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttribute1->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute2->toDatabase());

        $I->sendPost(
            self::URL,
            [
                'values' => ["test value"],
                'filters' => [
                    'to_ids' => true,
                    'eventid' => (string)$eventId
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Sighting' => [
            'attribute_id' => $attribute1Id,
            'event_id' => $eventId,
        ]]);
        $I->seeInDatabase('sightings', [
            'attribute_id' => $attribute1Id,
            'event_id' => $eventId
        ]);
    }
}
