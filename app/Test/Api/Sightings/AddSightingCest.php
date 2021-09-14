<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SightingFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\AttributeFixture;

class AddSightingCest
{

    private const URL = '/sightings/add/%s';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $attributeId = 1;
        $I->sendPost(sprintf(self::URL, $attributeId));

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
        $attributeId = 1;
        $fakeEvent = EventFixture::fake(
            [
                'id' => $eventId,
                'org_id' => $orgId,
                'orgc_id' => $orgId
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $fakeAttribute = AttributeFixture::fake(
            [
                'id' => $attributeId,
                'event_id' => (string)$eventId,
                'value1' => 'test value'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());
        $fakeSighting = SightingFixture::fake(
            [
                'event_id' => $eventId,
                'attribute_id' => $attributeId,
                'org_id' => $orgId
            ]
        );

        $I->sendPost(sprintf(self::URL, $attributeId), $fakeSighting->toRequest());

        $fakeSighting->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..Sighting.id')[0],
            'uuid' => $I->grabDataFromResponseByJsonPath('$..Sighting.uuid')[0],
            'date_sighting' => $I->grabDataFromResponseByJsonPath('$..Sighting.date_sighting')[0],
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Sighting' => $fakeSighting->toResponse()]);
        $I->seeInDatabase('sightings', $fakeSighting->toDatabase());
    }
}
