<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SightingFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\AttributeFixture;

class DeleSightingCest
{

    private const URL = '/sightings/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $sightingId = 1;
        $I->sendPost(sprintf(self::URL, $sightingId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedSighting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $attributeId = 1;
        $sightingId = 1;
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
                'id' => $sightingId,
                'event_id' => $eventId,
                'attribute_id' => $attributeId,
                'org_id' => $orgId
            ]
        );
        $I->haveInDatabase('sightings', $fakeSighting->toDatabase());

        $I->sendPost(sprintf(self::URL, $sightingId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Sighting successfully deleted.',
                'message' => 'Sighting successfully deleted.',
                'url' => sprintf(self::URL, $sightingId),
            ]
        );
        $I->cantSeeInDatabase('sightings', ['id' => $sightingId]);
    }
}
