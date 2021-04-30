<?php

declare(strict_types=1);

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\TagFixture;

class RemoveEventTagCest
{

    private const URL = '/events/removeTag/%s/%s';

    public function testRemoveTagReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $eventId = 1;
        $tagId = 1;
        $I->sendPost(sprintf(self::URL, $eventId, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testRemoveTag(ApiTester $I)
    {
        $orgId = 1;
        $eventId = 1;
        $tagId = 1;

        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);
        $fakeEvent = EventFixture::fake(
            [
                'id' => (string)$eventId,
                'org_id' => (string)$orgId,
                'orgc_id' => (string)$orgId
            ]
        );
        $fakeTag = TagFixture::fake(['id' => (string)$tagId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('tags', $fakeTag->toDatabase());
        $I->haveInDatabase(
            'event_tags',
            [
                'event_id' => $eventId,
                'tag_id' => $tagId
            ]
        );

        $I->sendPost(sprintf(self::URL, $eventId, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['saved' => true, 'success' => 'Tag removed.']);
        $I->cantSeeInDatabase(
            'event_tags',
            [
                'event_id' => $eventId,
                'tag_id' => $tagId
            ]
        );
    }
}
