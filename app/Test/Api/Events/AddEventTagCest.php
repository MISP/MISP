<?php

declare(strict_types=1);

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\TagFixture;

class AddEventTagCest
{

    private const URL = '/events/addTag/%s/%s';

    public function testAddTagReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $eventId = 1;
        $tagId = 1;
        $I->sendPost(sprintf(self::URL, $eventId, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAddTag(ApiTester $I)
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

        $I->sendPost(sprintf(self::URL, $eventId, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['saved' => true, 'success' => 'Tag added.']);
        $I->seeInDatabase(
            'event_tags',
            [
                'event_id' => $eventId,
                'tag_id' => $tagId
            ]
        );
    }
}
