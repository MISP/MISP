<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\TagFixture;

class RemoveAttributeTagCest
{

    private const URL = '/attributes/removeTag/%s/%s';

    public function testRemoveTagReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $attributeId = 1;
        $tagId = 1;

        $I->sendPost(sprintf(self::URL, $attributeId, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testRemoveTag(ApiTester $I)
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $attributeId = 1;
        $tagId = 1;
        $fakeEvent = EventFixture::fake(['id' => (string)$eventId]);
        $fakeTag = TagFixture::fake(['id' => (string)$tagId]);
        $fakeAttribute = AttributeFixture::fake(
            [
                'id' => (string)$attributeId,
                'event_id' => (string)$eventId
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());
        $I->haveInDatabase('tags', $fakeTag->toDatabase());
        $I->haveInDatabase('attribute_tags', [
            'attribute_id' => $attributeId,
            'event_id' => $eventId,
            'tag_id' => $tagId,
        ]);

        $I->sendPost(sprintf(self::URL, $attributeId, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['saved' => true, 'success' => 'Tag removed.']);
        $I->cantSeeInDatabase(
            'attribute_tags',
            [
                'attribute_id' => $attributeId,
                'event_id' => $eventId,
                'tag_id' => $tagId
            ]
        );
    }
}
