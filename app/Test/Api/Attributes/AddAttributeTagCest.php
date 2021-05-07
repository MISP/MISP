<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\TagFixture;

class AddAttributeTagCest
{

    private const URL = '/attributes/addTag/%s/%s';

    public function testAddTagReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $eventId = 1;
        $attributeId = 1;
        $tagId = 1;

        $fakeAttribute = AttributeFixture::fake(['id' => (string)$attributeId, 'event_id' => (string)$eventId]);
        $I->sendPost(sprintf(self::URL, $attributeId, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAddTag(ApiTester $I): void
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

        $I->sendPost(sprintf(self::URL, $attributeId, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['saved' => true, 'success' => 'Tag added.']);
        $I->seeInDatabase(
            'attribute_tags',
            [
                'attribute_id' => $attributeId,
                'event_id' => $eventId,
                'tag_id' => $tagId
            ]
        );
    }
}
