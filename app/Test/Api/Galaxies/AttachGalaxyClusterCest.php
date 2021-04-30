<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\TagFixture;
use \Helper\Fixture\Data\AttributeFixture;

class AttachGalaxyClusterCest
{

    private const URL = '/galaxies/attachCluster/%s/%s';

    public function testAttachClusterReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendPost(sprintf(self::URL, 1, 'event'));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAttachGalaxyClusterToEvent(ApiTester $I)
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $galaxyId = 1;
        $tagId = 1;
        $tagName = 'foobar';
        $galaxyClusterId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => $galaxyId]);
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'id' => $galaxyClusterId,
                'galaxy_id' => (string)$galaxyId,
                'tag_name' => $tagName
            ]
        );
        $fakeTag = TagFixture::fake(['id' => (string)$tagId, 'name' => $tagName]);
        $fakeEvent = EventFixture::fake(['id' => $eventId]);

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());
        $I->haveInDatabase('tags', $fakeTag->toDatabase());
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $I->sendPost(
            sprintf(self::URL, $eventId, 'event'),
            [
                'Galaxy' => [
                    'target_id' => $galaxyClusterId
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => 'Cluster attached.',
                'check_publish' => true
            ]
        );
        $I->seeInDatabase(
            'event_tags',
            [
                'event_id' => $eventId,
                'tag_id' => $tagId
            ]
        );
    }

    public function testAttachGalaxyClusterToAttribute(ApiTester $I)
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $attributeId = 1;
        $eventId = 1;
        $galaxyId = 1;
        $tagId = 1;
        $tagName = 'foobar';
        $galaxyClusterId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => $galaxyId]);
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'id' => $galaxyClusterId,
                'galaxy_id' => (string)$galaxyId,
                'tag_name' => $tagName
            ]
        );
        $fakeTag = TagFixture::fake(['id' => (string)$tagId, 'name' => $tagName]);
        $fakeEvent = EventFixture::fake(['id' => (string)$eventId]);
        $fakeAttribute = AttributeFixture::fake(
            [
                'id' => (string)$attributeId,
                'event_id' => (string)$eventId,
                'type' => 'text',
                'timestamp' => '0'
            ]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());
        $I->haveInDatabase('tags', $fakeTag->toDatabase());
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->sendPost(
            sprintf(self::URL, $eventId, 'attribute'),
            [
                'Galaxy' => [
                    'target_id' => $galaxyClusterId
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => 'Cluster attached.',
                'check_publish' => true
            ]
        );
        $I->seeInDatabase(
            'attribute_tags',
            [
                'attribute_id' => $eventId,
                'tag_id' => $tagId
            ]
        );
    }

    public function testAttachGalaxyClusterToTagCollection(ApiTester $I, $scenario)
    {
        $scenario->skip('TODO: missing TagCollectionFixture');
    }
}
