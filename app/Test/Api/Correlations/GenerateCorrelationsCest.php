<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class GenerateCorrelationsCest
{
    public function testSimpleAttributeCorrelationIsAdded(ApiTester $I): void
    {
        $attributeAId = 10;
        $attributeBId = 20;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 1;
        $userId = 1;

        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '0');

        $fakeEventA = EventFixture::fake(['id' => $eventAId, 'org_id' => $orgId, 'user_id' => $userId]);
        $fakeEventB = EventFixture::fake(['id' => $eventBId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEventA->toDatabase());
        $I->haveInDatabase('events', $fakeEventB->toDatabase());

        $fakeAttributeA = AttributeFixture::fake(
            [
                'id' => (string)$attributeAId,
                'event_id' => (string)$eventAId,
                'category' => 'Network activity',
                'type' => 'url',
                'value1' => 'http://example.com'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'id' => (string)$attributeBId,
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'url',
                'value1' => 'http://example.com'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttributeA->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttributeB->toDatabase());

        $I->sendPost(sprintf('/attributes/generateCorrelation'));

        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventAId,
                'attribute_id' => $attributeAId,
                '1_event_id' => $eventBId,
                '1_attribute_id' => $attributeBId,
                'value' => 'http://example.com'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => 'http://example.com'
            ]
        );
        $I->assertEquals(2, $I->grabNumRecords('correlations'));
    }
}
