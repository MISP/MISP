<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;

class AttributeCorrelationCest
{
    public function testAttributeCorrelationIsAdded(ApiTester $I): void
    {
        $attributeAId = 10;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 10;
        $userId = 10;

        $I->haveAuthorizationKey($orgId, $userId);
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
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'url',
                'value1' => 'http://example.com'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttributeA->toDatabase());

        $I->sendPost(
            sprintf('/attributes/add/%s', $eventBId),
            $fakeAttributeB->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $attributeBId = $I->grabDataFromResponseByJsonPath('$..Attribute.id')[0];

        $I->seeResponseCodeIs(200);
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

    public function testCompositeAttributesValue1Correlate(ApiTester $I): void
    {
        $attributeAId = 10;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 10;
        $userId = 10;

        $I->haveAuthorizationKey($orgId, $userId);
        $fakeEventA = EventFixture::fake(['id' => $eventAId, 'org_id' => $orgId, 'user_id' => $userId]);
        $fakeEventB = EventFixture::fake(['id' => $eventBId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEventA->toDatabase());
        $I->haveInDatabase('events', $fakeEventB->toDatabase());

        $fakeAttributeA = AttributeFixture::fake(
            [
                'id' => (string)$attributeAId,
                'event_id' => (string)$eventAId,
                'category' => 'Network activity',
                'type' => 'domain|ip',
                'value1' => 'example.com',
                'value2' => '10.1.2.3'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'domain|ip',
                'value1' => 'example.com',
                'value2' => '10.1.2.4'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttributeA->toDatabase());

        $I->sendPost(
            sprintf('/attributes/add/%s', $eventBId),
            $fakeAttributeB->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $attributeBId = $I->grabDataFromResponseByJsonPath('$..Attribute.id')[0];

        $I->seeResponseCodeIs(200);
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventAId,
                'attribute_id' => $attributeAId,
                '1_event_id' => $eventBId,
                '1_attribute_id' => $attributeBId,
                'value' => 'example.com'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => 'example.com'
            ]
        );
        $I->assertEquals(2, $I->grabNumRecords('correlations'));
    }

    public function testCompositeAttributesValue2Correlate(ApiTester $I): void
    {
        $attributeAId = 10;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 10;
        $userId = 10;

        $I->haveAuthorizationKey($orgId, $userId);
        $fakeEventA = EventFixture::fake(['id' => $eventAId, 'org_id' => $orgId, 'user_id' => $userId]);
        $fakeEventB = EventFixture::fake(['id' => $eventBId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEventA->toDatabase());
        $I->haveInDatabase('events', $fakeEventB->toDatabase());

        $fakeAttributeA = AttributeFixture::fake(
            [
                'id' => (string)$attributeAId,
                'event_id' => (string)$eventAId,
                'category' => 'Network activity',
                'type' => 'domain|ip',
                'value1' => 'example1.com',
                'value2' => '10.1.2.3'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'domain|ip',
                'value1' => 'example2.com',
                'value2' => '10.1.2.3'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttributeA->toDatabase());

        $I->sendPost(
            sprintf('/attributes/add/%s', $eventBId),
            $fakeAttributeB->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $attributeBId = $I->grabDataFromResponseByJsonPath('$..Attribute.id')[0];

        $I->seeResponseCodeIs(200);
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventAId,
                'attribute_id' => $attributeAId,
                '1_event_id' => $eventBId,
                '1_attribute_id' => $attributeBId,
                'value' => '10.1.2.3'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => '10.1.2.3'
            ]
        );
        $I->assertEquals(2, $I->grabNumRecords('correlations'));
    }

    public function testSimpleValue1AndCompositeValue2AttributesCorrelate(ApiTester $I): void
    {
        $attributeAId = 10;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 10;
        $userId = 10;

        $I->haveAuthorizationKey($orgId, $userId);
        $fakeEventA = EventFixture::fake(['id' => $eventAId, 'org_id' => $orgId, 'user_id' => $userId]);
        $fakeEventB = EventFixture::fake(['id' => $eventBId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEventA->toDatabase());
        $I->haveInDatabase('events', $fakeEventB->toDatabase());

        $fakeAttributeA = AttributeFixture::fake(
            [
                'id' => (string)$attributeAId,
                'event_id' => (string)$eventAId,
                'category' => 'Network activity',
                'type' => 'ip-dst',
                'value1' => '10.1.2.3'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'domain|ip',
                'value1' => 'example.com',
                'value2' => '10.1.2.3'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttributeA->toDatabase());

        $I->sendPost(
            sprintf('/attributes/add/%s', $eventBId),
            $fakeAttributeB->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $attributeBId = $I->grabDataFromResponseByJsonPath('$..Attribute.id')[0];

        $I->seeResponseCodeIs(200);
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventAId,
                'attribute_id' => $attributeAId,
                '1_event_id' => $eventBId,
                '1_attribute_id' => $attributeBId,
                'value' => '10.1.2.3'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => '10.1.2.3'
            ]
        );
        $I->assertEquals(2, $I->grabNumRecords('correlations'));
    }

    public function testSimpleValue1AndCompositeValue1AttributesCorrelate(ApiTester $I): void
    {
        $attributeAId = 10;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 10;
        $userId = 10;

        $I->haveAuthorizationKey($orgId, $userId);
        $fakeEventA = EventFixture::fake(['id' => $eventAId, 'org_id' => $orgId, 'user_id' => $userId]);
        $fakeEventB = EventFixture::fake(['id' => $eventBId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEventA->toDatabase());
        $I->haveInDatabase('events', $fakeEventB->toDatabase());

        $fakeAttributeA = AttributeFixture::fake(
            [
                'id' => (string)$attributeAId,
                'event_id' => (string)$eventAId,
                'category' => 'Network activity',
                'type' => 'host',
                'value1' => 'example.com'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'domain|ip',
                'value1' => 'example.com',
                'value2' => '10.1.2.3'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttributeA->toDatabase());

        $I->sendPost(
            sprintf('/attributes/add/%s', $eventBId),
            $fakeAttributeB->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $attributeBId = $I->grabDataFromResponseByJsonPath('$..Attribute.id')[0];

        $I->seeResponseCodeIs(200);
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventAId,
                'attribute_id' => $attributeAId,
                '1_event_id' => $eventBId,
                '1_attribute_id' => $attributeBId,
                'value' => 'example.com'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => 'example.com'
            ]
        );
        $I->assertEquals(2, $I->grabNumRecords('correlations'));
    }

    public function testCompositeAttributesValue1AndValue2Correlate(ApiTester $I): void
    {
        $attributeAId = 10;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 10;
        $userId = 10;

        $I->haveAuthorizationKey($orgId, $userId);
        $fakeEventA = EventFixture::fake(['id' => $eventAId, 'org_id' => $orgId, 'user_id' => $userId]);
        $fakeEventB = EventFixture::fake(['id' => $eventBId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEventA->toDatabase());
        $I->haveInDatabase('events', $fakeEventB->toDatabase());

        $fakeAttributeA = AttributeFixture::fake(
            [
                'id' => (string)$attributeAId,
                'event_id' => (string)$eventAId,
                'category' => 'Network activity',
                'type' => 'domain|ip',
                'value1' => 'example.com',
                'value2' => '10.1.2.3'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'domain|ip',
                'value1' => 'example.com',
                'value2' => '10.1.2.3'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttributeA->toDatabase());

        $I->sendPost(
            sprintf('/attributes/add/%s', $eventBId),
            $fakeAttributeB->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $attributeBId = $I->grabDataFromResponseByJsonPath('$..Attribute.id')[0];

        $I->seeResponseCodeIs(200);
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventAId,
                'attribute_id' => $attributeAId,
                '1_event_id' => $eventBId,
                '1_attribute_id' => $attributeBId,
                'value' => 'example.com'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => 'example.com'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventAId,
                'attribute_id' => $attributeAId,
                '1_event_id' => $eventBId,
                '1_attribute_id' => $attributeBId,
                'value' => '10.1.2.3'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => '10.1.2.3'
            ]
        );
        $I->assertEquals(4, $I->grabNumRecords('correlations'));
    }
}
