<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Codeception\Scenario;

class AttributeCorrelationCest
{
    public function testSimpleAttributeCorrelationIsAdded(ApiTester $I): void
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

    public function testSimpleAttributeValue1AndCompositeAttributeValue2Correlate(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Correlation not yet supported.');

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

    public function testSimpleAttributeValue1AndCompositeAttributeValue1Correlate(ApiTester $I): void
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

    public function testCompositeAttributeValue1AndCompositeAttributeValue2Correlate(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Correlation not yet supported.');
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
                'category' => 'Payload delivery',
                'type' => 'filename|sha256',
                'value1' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'value2' => '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Payload delivery',
                'type' => 'filename|sha256',
                'value1' => 'foo.txt',
                'value2' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
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
                'value' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            ]
        );
        $I->assertEquals(2, $I->grabNumRecords('correlations'));
    }

    public function testCompositeAttributeValue2AndCompositeAttributeValue1Correlate(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Correlation not yet supported.');
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
                'category' => 'Payload delivery',
                'type' => 'filename|sha256',
                'value1' => '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
                'value2' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Payload delivery',
                'type' => 'filename|sha256',
                'value1' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'value2' => 'fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9'
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
                'value' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
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

    public function testSimpleCIDRAttributeAndSimpleIPAttributeCorrelate(ApiTester $I): void
    {
        $attributeAId = 10;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 10;
        $userId = 10;

        $I->haveMispSetting('MISP.enable_advanced_correlations', '1');
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
                'value1' => '8.8.8.8'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'ip-dst',
                'value1' => '8.8.8.0/24'
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
                'value' => '8.8.8.8'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => '8.8.8.0/24'
            ]
        );
        $I->assertEquals(2, $I->grabNumRecords('correlations'));
    }

    public function testCompositeAttributeValue2AndSimpleAttributeValue1CidrCorrelate(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Correlation not yet supported');
        $attributeAId = 10;
        $eventAId = 1;
        $eventBId = 2;
        $orgId = 10;
        $userId = 10;

        $I->haveMispSetting('MISP.enable_advanced_correlations', '1');
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
                'value2' => '8.8.8.8'
            ]
        );
        $fakeAttributeB = AttributeFixture::fake(
            [
                'event_id' => (string)$eventBId,
                'category' => 'Network activity',
                'type' => 'ip-dst',
                'value1' => '8.8.8.0/24'
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
                'value' => '8.8.8.8'
            ]
        );
        $I->seeInDatabase(
            'correlations',
            [
                'event_id' => $eventBId,
                'attribute_id' => $attributeBId,
                '1_event_id' => $eventAId,
                '1_attribute_id' => $attributeAId,
                'value' => '8.8.8.0/24'
            ]
        );
        $I->assertEquals(2, $I->grabNumRecords('correlations'));
    }
}
