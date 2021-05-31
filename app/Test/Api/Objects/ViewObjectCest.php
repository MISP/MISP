<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\ObjectFixture;
use \Helper\Fixture\Data\AttributeFixture;

class ViewObjectCest
{

    private const URL = '/objects/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $objectId = 1;

        $I->sendGet(sprintf(self::URL, $objectId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testView(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $objectTemplateId = 999999;
        $objectTemplateUuid = '77212413-9cdc-44fe-a788-46fb20a8235d';
        $objectId = 1;
        $fakeEvent = EventFixture::fake(
            [
                'id' => $eventId,
                'org_id' => $orgId,
                'orgc_id' => $orgId
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('object_templates', [
            'id' => $objectTemplateId,
            'user_id' => $userId,
            'org_id' => $orgId,
            'uuid' => $objectTemplateUuid,
            'name' => 'test-object-template',
            'meta-category' => 'misc',
            'description' => '',
            'version' => 1,
            'requirements' => '{"required":["test"], "requiredOneOf":[]}',
            'fixed' => true,
            'active' => true
        ]);
        $I->haveInDatabase('object_template_elements', [
            'object_template_id' => $objectTemplateId,
            'object_relation' => 'test',
            'type' => 'text',
            'ui-priority' => 0,
            'categories' => '[]',
            'sane_default' => '[]',
            'values_list' => '[]',
            'description' => 'test',
            'disable_correlation' => 1,
            'multiple' => 0,
        ]);
        $fakeAttribute = AttributeFixture::fake(
            [
                'event_id' => (string)$eventId,
                'value1' => 'test value',
                'object_relation' => 'test',
                'object_id' => $objectId
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());
        $fakeObject = ObjectFixture::fake(
            [
                'id' => (string)$objectId,
                'event_id' => (string)$eventId,
                'name' => 'test-object-template',
                'template_uuid' => $objectTemplateUuid
            ],
            [$fakeAttribute]
        );
        $I->haveInDatabase('objects', $fakeObject->toDatabase());

        $I->sendGet(sprintf(self::URL, $objectId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Object' => $fakeObject->toResponse()]);
    }
}
