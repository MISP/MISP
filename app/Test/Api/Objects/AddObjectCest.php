<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\EventFixture;

class IndexObjectsCest
{

    private const URL = '/objects/add/%s/%s';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $eventId = 1;
        $objectTemplateId = 1;

        $I->sendPost(sprintf(self::URL, $eventId, $objectTemplateId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAdd(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $objectTemplateId = 999999;
        $objectTemplateUuid = '77212413-9cdc-44fe-a788-46fb20a8235d';
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
            'description' => 'foobar',
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

        $I->sendPost(
            sprintf(self::URL, $eventId, $objectTemplateId),
            [
                'Attribute' => [
                    [
                        'value' => 'test value',
                        'type' => 'text',
                        'object_relation' => 'test',
                    ]
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'Object' => [
                    'Attribute' => [
                        'value1' => 'test value',
                        'type' => 'text',
                    ]
                ]
            ]
        );
        $I->seeInDatabase(
            'objects',
            [
                'event_id' => $eventId,
                'name' => 'test-object-template',
                'template_uuid' => $objectTemplateUuid
            ]
        );
        $I->seeInDatabase(
            'attributes',
            [
                'event_id' => $eventId,
                'value1' => 'test value',
                'object_relation' => 'test'
            ]
        );
    }
}
