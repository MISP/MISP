<?php

use \Helper\Fixture\AttributeFixture;

class ViewAttributesCest
{

    private const URL = '/attributes/view/%d';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $attributeId = 10;
        $I->sendGet(sprintf(self::URL, $attributeId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedAttribute(ApiTester $I)
    {
        $I->haveAdminAuthorizationKey();

        $attributeId = 10;
        $fakeAttribute = AttributeFixture::fake(['id' => $attributeId]);
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->sendGet(sprintf(self::URL, $attributeId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson($fakeAttribute->toResponse());
    }
}
