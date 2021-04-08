<?php

use \Helper\Fixture\AttributeFixture;

class IndexAttributesCest
{

    private const URL = '/attributes';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedAttribute(ApiTester $I)
    {
        $I->haveAdminAuthorizationKey();

        $fakeAttribute = AttributeFixture::fake();
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson($fakeAttribute->toResponse());
    }
}
