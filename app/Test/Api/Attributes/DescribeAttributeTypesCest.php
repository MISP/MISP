<?php

use \Helper\Fixture\Data\UserFixture;

class DescribeAttributeTypesCest
{

    private const URL = '/attributes/describeTypes';

    public function testDescribeAttributeTypesReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDescribeAttributeTypes(ApiTester $I)
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
    }
}
