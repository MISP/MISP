<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class DescribeAttributeTypesCest
{

    private const URL = '/attributes/describeTypes';

    public function testDescribeAttributeTypesReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDescribeAttributeTypes(ApiTester $I): void
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
    }
}
