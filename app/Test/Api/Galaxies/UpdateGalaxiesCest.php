<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Codeception\Scenario;

class UpdateGalaxyCest
{

    private const URL = '/galaxies/update';

    public function testUpdateReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testUpdate(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Fix timeout problems.');
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Galaxies updated.',
                'message' => 'Galaxies updated.',
                'url' => '/galaxies/update',
            ]
        );
    }
}
