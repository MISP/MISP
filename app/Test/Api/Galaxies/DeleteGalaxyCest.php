<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\UserFixture;

class DeleteGalaxyCest
{

    private const URL = '/galaxies/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendDelete(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDelete(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $galaxyId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => (string)$galaxyId]);

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());

        $I->sendDelete(sprintf(self::URL, $galaxyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Galaxy deleted',
                'message' => 'Galaxy deleted',
                'url' => '/galaxies/delete',
            ]
        );
        $I->cantSeeInDatabase('galaxies', ['id' => $galaxyId]);
    }
}
