<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\UserFixture;

class DeleteGalaxyClusterCest
{

    private const URL = '/galaxy_clusters/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(sprintf(self::URL, 1));

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
        $galaxyClusterId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => $galaxyId]);
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'id' => (string)$galaxyClusterId,
                'galaxy_id' => (string)$galaxyId,
                'deleted' => false,
            ]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());

        $I->sendPost(sprintf(self::URL, $galaxyClusterId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([
            'saved' => true,
            'success' => true,
            'name' => 'Galaxy cluster successfuly soft deleted.',
            'message' => 'Galaxy cluster successfuly soft deleted.',
            'url' => sprintf(self::URL, $galaxyClusterId),
        ]);
        $I->seeInDatabase('galaxy_clusters', ['id' => $galaxyClusterId, 'deleted' => true]);
    }
}
