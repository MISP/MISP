<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\UserFixture;

class UnpublishGalaxyClusterCest
{

    private const URL = '/galaxy_clusters/unpublish/%s';

    public function testUnpublishReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(sprintf(self::URL, 1));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testUnpublish(ApiTester $I): void
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
                'default' => false,
                'published' => true
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
            'name' => 'GalaxyCluster unpublished',
            'message' => 'GalaxyCluster unpublished',
            'url' => sprintf(self::URL, $galaxyClusterId),
        ]);
        $I->seeInDatabase('galaxy_clusters', ['id' => $galaxyClusterId, 'published' => false]);
    }
}
