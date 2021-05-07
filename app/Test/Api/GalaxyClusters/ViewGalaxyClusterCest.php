<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\GalaxyElementFixture;

class ViewGalaxyClusterCest
{

    private const URL = '/galaxy_clusters/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(sprintf(self::URL, 1));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedGalaxyCluster(ApiTester $I): void
    {
        $I->haveAuthorizationKey();

        $galaxyId = 1;
        $galaxyClusterId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => $galaxyId]);
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'id' => $galaxyClusterId,
                'galaxy_id' => (string)$galaxyId,
                'tag_name' => 'foobar'
            ]
        );
        $fakeGalaxyElement = GalaxyElementFixture::fake(
            [
                'galaxy_cluster_id' => (string)$galaxyClusterId
            ]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());
        $I->haveInDatabase('galaxy_elements', $fakeGalaxyElement->toDatabase());

        $I->sendGet(sprintf(self::URL, $galaxyClusterId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['GalaxyCluster' => $fakeGalaxyCluster->toResponse()]);
    }
}
