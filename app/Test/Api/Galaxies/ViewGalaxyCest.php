<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\GalaxyElementFixture;

class ViewGalaxyCest
{

    private const URL = '/galaxies/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedGalaxy(ApiTester $I): void
    {
        $I->haveAuthorizationKey();

        $galaxyFooId = 1;
        $galaxyFooClusterId = 1;
        $fakeGalaxyFoo = GalaxyFixture::fake(['id' => $galaxyFooId, 'name' => 'foo']);

        $fakeGalaxyElementFoo = GalaxyElementFixture::fake(
            [
                'galaxy_cluster_id' => (string)$galaxyFooClusterId
            ]
        );
        $fakeGalaxyClusterFoo = GalaxyClusterFixture::fake(
            [
                'id' => $galaxyFooClusterId,
                'galaxy_id' => (string)$galaxyFooId
            ],
            [$fakeGalaxyElementFoo]
        );
        $fakeGalaxyBar = GalaxyFixture::fake(['id' => 2, 'name' => 'bar']);
        $I->haveInDatabase('galaxies', $fakeGalaxyFoo->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyClusterFoo->toDatabase());
        $I->haveInDatabase('galaxy_elements', $fakeGalaxyElementFoo->toDatabase());
        $I->haveInDatabase('galaxies', $fakeGalaxyBar->toDatabase());

        $I->sendGet(sprintf(self::URL, $galaxyFooId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'Galaxy' => $fakeGalaxyFoo->toResponse(),
                'GalaxyCluster' => [
                    $fakeGalaxyClusterFoo->toResponse()
                ]
            ]
        );
    }
}
