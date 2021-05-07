<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;

class IndexGalaxyClustersCest
{

    private const URL = '/galaxy_clusters/index/%s';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(sprintf(self::URL, 1));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testPostIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(sprintf(self::URL, 1));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedGalaxyCluster(ApiTester $I): void
    {
        $I->haveAuthorizationKey();

        $galaxyId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => $galaxyId]);
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'galaxy_id' => (string)$galaxyId,
                'tag_name' => 'foobar'
            ]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());

        $I->sendGet(sprintf(self::URL, $galaxyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([['GalaxyCluster' => $fakeGalaxyCluster->toResponse()]]);
    }

    public function testPostIndexReturnsExpectedGalaxyCluster(ApiTester $I): void
    {
        $I->haveAuthorizationKey();

        $galaxyId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => $galaxyId]);
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'galaxy_id' => (string)$galaxyId,
                'value' => 'foobar',
                'tag_name' => 'foobar'
            ]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());

        $I->sendPost(
            sprintf(self::URL, $galaxyId),
            [
                'context' => 'all',
                'searchall' => 'foobar'
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([['GalaxyCluster' => $fakeGalaxyCluster->toResponse()]]);
    }
}
