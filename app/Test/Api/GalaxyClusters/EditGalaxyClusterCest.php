<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\UserFixture;

class EditGalaxyClusterCest
{

    private const URL = '/galaxy_clusters/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(sprintf(self::URL, 1));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEdit(ApiTester $I): void
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
                'value' => 'foo',
                'tag_name' => 'foobar',
                'default' => false
            ]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());

        $fakeGalaxyCluster->set(['value' => 'bar']);

        $I->sendPost(sprintf(self::URL, $galaxyClusterId), $fakeGalaxyCluster->toRequest());

        $fakeGalaxyCluster->set([
            'version' => $I->grabDataFromResponseByJsonPath('$..GalaxyCluster.version')[0],
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['GalaxyCluster' => $fakeGalaxyCluster->toResponse()]);
    }
}
