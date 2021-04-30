<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\UserFixture;

class AddGalaxyClusterCest
{

    private const URL = '/galaxy_clusters/add/%s';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendPost(sprintf(self::URL, 1));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAdd(ApiTester $I)
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $galaxyId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => $galaxyId, 'type' => 'botnet']);
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'galaxy_id' => (string)$galaxyId,
                'default' => false,
                'org_id' => (string)$orgId,
                'orgc_id' => (string)$orgId,
                'type' => 'botnet',
                'extends_uuid' => null,
                'extends_version' => null,
            ]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());

        $I->sendPost(sprintf(self::URL, $galaxyId), $fakeGalaxyCluster->toRequest());
        $fakeGalaxyCluster->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..GalaxyCluster.id')[0],
            'tag_name' => $I->grabDataFromResponseByJsonPath('$..GalaxyCluster.tag_name')[0],
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['GalaxyCluster' => $fakeGalaxyCluster->toResponse()]);
    }
}
