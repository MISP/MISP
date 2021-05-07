<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;

class ImportGalaxyClusterCest
{

    private const URL = '/galaxies/import';

    public function testImportReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testImport(ApiTester $I): void
    {
        $orgId = 1;
        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);

        $galaxyId = 1;
        $galaxyUuid = 'c51c59e9-f213-4ad4-9913-09a43d78dff5';
        $galaxyClusterUuid = 'c51c59e9-f213-4ad4-9913-09a43d78dff0';
        $fakeGalaxy = GalaxyFixture::fake(['id' => (string)$galaxyId, 'uuid' => $galaxyUuid]);
        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());

        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'id' => null,
                'uuid' => $galaxyClusterUuid,
                'galaxy_id' => (string)$galaxyId,
                'default' => false,
                'locked' => true,
                'org_id' => (string)$orgId,
                'orgc_id' => (string)$orgId
            ]
        );

        $I->sendPost(
            self::URL,
            [
                [
                    'GalaxyCluster' => array_merge(
                        $fakeGalaxyCluster->toRequest(),
                        [
                            'Galaxy' => [
                                'uuid' => $galaxyUuid
                            ]
                        ]
                    )
                ]
            ]
        );
        $fakeGalaxyCluster->set(
            [
                'id' => $I->grabFromDatabase('galaxy_clusters', 'id', array('uuid' => $galaxyClusterUuid)),
                'tag_name' => $I->grabFromDatabase('galaxy_clusters', 'tag_name', array('uuid' => $galaxyClusterUuid))
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Galaxy clusters imported. 1 imported, 0 ignored, 0 failed. ',
                'message' => 'Galaxy clusters imported. 1 imported, 0 ignored, 0 failed. ',
                'url' => '/galaxies/import',
            ]
        );
        $I->seeInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());
    }
}
