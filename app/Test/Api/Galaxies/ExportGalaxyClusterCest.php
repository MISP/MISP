<?php

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\GalaxyElementFixture;

class ExportGalaxyClusterCest
{

    private const URL = '/galaxies/export/%s';

    public function testExportReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $galaxyId = 1;
        $I->sendPost(sprintf(self::URL, $galaxyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testExport(ApiTester $I)
    {
        $orgId = 1;
        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);

        $galaxyId = 1;
        $galaxyUuid = 'c51c59e9-f213-4ad4-9913-09a43d78dff5';
        $galaxyClusterId = 1;
        $galaxyClusterUuid = 'c51c59e9-f213-4ad4-9913-09a43d78dff0';
        $galaxyName = 'foobar';
        $collectionUuid = '341a6f4c-e099-3cea-bd9a-9501666e4ba9';
        $fakeGalaxy = GalaxyFixture::fake(
            [
                'id' => (string)$galaxyId,
                'uuid' => $galaxyUuid,
                'name' => $galaxyName,
            ]
        );
        $fakeGalaxyElement = GalaxyElementFixture::fake(
            [
                'galaxy_cluster_id' => (string)$galaxyClusterId,
                'key' => 'foo',
                'value' => 'bar'
            ]
        );
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'id' => $galaxyClusterId,
                'uuid' => $galaxyClusterUuid,
                'galaxy_id' => (string)$galaxyId,
                'default' => true,
                'locked' => true,
                'org_id' => (string)$orgId,
                'orgc_id' => (string)$orgId,
                'distribution' => '3',
                'collection_uuid' => $collectionUuid
            ],
            [$fakeGalaxyElement]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());
        $I->haveInDatabase('galaxy_elements', $fakeGalaxyElement->toDatabase());

        $I->sendPost(
            sprintf(self::URL, $galaxyId),
            [
                'Galaxy' => [
                    'default' => true,
                    'custom' => false,
                    'distribution' => '3',
                    'format' => 'default',
                    'download' => false
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([['GalaxyCluster' => $fakeGalaxyCluster->toExportResponse()]]);
    }

    public function testMispGalaxyFormatExport(ApiTester $I)
    {
        $orgId = 1;
        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);

        $galaxyId = 1;
        $galaxyUuid = 'c51c59e9-f213-4ad4-9913-09a43d78dff5';
        $galaxyClusterId = 1;
        $galaxyClusterUuid = 'c51c59e9-f213-4ad4-9913-09a43d78dff0';
        $galaxyName = 'foobar';
        $collectionUuid = '341a6f4c-e099-3cea-bd9a-9501666e4ba9';
        $fakeGalaxy = GalaxyFixture::fake(
            [
                'id' => (string)$galaxyId,
                'uuid' => $galaxyUuid,
                'name' => $galaxyName,
            ]
        );
        $fakeGalaxyElement = GalaxyElementFixture::fake(
            [
                'galaxy_cluster_id' => (string)$galaxyClusterId,
                'key' => 'foo',
                'value' => 'bar'
            ]
        );
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'id' => (string)$galaxyClusterId,
                'uuid' => $galaxyClusterUuid,
                'galaxy_id' => (string)$galaxyId,
                'default' => true,
                'locked' => true,
                'org_id' => (string)$orgId,
                'orgc_id' => (string)$orgId,
                'distribution' => '3',
                'collection_uuid' => $collectionUuid
            ],
            [$fakeGalaxyElement]
        );

        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());
        $I->haveInDatabase('galaxy_clusters', $fakeGalaxyCluster->toDatabase());
        $I->haveInDatabase('galaxy_elements', $fakeGalaxyElement->toDatabase());

        $I->sendPost(
            sprintf(self::URL, $galaxyId),
            [
                'Galaxy' => [
                    'default' => true,
                    'custom' => false,
                    'distribution' => '3',
                    'format' => 'misp-galaxy',
                    'download' => false
                ]
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'uuid' => $collectionUuid,
                'name' => $galaxyName,
                'values' => [
                    [
                        'uuid' => $galaxyClusterUuid,
                        'meta' => [
                            'foo' => 'bar'
                        ]
                    ]
                ]
            ]
        );
    }
}
