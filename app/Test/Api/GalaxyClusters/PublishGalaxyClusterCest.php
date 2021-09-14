<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;
use \Helper\Fixture\Data\GalaxyClusterFixture;
use \Helper\Fixture\Data\UserFixture;

class PublishGalaxyClusterCest
{

    private const URL = '/galaxy_clusters/publish/%s';

    public function testPublishReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(sprintf(self::URL, 1));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testPublish(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '0');

        $galaxyId = 1;
        $galaxyClusterId = 1;
        $fakeGalaxy = GalaxyFixture::fake(['id' => $galaxyId]);
        $fakeGalaxyCluster = GalaxyClusterFixture::fake(
            [
                'id' => (string)$galaxyClusterId,
                'galaxy_id' => (string)$galaxyId,
                'default' => false,
                'published' => false
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
            'name' => 'GalaxyCluster published',
            'message' => 'GalaxyCluster published',
            'url' => '/galaxy_clusters/publish/1'
        ]);
    }
}
