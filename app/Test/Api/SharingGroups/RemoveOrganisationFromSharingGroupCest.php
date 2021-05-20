<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SharingGroupFixture;
use \Helper\Fixture\Data\UserFixture;

class RemoveOrganisationFromSharingGroupCest
{

    private const URL = '/sharing_groups/removeOrg/%s/%s';

    public function testRemoveOrganisationFromSharingGroupReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $sharingGroupId = 1;
        $orgId = 1;
        $I->sendPost(sprintf(self::URL, $sharingGroupId, $orgId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testRemoveOrganisationFromSharingGroup(ApiTester $I): void
    {
        $orgId = 1;
        $sharingGroupId = 1;
        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);

        $sharingGroupId = 1;
        $fakeSharingGroup = SharingGroupFixture::fake(
            [
                'id' => (string)$sharingGroupId,
                'org_id' => (string)$orgId
            ]
        );
        $I->haveInDatabase('sharing_groups', $fakeSharingGroup->toDatabase());
        $I->haveInDatabase(
            'sharing_group_orgs',
            [
                'sharing_group_id' => $sharingGroupId,
                'org_id' => $orgId
            ]
        );

        $I->sendPost(sprintf(self::URL, $sharingGroupId, $orgId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Organisation removed from the sharing group.',
                'message' => 'Organisation removed from the sharing group.',
                'url' => '/sharing_groups/removeOrg'
            ]
        );
        $I->cantSeeInDatabase(
            'sharing_group_orgs',
            [
                'sharing_group_id' => $sharingGroupId,
                'org_id' => $orgId
            ]
        );
    }
}
