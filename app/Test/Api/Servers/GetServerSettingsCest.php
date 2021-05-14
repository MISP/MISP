<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\ServerFixture;
use \Helper\Fixture\Data\OrganisationFixture;
use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \WireMock\Client\WireMock;

class GetServerSettingsCest
{

    private const URL = '/servers/serverSettings';

    public function testGetServerSettingsReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $serverId = 1;
        $technique = 'full';
        $I->sendGet(sprintf(self::URL, $serverId, $technique));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testGetServerSettings(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
    }
}
