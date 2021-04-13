<?php

use Helper\Fixture\Data\AuthKeyFixture;
use Helper\Fixture\Data\OrganisationFixture;
use Helper\Fixture\Data\UserFixture;

/**
 * Inherited Methods
 * @method void wantToTest($text)
 * @method void wantTo($text)
 * @method void execute($callable)
 * @method void expectTo($prediction)
 * @method void expect($prediction)
 * @method void amGoingTo($argumentation)
 * @method void am($role)
 * @method void lookForwardTo($achieveValue)
 * @method void comment($description)
 * @method void pause()
 *
 * @SuppressWarnings(PHPMD)
 */
class ApiTester extends \Codeception\Actor
{
    use _generated\ApiTesterActions;

    public function _beforeSuite($settings = array())
    {
        $this->haveMispSetting('Security.advanced_authkeys', '1');
        $this->haveMispSetting('MISP.live', '1');
    }

    /**
     * Define custom actions here
     */

    public function haveAuthorizationKey(
        int $orgId = 1,
        int $userId = 1,
        int $roleId = UserFixture::ROLE_USER,
        string $authkey_plain = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ) {
        $fakeOrg = OrganisationFixture::fake(['id' => $orgId]);
        $this->haveInDatabase('organisations', $fakeOrg->toDatabase());

        $fakeUser = UserFixture::fake([
            'id' => $userId,
            'org_id' => $orgId,
            'role_id' => $roleId,
            'authkey' => $authkey_plain
        ]);
        $this->haveInDatabase('users', $fakeUser->toDatabase());

        $fakeAuthKey = AuthKeyFixture::fake(['user_id' => $userId, 'authkey' => $authkey_plain]);
        $this->haveInDatabase('auth_keys', $fakeAuthKey->toDatabase());

        $this->haveHttpHeader('Authorization', $authkey_plain);
    }
}
