<?php


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
        $this->haveMispSetting('Security.advanced_authkeys', '0');
    }

    /**
     * Define custom actions here
     */

    public function haveAdminAuthorizationKey()
    {
        // TODO: Refactor, use OrganisationFixture
        $this->haveInDatabase(
            'organisations',
            [
                'id' => 1,
                'name' => 'ORGNAME',
                'date_created' => '2021-04-08 13:45:06',
                'date_modified' => '2021-04-08 13:45:06',
                'description' => 'Automatically generated admin organisation',
                'type' => 'ADMIN',
                'nationality' => '',
                'sector' => '',
                'created_by' => 0,
                'uuid' => '76e91054-b441-47a0-ab5f-c4db436dacce',
                'contacts' => null,
                'local' => 1,
                'restricted_to_domain' => '',
                'landingpage' => null
            ]
        );

        // TODO: Refactor, use UserFixture
        $this->haveInDatabase(
            'users',
            [
                'id' => 1,
                'password' => '$2a$10$.4Wxcl93EkdM9yJSfwrmv.OAeaC/4DNWdJSqwhBcEblIIoPpINSWy',
                'org_id' => '1',
                'server_id' => '0',
                'email' => 'admin@admin.test',
                'autoalert' => 0,
                'authkey' => 'x7xVLpxkdHcIgpWf1WmZr8M90dABbtXOwNTk5fUe',
                'invited_by' => 0,
                'gpgkey' => null,
                'certif_public' => '',
                'nids_sid' => 4000000,
                'termsaccepted' => 1,
                'newsread' => 1,
                'role_id' => 1,
                'change_pw' => 0,
                'contactalert' => 0,
                'disabled' => 0,
                'expiration' => null,
                'current_login' => 0,
                'last_login' => 0,
                'force_logout' => 0,
                'date_created' => null,
                'date_modified' => 1617889510
            ]
        );

        $this->haveHttpHeader('Authorization', 'x7xVLpxkdHcIgpWf1WmZr8M90dABbtXOwNTk5fUe');
    }
}
