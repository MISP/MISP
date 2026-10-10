<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/Lib/DTO/MsgdUserDTO.php';
require_once dirname(__DIR__, 4) . '/Lib/Enum/MsgdPluginConfigEnum.php';
require_once dirname(__DIR__, 4) . '/Lib/Voter/MsgdSharingGroupVoter.php';

/**
 * Tests for MsgdSharingGroupVoter.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.Voter
 */
final class MsgdSharingGroupVoterTest extends TestCase
{
    private const UUID_1 = '11111111-1111-4111-8111-111111111111';

    protected function tearDown(): void
    {
        Configure::delete(MsgdPluginConfigEnum::user_permissions_whitelist->value);
        parent::tearDown();
    }

    private function createUser(
        bool $isSiteAdmin = false,
        bool $canUseSharingGroups = false,
        string $email = 'user@example.com'
    ): MsgdUserDTO {
        return new MsgdUserDTO([
            'id' => 1,
            'org_id' => 10,
            'email' => $email,
            'Role' => [
                'perm_site_admin' => $isSiteAdmin,
                'perm_sharing_group' => $canUseSharingGroups,
            ],
            'Organisation' => [
                'id' => 10,
                'name' => 'Test Org',
                'uuid' => self::UUID_1,
            ],
        ]);
    }

    public function testVoteReturnsTrueForSiteAdmin(): void
    {
        $voter = new MsgdSharingGroupVoter();
        $user = $this->createUser(isSiteAdmin: true);

        $this->assertTrue($voter->vote($user, MsgdSharingGroupVoter::USE_SHARING_GROUPS));
    }

    public function testVoteReturnsTrueForUserWithDirectPermission(): void
    {
        $voter = new MsgdSharingGroupVoter();
        $user = $this->createUser(canUseSharingGroups: true);

        $this->assertTrue($voter->vote($user, MsgdSharingGroupVoter::USE_SHARING_GROUPS));
    }

    public function testVoteReturnsTrueForWhitelistedEmail(): void
    {
        Configure::write(
            MsgdPluginConfigEnum::user_permissions_whitelist->value,
            'admin@example.com, USER@EXAMPLE.COM '
        );

        $voter = new MsgdSharingGroupVoter();
        $user = $this->createUser(email: 'user@example.com');

        $this->assertTrue($voter->vote($user, MsgdSharingGroupVoter::USE_SHARING_GROUPS));
    }

    public function testVoteReturnsTrueForWildcardWhitelist(): void
    {
        Configure::write(
            MsgdPluginConfigEnum::user_permissions_whitelist->value,
            '*'
        );

        $voter = new MsgdSharingGroupVoter();
        $user = $this->createUser();

        $this->assertTrue($voter->vote($user, MsgdSharingGroupVoter::USE_SHARING_GROUPS));
    }

    public function testVoteReturnsFalseWhenUserHasNoAccessAndNotWhitelisted(): void
    {
        Configure::write(
            MsgdPluginConfigEnum::user_permissions_whitelist->value,
            'other@example.com'
        );

        $voter = new MsgdSharingGroupVoter();
        $user = $this->createUser();

        $this->assertFalse($voter->vote($user, MsgdSharingGroupVoter::USE_SHARING_GROUPS));
    }

    public function testVoteReturnsFalseForUnsupportedAttribute(): void
    {
        $voter = new MsgdSharingGroupVoter();
        $user = $this->createUser(isSiteAdmin: true);

        $this->assertFalse($voter->vote($user, 'invalid_attribute'));
    }
}
