<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

/**
 * Voter responsible for authorizing user access to Sharing Group and Blueprint features.
 *
 * @package    MsgdPlug
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Lib.Voter
 */
class MsgdSharingGroupVoter
{
    public const USE_SHARING_GROUPS = 'use_sharing_groups';

    /**
     * Votes whether the user has access to a specific attribute.
     *
     * @param MsgdUserDTO $user
     * @param string $attribute
     *
     * @return bool
     */
    public function vote(MsgdUserDTO $user, string $attribute): bool
    {
        return match ($attribute) {
            self::USE_SHARING_GROUPS => $this->canUseSharingGroups($user),
            default => false,
        };
    }

    /**
     * Throws a ForbiddenException if the user is not authorized for the given attribute.
     *
     * @param MsgdUserDTO $user
     * @param string $attribute
     * @param string $message
     *
     * @return void
     *
     * @throws ForbiddenException
     */
    public function denyAccessUnlessGranted(
        MsgdUserDTO $user,
        string $attribute,
        string $message = 'You do not have permission to use this functionality.'
    ): void {
        if (!$this->vote($user, $attribute)) {
            throw new ForbiddenException($message);
        }
    }

    /**
     * Determines if the user is authorized based on roles, flags, or whitelist settings.
     *
     * @param MsgdUserDTO $user
     *
     * @return bool
     */
    private function canUseSharingGroups(MsgdUserDTO $user): bool
    {
        if ($user->isSiteAdmin || $user->canUseSharingGroups) {
            return true;
        }

        $userEmail = strtolower(trim($user->email));
        $whitelistConfig = $this->getWhitelistConfig();

        if ($whitelistConfig === '') {
            return false;
        }

        $allowedList = array_filter(
            array_map(
                static fn(string $value): string => strtolower(trim($value)),
                explode(',', $whitelistConfig)
            ),
            static fn(string $item): bool => $item !== ''
        );

        return in_array('*', $allowedList, true)
            || ($userEmail !== '' && in_array($userEmail, $allowedList, true));
    }

    /**
     * Retrieves configured whitelist string.
     *
     * @return string
     */
    private function getWhitelistConfig(): string
    {
        $rawWhitelist = Configure::read(
            MsgdPluginConfigEnum::user_permissions_whitelist->value
        );

        return is_scalar($rawWhitelist) ? (string)$rawWhitelist : '';
    }
}
