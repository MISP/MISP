<?php
/**
 * File naming for cached exports. Writers (EventShell) and readers
 * (EventsController) must both go through here, so that nothing a user can
 * choose, such as an organisation name, ends up in the path.
 */
class CachedExportTool
{
    const ADMIN_OWNER = 'ADMIN';

    /**
     * Site admins get their own file (their export is unrestricted); everyone
     * else is keyed by the numeric organisation id, which can never equal
     * the admin marker.
     */
    public static function owner(array $user)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return self::ADMIN_OWNER;
        }
        return (string)(int)$user['org_id'];
    }

    public static function fileName($exportType, $subType, $owner, $extension)
    {
        return 'misp.' . $exportType . ($subType === null || $subType === '' ? '' : '_' . $subType)
            . '.' . $owner . $extension;
    }
}
