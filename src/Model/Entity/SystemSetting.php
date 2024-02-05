<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class SystemSetting extends AppModel
{
    public const BLOCKED_SETTINGS = [
        'Security.encryption_key',
        'Security.disable_local_feed_access',
        'GnuPG.binary',
        'MISP.python_bin',
        'MISP.ca_path',
        'MISP.tmpdir',
        'MISP.system_setting_db',
        'MISP.attachments_dir',
        'MISP.self_update',
        'MISP.online_version_check',
    ];

    // Allow to set config values just for these categories
    public const ALLOWED_CATEGORIES = [
        'MISP',
        'Security',
        'GnuPG',
        'SMIME',
        'Proxy',
        'SecureAuth',
        'Session',
        'Plugin',
        'debug',
        'site_admin_debug',
    ];

    /**
     * Sensitive setting are passwords or api keys.
     * @param string $setting Setting name
     * @return bool
     */
    public static function isSensitive($setting)
    {
        if ($setting === 'Security.encryption_key' || $setting === 'Security.salt') {
            return true;
        }
        if (substr($setting, 0, 7) === 'Plugin.' && (strpos($setting, 'apikey') !== false || strpos($setting, 'secret') !== false)) {
            return true;
        }
        return strpos($setting, 'password') !== false;
    }
}
