<?php
App::uses('AppModel', 'Model');
App::uses('EncryptedValue', 'Tools');
App::uses('BetterSecurity', 'Tools');

class SystemSetting extends AppModel
{
    public $actsAs = [
        'AuditLog'
    ];

    public $primaryKey = 'setting';

    // Blocked setting that cannot be saved or fetched from DB. The same as cli_only settings.
    const BLOCKED_SETTINGS = [
        'Security.encryption_key',
        'Security.disable_local_feed_access',
        'GnuPG.binary',
        'MISP.python_bin',
        'MISP.ca_path',
        'MISP.tmpdir',
        'MISP.system_setting_db',
        'MISP.attachments_dir',
    ];

    // Allow to set config values just for these categories
    const ALLOWED_CATEGORIES = [
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
     * Set config values from database into global Configure class
     */
    public static function setGlobalSetting()
    {
        /** @var self $systemSetting */
        $systemSetting = ClassRegistry::init('SystemSetting');
        if (!$systemSetting->databaseExists()) {
            return;
        }
        $settings = $systemSetting->getSettings();
        foreach ($settings as $settingName => $settingValue) {
            $firstPart = explode('.', $settingName)[0];
            if (in_array($firstPart, self::ALLOWED_CATEGORIES, true) && !in_array($settingName, self::BLOCKED_SETTINGS, true)) {
                Configure::write($settingName, $settingValue);
            }
        }
    }

    public function databaseExists()
    {
        $tables = ConnectionManager::getDataSource($this->useDbConfig)->listSources();
        return in_array('system_settings', $tables, true);
    }

    /**
     * @return array
     * @throws JsonException
     */
    public function getSettings()
    {
        $settings = $this->find('list', [
            'fields' => ['SystemSetting.setting', 'SystemSetting.value'],
        ]);
        return array_map(function ($value) {
            if (EncryptedValue::isEncrypted($value)) {
                return new EncryptedValue($value, true);
            } else {
                return JsonTool::decode($value);
            }
        }, $settings);
    }

    /**
     * @param string $setting Setting name
     * @param mixed $value
     * @throws Exception
     */
    public function setSetting($setting, $value)
    {
        $firstPart = explode('.', $setting)[0];
        if (!in_array($firstPart, self::ALLOWED_CATEGORIES, true) || in_array($setting, self::BLOCKED_SETTINGS, true)) {
            return false; // blocked setting
        }

        if ($value === '' || $value === null) {
            if ($this->hasAny(['SystemSetting.setting' => $setting])) {
                return $this->delete($setting); // delete the whole setting when value is empty
            }
            return true;
        }

        $value = JsonTool::encode($value);

        // If encryption is enabled and setting name contains `password` or `apikey` string, encrypt value to protect it
        if (self::isSensitive($setting)) {
            $value = EncryptedValue::encryptIfEnabled($value);
        }

        $valid = $this->save(['SystemSetting' => [
            'setting' => $setting,
            'value' => $value,
        ]]);
        if (!$valid) {
            throw new Exception("Could not save system setting `$setting` because of validation errors: " . JsonTool::encode($this->validationErrors));
        }
        return true;
    }

    /**
     * @param string|null $old Old (or current) encryption key.
     * @param string|null $new New encryption key. If empty, encrypted values will be decrypted.
     * @throws Exception
     */
    public function reencrypt($old, $new)
    {
        $settings = $this->find('list', [
            'fields' => ['SystemSetting.setting', 'SystemSetting.value'],
        ]);
        $toSave = [];
        foreach ($settings as $setting => $value) {
            if (!self::isSensitive($setting)) {
                continue;
            }
            if (EncryptedValue::isEncrypted($value)) {
                try {
                    $value = BetterSecurity::decrypt(substr($value, 2), $old);
                } catch (Exception $e) {
                    throw new Exception("Could not decrypt `$setting` setting.", 0, $e);
                }
            }
            if (!empty($new)) {
                $value = EncryptedValue::ENCRYPTED_MAGIC . BetterSecurity::encrypt($value, $new);
            }
            $toSave[] = ['SystemSetting' => [
                'setting' => $setting,
                'value' => $value,
            ]];
        }
        if (empty($toSave)) {
            return true;
        }
        return $this->saveMany($toSave);
    }

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
