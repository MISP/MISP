<?php
App::uses('AppModel', 'Model');
App::uses('JsonTool', 'Tools');
App::uses('BetterSecurity', 'Tools');

/**
 * Class for ondemand encryption of JSON serialized value
 */
class EncryptedValue implements JsonSerializable
{
    const ENCRYPTED_MAGIC = "\x1F\x1D";

    /** @var string */
    private $value;

    public function __construct($value)
    {
        $this->value = $value;
    }

    /**
     * @return mixed
     * @throws JsonException
     * @throws Exception
     */
    public function decrypt()
    {
        $decrypt = BetterSecurity::decrypt($this->value, Configure::read('Security.encryption_key'));
        return JsonTool::decode($decrypt);
    }

    public function __toString()
    {
        return $this->decrypt();
    }

    public function jsonSerialize()
    {
        return $this->decrypt();
    }
}

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
        $systemSetting = ClassRegistry::init('SystemSetting');
        $settings = $systemSetting->getSettings();
        foreach ($settings as $settingName => $settingValue) {
            $firstPart = explode('.', $settingName)[0];
            if (in_array($firstPart, self::ALLOWED_CATEGORIES, true) && !in_array($settingName, self::BLOCKED_SETTINGS, true)) {
                Configure::write($settingName, $settingValue);
            }
        }
    }

    /**
     * @return array
     */
    public function getSettings()
    {
        $settings = $this->find('list', [
            'fields' => ['SystemSetting.setting', 'SystemSetting.value'],
        ]);
        return array_map([$this, 'decode'], $settings);
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
        $key = Configure::read('Security.encryption_key');
        if ($key && self::isSensitive($setting)) {
            $value = EncryptedValue::ENCRYPTED_MAGIC . BetterSecurity::encrypt($value, $key);
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
     * @throws JsonException
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
            if (substr($value, 0, 2) === EncryptedValue::ENCRYPTED_MAGIC) {
                $value = BetterSecurity::decrypt(substr($value, 2), $old);
            }
            if (!empty($new)) {
                $value = EncryptedValue::ENCRYPTED_MAGIC . BetterSecurity::encrypt($value, $new);
            }
            $toSave[] = ['SystemSetting' => [
                'setting' => $setting,
                'value' => $value,
            ]];
        }
        return $this->saveMany($toSave);
    }

    /**
     * @param string $value
     * @return EncryptedValue|mixed
     * @throws JsonException
     */
    private function decode($value)
    {
        if (substr($value, 0, 2) === EncryptedValue::ENCRYPTED_MAGIC) {
            return new EncryptedValue(substr($value, 2));
        } else {
            return JsonTool::decode($value);
        }
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
