<?php
App::uses('AppModel', 'Model');
App::uses('JsonTool', 'Tools');

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
        $key = Configure::read('Security.encryption_key');
        if (empty($key)) {
            throw new Exception("Value is encrypted, but encryption key is not sed.");
        }
        $decrypt = Security::decrypt($this->value, $key);
        if ($decrypt === false) {
            throw new Exception("Could not decrypt.");
        }
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
        'SysLogLogable.SysLogLogable' => [
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ],
        'AuditLog'
    ];

    public $primaryKey = 'setting';

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
        $value = JsonTool::encode($value);

        // If encryption is enabled and setting name contains `password` or `apikey` string, encrypt value to protect it
        $key = Configure::read('Security.encryption_key');
        if ($key && (strpos($setting, 'password') !== false || strpos($setting, 'apikey') !== false)) {
            $value = EncryptedValue::ENCRYPTED_MAGIC . Security::encrypt($value, $key);
        }

        $valid = $this->save(['SystemSetting' => [
            'setting' => $setting,
            'value' => $value,
        ]]);
        if (!$valid) {
            throw new Exception("Could not save system setting `$setting` because of validation errors: " . JsonTool::encode($this->validationErrors));
        }
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
}
