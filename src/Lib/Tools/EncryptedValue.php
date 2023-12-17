<?php

namespace App\Lib\Tools;

use Cake\Core\Configure;
use JsonSerializable;

/**
 * Class for ondemand encryption of JSON serialized value
 */
class EncryptedValue implements JsonSerializable
{
    const ENCRYPTED_MAGIC = "\x1F\x1D";

    /** @var string */
    private $value;

    /** @var bool */
    private $isJson;

    public function __construct($value, $isJson = false)
    {
        $this->value = $value;
        $this->isJson = $isJson;
    }

    /**
     * @return mixed
     * @throws JsonException
     * @throws Exception
     */
    public function decrypt($key=false)
    {
        if (!$key) {
            $key = Configure::read('Security.encryption_key');
        }
        if (!$key) return '';
        $decrypt = BetterSecurity::decrypt(substr($this->value, 2), $key);
        return $this->isJson ? JsonTool::decode($decrypt) : $decrypt;
    }

    public function __toString()
    {
        return $this->decrypt();
    }

    public function jsonSerialize(): mixed
    {
        return $this->decrypt();
    }

    /**
     * Encrypt provided string if encryption is enabled. If not enabled, input value will be returned.
     * @param string $value
     * @return string
     * @throws Exception
     */
    public static function encryptIfEnabled($value, $key=false)
    {
        if (!$key) {
            $key = Configure::read('Security.encryption_key');
        }
        if ($key) {
            return EncryptedValue::ENCRYPTED_MAGIC . BetterSecurity::encrypt($value, $key);
        }
        return $value;
    }

    /**
     * Decrypt if value is encrypted. If not encrypted, input value will be returned.
     * @param string $value
     * @return string
     * @throws Exception
     */
    public static function decryptIfEncrypted($value, $key=false)
    {
        if(is_resource($value))
            $value = stream_get_contents($value);
        if (EncryptedValue::isEncrypted($value)) {
            $self = new EncryptedValue($value);
            return $self->decrypt($key); 
        } else {
            return $value;
        }
    }

    /**
     * Check if value is encrypted (starts with encrypted magic)
     * @param string $value
     * @return bool
     */
    public static function isEncrypted($value)
    {
        return substr($value, 0, 2) === EncryptedValue::ENCRYPTED_MAGIC;
    }
}
