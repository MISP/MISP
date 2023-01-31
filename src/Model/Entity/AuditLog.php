<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Entity;
use Cake\Core\Configure;

class AuditLog extends AppModel
{
    private $compressionEnabled = false;

    public function __construct(array $properties = [], array $options = [])
    {
        $this->compressionEnabled = Configure::read('Cerebrate.log_compress') && function_exists('brotli_compress');
        parent::__construct($properties, $options);
    }

    protected function _getTitle(): String
    {
        return $this->generateUserFriendlyTitle($this);
    }

    /**
     * @param string $change
     * @return array|string
     * @throws JsonException
     */
    private function decodeChange($change)
    {
        if (substr($change, 0, 4) === self::BROTLI_HEADER) {
            if (function_exists('brotli_uncompress')) {
                $change = brotli_uncompress(substr($change, 4));
                if ($change === false) {
                    return 'Compressed';
                }
            } else {
                return 'Compressed';
            }
        }
        return json_decode($change, true);
    }

    /**
     * @param array $auditLog
     * @return string
     */
    public function generateUserFriendlyTitle($auditLog)
    {
        if (in_array($auditLog['request_action'], [self::ACTION_TAG, self::ACTION_TAG_LOCAL, self::ACTION_REMOVE_TAG, self::ACTION_REMOVE_TAG_LOCAL], true)) {
            $attached = ($auditLog['request_action'] === self::ACTION_TAG || $auditLog['request_action'] === self::ACTION_TAG_LOCAL);
            $local = ($auditLog['request_action'] === self::ACTION_TAG_LOCAL || $auditLog['request_action'] === self::ACTION_REMOVE_TAG_LOCAL) ? __('local') : __('global');
            if ($attached) {
                return __('Attached %s tag "%s" to %s #%s', $local, $auditLog['model_title'], strtolower($auditLog['model']), $auditLog['model_id']);
            } else {
                return __('Detached %s tag "%s" from %s #%s', $local, $auditLog['model_title'], strtolower($auditLog['model']), $auditLog['model_id']);
            }
        }


        $title = "{$auditLog['model']} #{$auditLog['model_id']}";

        if (isset($auditLog['model_title']) && $auditLog['model_title']) {
            $title .= ": {$auditLog['model_title']}";
        }
        return $title;
    }

    public function rearrangeForAPI(): void
    {
        if (!empty($this->user)) {
            $this->user = $this->user->toArray();
        }
        if (!empty($this->user['user_settings_by_name_with_fallback'])) {
            unset($this->user['user_settings_by_name_with_fallback']);
        }
    }
}
