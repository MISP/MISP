<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\Core\Configure;

class AuditLog extends AppModel
{
    private $compressionEnabled = false;

    public const ACTION_ADD = 'add',
        ACTION_EDIT = 'edit',
        ACTION_SOFT_DELETE = 'soft_delete',
        ACTION_DELETE = 'delete',
        ACTION_UNDELETE = 'undelete',
        ACTION_TAG = 'tag',
        ACTION_TAG_LOCAL = 'tag_local',
        ACTION_REMOVE_TAG = 'remove_tag',
        ACTION_REMOVE_TAG_LOCAL = 'remove_local_tag',
        ACTION_GALAXY = 'galaxy',
        ACTION_GALAXY_LOCAL = 'galaxy_local',
        ACTION_REMOVE_GALAXY = 'remove_galaxy',
        ACTION_REMOVE_GALAXY_LOCAL = 'remove_local_galaxy',
        ACTION_PUBLISH = 'publish',
        ACTION_PUBLISH_SIGHTINGS = 'publish_sightings',
        ACTION_LOGIN = 'login',
        ACTION_PASSWDCHANGE = 'password_change',
        ACTION_LOGOUT = 'logout',
        ACTION_LOGIN_FAILED = 'login_failed';

    public const REQUEST_TYPE_DEFAULT = 0,
        REQUEST_TYPE_API = 1,
        REQUEST_TYPE_CLI = 2;


    public function __construct(array $properties = [], array $options = [])
    {
        $this->compressionEnabled = Configure::read('Cerebrate.log_compress') && function_exists('brotli_compress');
        parent::__construct($properties, $options);
    }

    protected function _getTitle(): string
    {
        return $this->generateUserFriendlyTitle();
    }



    /**
     * @return string
     */
    public function generateUserFriendlyTitle()
    {
        if (in_array($this['request_action'], [AuditLog::ACTION_TAG, AuditLog::ACTION_TAG_LOCAL, AuditLog::ACTION_REMOVE_TAG, AuditLog::ACTION_REMOVE_TAG_LOCAL], true)) {
            $attached = ($this['request_action'] === AuditLog::ACTION_TAG || $this['request_action'] === AuditLog::ACTION_TAG_LOCAL);
            $local = ($this['request_action'] === AuditLog::ACTION_TAG_LOCAL || $this['request_action'] === AuditLog::ACTION_REMOVE_TAG_LOCAL) ? __('local') : __('global');
            if ($attached) {
                return __('Attached %s tag "%s" to %s #%s', $local, $this['model_title'], strtolower($this['model']), $this['model_id']);
            } else {
                return __('Detached %s tag "%s" from %s #%s', $local, $this['model_title'], strtolower($this['model']), $this['model_id']);
            }
        }

        if (in_array($this['request_action'], [AuditLog::ACTION_GALAXY, AuditLog::ACTION_GALAXY_LOCAL, AuditLog::ACTION_REMOVE_GALAXY, AuditLog::ACTION_REMOVE_GALAXY_LOCAL], true)) {
            $attached = ($this['request_action'] === AuditLog::ACTION_GALAXY || $this['request_action'] === AuditLog::ACTION_GALAXY_LOCAL);
            $local = ($this['request_action'] === AuditLog::ACTION_GALAXY_LOCAL || $this['request_action'] === AuditLog::ACTION_REMOVE_GALAXY_LOCAL) ? __('local') : __('global');
            if ($attached) {
                return __('Attached %s galaxy cluster "%s" to %s #%s', $local, $this['model_title'], strtolower($this['model']), $this['model_id']);
            } else {
                return __('Detached %s galaxy cluster "%s" from %s #%s', $local, $this['model_title'], strtolower($this['model']), $this['model_id']);
            }
        }

        if (in_array($this['model'], ['Attribute', 'Object', 'ShadowAttribute'], true)) {
            $modelName = $this['model'] === 'ShadowAttribute' ? 'Proposal' : $this['model'];
            $title = __('%s from Event #%s', $modelName, $this['event_id']);
        }

        if (isset($this['model_title']) && $this['model_title']) {
            if (isset($title)) {
                $title .= ": {$this['model_title']}";
                return $title;
            } else {
                return $this['model_title'];
            }
        }
        return '';
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
