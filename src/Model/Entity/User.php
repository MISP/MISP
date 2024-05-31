<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use App\Model\Table\SettingProviders\UserSettingsProvider;
use Authentication\PasswordHasher\DefaultPasswordHasher;

class User extends AppModel
{
    protected $_hidden = ['password', 'confirm_password', 'user_settings_by_name', 'user_settings_by_name_with_fallback', 'SettingsProvider', 'user_settings'];

    protected $_virtual = ['user_settings_by_name', 'user_settings_by_name_with_fallback'];

    protected function _getUserSettingsByName()
    {
        $settingsByName = [];
        if (!empty($this->user_settings)) {
            foreach ($this->user_settings as $i => $setting) {
                $settingsByName[$setting->name] = $setting;
            }
        }
        return $settingsByName;
    }

    protected function _getUserSettingsByNameWithFallback()
    {
        if (!isset($this->SettingsProvider)) {
            $this->SettingsProvider = new UserSettingsProvider();
        }
        $settingsByNameWithFallback = [];
        if (!empty($this->user_settings)) {
            foreach ($this->user_settings as $i => $setting) {
                $settingsByNameWithFallback[$setting->name] = $setting->value;
            }
        }
        $settingsProvider = $this->SettingsProvider->getSettingsConfiguration($settingsByNameWithFallback);
        $settingsFlattened = $this->SettingsProvider->flattenSettingsConfiguration($settingsProvider);
        return $settingsFlattened;
    }

    protected function _setPassword(string $password): ?string
    {
        if (strlen($password) > 0) {
            return (new DefaultPasswordHasher())->hash($password);
        }

        return null;
    }

    public function rearrangeForAPI(): void
    {
        if (!empty($this->tags)) {
            $this->tags = $this->rearrangeTags($this->tags);
        }
        if (!empty($this->meta_fields)) {
            $this->rearrangeMetaFields();
        }
        if (!empty($this->MetaTemplates)) {
            unset($this->MetaTemplates);
        }
        if (!empty($this->user_settings_by_name)) {
            $this->rearrangeUserSettings();
        }
        $this->rearrangeSimplify(['organisation']);
    }

    private function rearrangeUserSettings()
    {
        $settings = [];
        if (isset($this->user_settings_by_name)) {
            foreach ($this->user_settings_by_name as $setting => $data) {
                $settings[$setting] = $data['value'];
            }
        }
        if (isset($this->user_settings_by_name_with_fallback)) {
            foreach ($this->user_settings_by_name_with_fallback as $setting => $data) {
                if (!isset($settings[$setting])) {
                    $settings[$setting] = $data['value'];
                }
            }
        }
        $this->settings = $settings;
    }
}
