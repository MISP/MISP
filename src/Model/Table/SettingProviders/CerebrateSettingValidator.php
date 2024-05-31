<?php

namespace App\Model\Table\SettingProviders;

use Cake\Core\Configure;

class CerebrateSettingValidator extends SettingValidator
{
    public function testUuid($value, &$setting)
    {
        if (empty($value) || !preg_match('/^\{?[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}\}?$/', $value)) {
            return __('Invalid UUID.');
        }
        return true;
    }


    public function testBaseURL($value, &$setting)
    {
        if (empty($value)) {
            return __('Cannot be empty');
        }
        if (!empty($value) && !preg_match('/^http(s)?:\/\//i', $value)) {
            return __('Invalid URL, please make sure that the protocol is set.');
        }
        return true;
    }

    public function testEnabledAuth($value, &$setting)
    {
        $providers = [
            'password_auth',
            'keycloak'
        ];
        if (!$value) {
            $foundEnabledAuth = __('Cannot make change - this would disable every possible authentication method.');
            foreach ($providers as $provider) {
                if ($provider !== $setting['authentication_type']) {
                    if (Configure::read($provider . '.enabled')) {
                        $foundEnabledAuth = true;
                    }
                }
            }
            return $foundEnabledAuth;
        }
        return true;
    }
}
