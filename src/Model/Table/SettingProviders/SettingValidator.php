<?php

namespace App\Model\Table\SettingProviders;

class SettingValidator
{
    public function testEmptyBecomesDefault($value, &$setting)
    {
        if (!empty($value)) {
            return true;
        } else if (isset($setting['default'])) {
            $setting['value'] = $setting['default'];
            $setting['severity'] = $setting['severity'] ?? 'info';
            if ($setting['type'] == 'boolean') {
                return __('Setting is not set, fallback to default value: {0}', empty($setting['default']) ? 'false' : 'true');
            } else {
                return __('Setting is not set, fallback to default value: {0}', $setting['default']);
            }
        } else {
            $setting['severity'] = $setting['severity'] ?? 'critical';
            return __('Cannot be empty. Setting does not have a default value.');
        }
    }

    public function testForEmpty($value, &$setting)
    {
        return !empty($value) ? true : __('Cannot be empty');
    }
}
