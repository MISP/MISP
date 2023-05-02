<?php
namespace App\Settings\SettingsProvider;

use App\Model\Table\AppTable;
use Cake\Validation\Validator;
use Cake\ORM\TableRegistry;

class BaseSettingsProvider
{
    protected $settingsConfiguration = [];
    protected $error_critical = '',
            $error_warning = '',
            $error_info = '';
    protected $severities = ['info', 'warning', 'critical'];
    protected $settingValidator;

    public function __construct()
    {
        $this->settingsConfiguration = $this->generateSettingsConfiguration();
        $this->error_critical =  __('Cerebrate will not operate correctly or will be unsecure until these issues are resolved.');
        $this->error_warning =  __('Some of the features of Cerebrate cannot be utilised until these issues are resolved.');
        $this->error_info =  __('There are some optional tweaks that could be done to improve the looks of your Cerebrate instance.');
        if (!isset($this->settingValidator)) {
            $this->settingValidator = new SettingValidator();
        }
    }

    /**
     * Supports up to 3 levels:
     *      Application -> Network -> Proxy -> Proxy.URL
     *        page -> [group] -> [panel] -> setting
     * Keys of setting configuration are the actual setting name.
     * Accepted setting configuration:
     *     name        [required]: The human readable name of the setting.
     *     type        [required]: The type of the setting.
     *     description [required]: A description of the setting.
     *                             Default severity level is `info` if a `default` value is provided otherwise it becomes `critical`
     *     default     [optional]: The default value of the setting if not specified in the configuration.
     *     options     [optional]: Used to populate the select with options. Keys are values to be saved, values are human readable version of the value.
     *                             Required paramter if `type` == `select`.
     *     severity    [optional]: Severity level of the setting if the configuration is incorrect.
     *     dependsOn   [optional]: If the validation of this setting depends on the validation of the provided setting name
     *     test        [optional]: Could be either a string or an anonymous function to be called in order to warn user if setting is invalid.
     *                             Could be either: `string`, `boolean`, `integer`, `select`
     *     beforeSave  [optional]: Could be either a string or an anonymous function to be called in order to block a setting to be saved.
     *     afterSave   [optional]: Could be either a string or an anonymous function to be called allowing to execute a function after the setting is saved.
     *     redacted    [optional]: Should the setting value be redacted. FIXME: To implement
     *     cli_only    [optional]: Should this setting be modified only via the CLI.
     */
    protected function generateSettingsConfiguration()
    {
        return [];
    }

    /**
     * getSettingsConfiguration Return the setting configuration and merge existing settings into it if provided
     *
     * @param  null|array $settings - Settings to be merged in the provided setting configuration
     * @return array
     */
    public function getSettingsConfiguration($settings = null) {
        $settingConf = $this->settingsConfiguration;
        if (!is_null($settings)) {
            $settingConf = $this->mergeSettingsIntoSettingConfiguration($settingConf, $settings);
        }
        return $settingConf;
    }

    /**
     * mergeSettingsIntoSettingConfiguration Inject the provided settings into the configuration while performing depencency and validation checks
     *
     * @param  array $settingConf the setting configuration to have the setting injected into
     * @param  array $settings the settings
     * @return void
     */
    protected function mergeSettingsIntoSettingConfiguration(array $settingConf, array $settings, string $path=''): array
    {
        foreach ($settingConf as $key => $value) {
            if ($this->isSettingMetaKey($key)) {
                continue;
            }
            if ($this->isLeaf($value)) {
                if (isset($settings[$key])) {
                    $settingConf[$key]['value'] = $settings[$key];
                }
                $settingConf[$key] = $this->evaluateLeaf($settingConf[$key], $settingConf);
                $settingConf[$key]['setting-path'] = $path;
                $settingConf[$key]['true-name'] = $key;
            } else {
                $currentPath = empty($path) ? $key : sprintf('%s.%s', $path, $key);
                $settingConf[$key] = $this->mergeSettingsIntoSettingConfiguration($value, $settings, $currentPath);
            }
        }
        return $settingConf;
    }

    public function flattenSettingsConfiguration(array $settingsProvider, $flattenedSettings=[]): array
    {
        foreach ($settingsProvider as $key => $value) {
            if ($this->isSettingMetaKey($key)) {
                continue;
            }
            if ($this->isLeaf($value)) {
                $flattenedSettings[$key] = $value;
            } else {
                $flattenedSettings = $this->flattenSettingsConfiguration($value, $flattenedSettings);
            }
        }
        return $flattenedSettings;
    }

    /**
     * getNoticesFromSettingsConfiguration Summarize the validation errors
     *
     * @param  array $settingsProvider the setting configuration having setting value assigned
     * @return void
     */
    public function getNoticesFromSettingsConfiguration(array $settingsProvider): array
    {
        $notices = [];
        foreach ($settingsProvider as $key => $value) {
            if ($this->isSettingMetaKey($key)) {
                continue;
            }
            if ($this->isLeaf($value)) {
                if (!empty($value['error'])) {
                    if (empty($notices[$value['severity']])) {
                        $notices[$value['severity']] = [];
                    }
                    $notices[$value['severity']][] = $value;
                }
            } else {
                $notices = array_merge_recursive($notices, $this->getNoticesFromSettingsConfiguration($value));
            }
        }
        return $notices;
    }

    protected function isLeaf($setting)
    {
        return !empty($setting['name']) && !empty($setting['type']);
    }

    protected function evaluateLeaf($setting, $settingSection)
    {
        $skipValidation = false;
        if ($setting['type'] == 'select' || $setting['type'] == 'multi-select') {
            if (!empty($setting['options']) && is_callable($setting['options'])) {
                $setting['options'] = $setting['options']($this);
            }
        }
        if (isset($setting['dependsOn'])) {
            $parentSetting = null;
            foreach ($settingSection as $settingSectionName => $settingSectionConfig) {
                if ($settingSectionName == $setting['dependsOn']) {
                    $parentSetting = $settingSectionConfig;
                }
            }
            if (!is_null($parentSetting)) {
                $parentSetting = $this->evaluateLeaf($parentSetting, $settingSection);
                $skipValidation = $parentSetting['error'] === true || empty($parentSetting['value']);
            }
        }
        $setting['error'] = false;
        if (!$skipValidation) {
            $validationResult = true;
            if (!isset($setting['value'])) {
                $validationResult = $this->settingValidator->testEmptyBecomesDefault(null, $setting);
            } else if (isset($setting['test'])) {
                $setting['value'] = $setting['value'] ?? '';
                $validationResult = $this->evaluateFunctionForSetting($setting['test'], $setting);
            }
            if ($validationResult !== true) {
                $setting['severity'] = $setting['severity'] ?? 'warning';
                if (!in_array($setting['severity'], $this->severities)) {
                    $setting['severity'] = 'warning';
                }
                $setting['errorMessage'] = $validationResult;
            }
            $setting['error'] = $validationResult !== true ? true : false;
        }
        return $setting;
    }

    /**
     * evaluateFunctionForSetting - evaluate the provided function. If function could not be evaluated, its result is defaulted to true
     *
     * @param  mixed $fun
     * @param  array $setting
     * @return mixed
     */
    public function evaluateFunctionForSetting($fun, &$setting)
    {
        $functionResult = true;
        if (is_callable($fun)) { // Validate with anonymous function
            $functionResult = $fun($setting['value'], $setting, new Validator());
        } else if (method_exists($this->settingValidator, $fun)) { // Validate with function defined in settingValidator class
            $functionResult = $this->settingValidator->{$fun}($setting['value'], $setting);
        } else {
            $validator = new Validator();
            if (method_exists($validator, $fun)) { // Validate with cake's validator function
                $validator->{$fun};
                $functionResult = $validator->validate($setting['value']);
            }
        }
        return $functionResult;
    }

    function isSettingMetaKey($key)
    {
        return substr($key, 0, 1) == '_';
    }
}

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
