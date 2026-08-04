<?php
App::uses('SystemSetting', 'Model');

/**
 * Loads MISP settings from environment variables as a third configuration
 * source, in addition to the config file and the `system_settings` database
 * table. This is primarily useful for container and Kubernetes deployments
 * where settings are injected as environment variables.
 *
 * An environment variable is recognised when it starts with the prefix
 * `MISP_SETTING_`, followed by the setting name with each `.` replaced by a
 * double underscore `__`. Examples:
 *
 *   MISP.baseurl                   -> MISP_SETTING_MISP__baseurl
 *   Security.salt                  -> MISP_SETTING_Security__salt
 *   Plugin.Enrichment.services_url -> MISP_SETTING_Plugin__Enrichment__services_url
 *
 * Environment provided settings take precedence over both the database and
 * the config file, so they must be applied after those sources are loaded.
 * They are read only and cannot be changed from the UI or CLI.
 *
 * Values are cast to the most appropriate type: `true`/`false`/`null`, then
 * integers and floats, then JSON for arrays and objects, falling back to the
 * raw string. A value that should stay a string but looks numeric (for
 * example a digit only token) is therefore coerced to a number, so quote or
 * JSON encode such values if the exact string is required.
 */
class EnvSetting
{
    const ENV_PREFIX = 'MISP_SETTING_';

    /**
     * Apply every setting defined via environment variables into the global
     * Configure store. Must be called after the file and database sources are
     * loaded so that the environment always wins.
     *
     * @return void
     */
    public static function setGlobalSetting()
    {
        foreach (self::readSettings() as $settingName => $value) {
            Configure::write($settingName, $value);
        }
    }

    /**
     * Returns the settings provided via environment variables, keyed by their
     * MISP setting name (e.g. `MISP.baseurl`). Only settings whose top level
     * category is a known MISP category are returned. Unlike the database
     * source, sensitive settings are allowed, as environment variables are the
     * intended channel for injecting secrets.
     *
     * @return array
     */
    public static function readSettings()
    {
        $settings = [];
        foreach (self::environment() as $name => $value) {
            if (strpos($name, self::ENV_PREFIX) !== 0) {
                continue;
            }
            $settingName = str_replace('__', '.', substr($name, strlen(self::ENV_PREFIX)));
            $firstPart = explode('.', $settingName)[0];
            if (!in_array($firstPart, SystemSetting::ALLOWED_CATEGORIES, true)) {
                continue;
            }
            $settings[$settingName] = self::castValue($value);
        }
        return $settings;
    }

    /**
     * Whether the given setting is currently provided via an environment
     * variable. Used to mark such settings as read only.
     *
     * @param string $settingName
     * @return bool
     */
    public static function isSetViaEnv($settingName)
    {
        return array_key_exists($settingName, self::readSettings());
    }

    /**
     * Returns the environment variable name that maps to the given setting.
     *
     * @param string $settingName
     * @return string
     */
    public static function envVariableName($settingName)
    {
        return self::ENV_PREFIX . str_replace('.', '__', $settingName);
    }

    /**
     * Casts a raw environment string into the most appropriate PHP type.
     * Booleans and null are matched first, since a literal "false" string
     * would otherwise be truthy, then integers and floats, then JSON for
     * arrays and objects, falling back to the raw string.
     *
     * @param string $value
     * @return mixed
     */
    private static function castValue($value)
    {
        $lowered = strtolower($value);
        if ($lowered === 'true') {
            return true;
        }
        if ($lowered === 'false') {
            return false;
        }
        if ($lowered === 'null') {
            return null;
        }
        if (is_numeric($value)) {
            return $value == (int)$value ? (int)$value : (float)$value;
        }
        $firstChar = isset($value[0]) ? $value[0] : '';
        if ($firstChar === '{' || $firstChar === '[') {
            $decoded = json_decode($value, true);
            if ($decoded !== null) {
                return $decoded;
            }
        }
        return $value;
    }

    /**
     * Returns all environment variables. Uses getenv() so values are read
     * regardless of the PHP `variables_order` setting.
     *
     * @return array
     */
    private static function environment()
    {
        $env = getenv();
        return is_array($env) ? $env : [];
    }
}
