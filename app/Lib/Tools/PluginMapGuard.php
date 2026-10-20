<?php
/**
 * Runs before CakePHP boots (webroot/index.php, Console/cake.php).
 *
 * Cake caches the list of plugin directories for 999 days. After an update
 * removes a plugin, Config/bootstrap.php - an old copy of it still calls
 * CakePlugin::loadAll() - throws MissingPluginException on every request and
 * every cake command, before anything could clear the cache. The stale cache
 * file is deleted instead. Never throws: when it cannot help, the instance
 * behaves as it did without it.
 */
class PluginMapGuard
{
    /**
     * @param string $appDir The app directory, without a trailing separator
     * @param array $extraPluginPaths Further directories Cake searches for plugins
     * @return array|null array('file' => path, 'removed' => bool) for a stale cache file, null when there is nothing to do
     */
    public static function heal($appDir, array $extraPluginPaths = array())
    {
        try {
            $paths = array_merge(array($appDir . DIRECTORY_SEPARATOR . 'Plugin' . DIRECTORY_SEPARATOR), $extraPluginPaths);
            $pattern = $appDir . DIRECTORY_SEPARATOR . 'tmp' . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR . 'persistent' . DIRECTORY_SEPARATOR . '*cake_core_object_map';
            foreach (glob($pattern, GLOB_NOSORT) ?: array() as $file) {
                // Cake's file cache: the expiry time, a line break, the serialized value
                $parts = explode("\n", (string)@file_get_contents($file), 2);
                $map = isset($parts[1]) ? @unserialize($parts[1], array('allowed_classes' => false)) : false;
                if (!is_array($map) || empty($map['app']['plugins']) || !is_array($map['app']['plugins'])) {
                    continue;
                }
                foreach ($map['app']['plugins'] as $plugin) {
                    if (!self::exists((string)$plugin, $paths)) {
                        return array('file' => $file, 'removed' => @unlink($file));
                    }
                }
            }
        } catch (Throwable $e) {
        }
        return null;
    }

    /**
     * CakePlugin::load() looks for the name as it is, then underscored.
     *
     * @param string $plugin
     * @param array $paths
     * @return bool
     */
    private static function exists($plugin, array $paths)
    {
        $underscored = strtolower(preg_replace('/(?<=\w)([A-Z])/', '_\1', $plugin));
        foreach ($paths as $path) {
            if (is_dir($path . $plugin) || is_dir($path . $underscored)) {
                return true;
            }
        }
        return false;
    }
}
