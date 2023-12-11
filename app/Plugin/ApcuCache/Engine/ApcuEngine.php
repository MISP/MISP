<?php
require_once CAKE_CORE_INCLUDE_PATH . '/Cake/Cache/CacheEngine.php';

/**
 * APC storage engine for cache. Faster version of original ApcEngine
 */
class ApcuEngine extends CacheEngine {

    /**
     * Contains the compiled group names
     * (prefixed with the global configuration prefix)
     *
     * @var array
     */
    protected $_compiledGroupNames = array();

    /**
     * Initialize the Cache Engine
     *
     * Called automatically by the cache frontend
     * To reinitialize the settings call Cache::engine('EngineName', [optional] settings = array());
     *
     * @param array $settings array of setting for the engine
     * @return bool True if the engine has been successfully initialized, false if not
     * @see CacheEngine::__defaults
     */
    public function init($settings = array()) {
        if (!isset($settings['prefix'])) {
            $settings['prefix'] = Inflector::slug(APP_DIR) . '_';
        }
        $settings += array('engine' => 'Apc');
        parent::init($settings);
        return function_exists('apcu_dec');
    }

    /**
     * Write data for key into cache
     *
     * @param string $key Identifier for the data
     * @param mixed $value Data to be cached
     * @param int $duration How long to cache the data, in seconds
     * @return bool True if the data was successfully cached, false on failure
     */
    public function write($key, $value, $duration) {
        return apcu_store($key, $value, $duration);
    }

    /**
     * Read a key from the cache
     *
     * @param string $key Identifier for the data
     * @return mixed The cached data, or false if the data doesn't exist, has expired, or if there was an error fetching it
     */
    public function read($key) {
        return apcu_fetch($key);
    }

    /**
     * Increments the value of an integer cached key
     *
     * @param string $key Identifier for the data
     * @param int $offset How much to increment
     * @return false|int New incremented value, false otherwise
     */
    public function increment($key, $offset = 1) {
        return apcu_inc($key, $offset);
    }

    /**
     * Decrements the value of an integer cached key
     *
     * @param string $key Identifier for the data
     * @param int $offset How much to subtract
     * @return false|int New decremented value, false otherwise
     */
    public function decrement($key, $offset = 1) {
        return apcu_dec($key, $offset);
    }

    /**
     * Delete a key from the cache
     *
     * @param string $key Identifier for the data
     * @return bool True if the value was successfully deleted, false if it didn't exist or couldn't be removed
     */
    public function delete($key) {
        return apcu_delete($key);
    }

    /**
     * Delete all keys from the cache. This will clear every cache config using APC.
     *
     * @param bool $check If true, nothing will be cleared, as entries are removed
     *    from APC as they expired. This flag is really only used by FileEngine.
     * @return bool True Returns true.
     */
    public function clear($check) {
        if ($check) {
            return true;
        }
        $iterator = new APCUIterator(
            '/^' . preg_quote($this->settings['prefix'], '/') . '/',
            APC_ITER_NONE
        );
        apcu_delete($iterator);
        return true;
    }

    /**
     * Returns the `group value` for each of the configured groups
     * If the group initial value was not found, then it initializes
     * the group accordingly.
     *
     * @return array
     */
    public function groups() {
        if (empty($this->_compiledGroupNames)) {
            foreach ($this->settings['groups'] as $group) {
                $this->_compiledGroupNames[] = $this->settings['prefix'] . $group;
            }
        }

        $groups = apcu_fetch($this->_compiledGroupNames);
        if (count($groups) !== count($this->settings['groups'])) {
            foreach ($this->_compiledGroupNames as $group) {
                if (!isset($groups[$group])) {
                    apcu_store($group, 1);
                    $groups[$group] = 1;
                }
            }
            ksort($groups);
        }

        $result = array();
        $groups = array_values($groups);
        foreach ($this->settings['groups'] as $i => $group) {
            $result[] = $group . $groups[$i];
        }
        return $result;
    }

    /**
     * Increments the group value to simulate deletion of all keys under a group
     * old values will remain in storage until they expire.
     *
     * @param string $group The group to clear.
     * @return bool success
     */
    public function clearGroup($group) {
        apcu_inc($this->settings['prefix'] . $group, 1, $success);
        return $success;
    }

    /**
     * Write data for key into cache if it doesn't exist already.
     * If it already exists, it fails and returns false.
     *
     * @param string $key Identifier for the data.
     * @param mixed $value Data to be cached.
     * @param int $duration How long to cache the data, in seconds.
     * @return bool True if the data was successfully cached, false on failure.
     * @link http://php.net/manual/en/function.apc-add.php
     */
    public function add($key, $value, $duration) {
        return apc_add($key, $value, $duration);
    }
}
