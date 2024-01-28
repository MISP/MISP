<?php
declare(strict_types=1);

class ApcuCacheTool implements \Psr\SimpleCache\CacheInterface
{
    /** @var string */
    private $prefix;

    /**
     * @param string $prefix
     */
    public function __construct(string $prefix)
    {
        $this->prefix = $prefix;
    }

    public function get($key, $default = null)
    {
        $success = false;
        $value = \apcu_fetch("$this->prefix:$key", $success);
        if ($success) {
            return $value;
        }
        return $default;
    }

    public function set($key, $value, $ttl = null)
    {
        return \apcu_store("$this->prefix:$key", $value, $ttl === null ? 0 : $ttl);
    }

    public function delete($key)
    {
        return \apcu_delete("$this->prefix:$key");
    }

    public function clear()
    {
        foreach (new APCUIterator("/^$this->prefix:/") as $item) {
            \apcu_delete($item['key']);
        }
    }

    public function getMultiple($keys, $default = null)
    {
        foreach ($keys as $key) {
            yield $key => $this->get($key, $default);
        }
    }

    public function setMultiple($values, $ttl = null)
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }
        return true;
    }

    public function deleteMultiple($keys)
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
        return true;
    }

    public function has($key)
    {
        return \apcu_exists("$this->prefix:$key");
    }
}