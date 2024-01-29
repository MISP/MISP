<?php
require_once CAKE_CORE_INCLUDE_PATH . '/Cake/Cache/CacheEngine.php';
require_once CAKE_CORE_INCLUDE_PATH . '/Cake/Cache/Engine/FileEngine.php';

/**
 * This is faster version of FileEngine cache engine
 * - stores file in binary format, so no need to change line endings
 * - uses igbinary if supported for faster serialization/deserialization and smaller cache files
 * - default file mask is set to 0660, so cache files are not readable by other users
 * - optimised file saving and fetching
 */
class BinaryFileEngine extends FileEngine
{
    const BINARY_CACHE_TIME_LENGTH = 8;

    private $useIgbinary = false;

    public function init($settings = [])
    {
        $settings += [
            'engine' => 'BinaryFile',
            'path' => CACHE,
            'prefix' => 'cake_',
            'serialize' => true,
            'mask' => 0660,
        ];
        CacheEngine::init($settings);

        $this->useIgbinary = function_exists('igbinary_serialize');
        if (substr($this->settings['path'], -1) !== DS) {
            $this->settings['path'] .= DS;
        }
        if (!empty($this->_groupPrefix)) {
            $this->_groupPrefix = str_replace('_', DS, $this->_groupPrefix);
        }
        return $this->_active();
    }

    /**
     * @param string $key
     * @param mixed $data
     * @param int $duration
     * @return bool
     */
    public function write($key, $data, $duration)
    {
        if (!$this->_init) {
            return false;
        }

        $fileInfo = $this->cacheFilePath($key);
        $resource = $this->createFile($fileInfo);
        if (!$resource) {
            return false;
        }

        if (!empty($this->settings['serialize'])) {
            if ($this->useIgbinary) {
                $data = igbinary_serialize($data);
                if ($data === null) {
                    return false;
                }
            } else {
                $data = serialize($data);
            }
        }

        $expires = pack("q", time() + $duration);

        flock($resource, LOCK_EX);

        ftruncate($resource, 0);

        $result = fwrite($resource, $expires);
        if ($result !== self::BINARY_CACHE_TIME_LENGTH) {
            $this->handleWriteError($fileInfo);
            fclose($resource);
            return false;
        }

        $result = fwrite($resource, $data);
        if ($result !== strlen($data)) {
            $this->handleWriteError($fileInfo);
            fclose($resource);
            return false;
        }

        fclose($resource);

        return true;
    }

    /**
     * @param string $key
     * @return false|mixed|string
     */
    public function read($key)
    {
        if (!$this->_init) {
            return false;
        }

        $fileInfo = $this->cacheFilePath($key);

        $exists = file_exists($fileInfo->getPathname());
        if (!$exists) {
            return false;
        }

        $resource = $this->openFile($fileInfo);
        if (!$resource) {
            return false;
        }

        $time = time();

        flock($resource, LOCK_SH);

        $cacheTimeBinary = fread($resource, self::BINARY_CACHE_TIME_LENGTH);
        if (!$cacheTimeBinary) {
            fclose($resource);
            return false;
        }

        $cacheTime = $this->unpackCacheTime($cacheTimeBinary);
        if ($cacheTime < $time || ($time + $this->settings['duration']) < $cacheTime) {
            fclose($resource);
            return false; // already expired
        }

        $data = stream_get_contents($resource, null, self::BINARY_CACHE_TIME_LENGTH);
        fclose($resource);

        if (!empty($this->settings['serialize'])) {
            if ($this->useIgbinary) {
                $data = igbinary_unserialize($data);
            } else {
                $data = unserialize($data);
            }
        }

        return $data;
    }

    /**
     * @param string $path
     * @param int $now
     * @param int $threshold
     * @return void
     */
    protected function _clearDirectory($path, $now, $threshold)
    {
        $prefixLength = strlen($this->settings['prefix']);

        if (!is_dir($path)) {
            return;
        }

        $dir = dir($path);
        if ($dir === false) {
            return;
        }

        while (($entry = $dir->read()) !== false) {
            if (substr($entry, 0, $prefixLength) !== $this->settings['prefix']) {
                continue;
            }

            try {
                $file = new SplFileObject($path . $entry, 'rb');
            } catch (Exception $e) {
                continue;
            }

            if ($threshold) {
                $mtime = $file->getMTime();
                if ($mtime > $threshold) {
                    continue;
                }
                $expires = $this->unpackCacheTime($file->fread(self::BINARY_CACHE_TIME_LENGTH));
                if ($expires > $now) {
                    continue;
                }
            }
            if ($file->isFile()) {
                $filePath = $file->getRealPath();
                $file = null;
                @unlink($filePath);
            }
        }
    }

    /**
     * @param SplFileInfo $fileInfo
     * @return false|resource
     */
    private function createFile(SplFileInfo $fileInfo)
    {
        $exists = file_exists($fileInfo->getPathname());
        if (!$exists) {
            $resource = $this->openFile($fileInfo, 'cb');
            if ($resource && !chmod($fileInfo->getPathname(), (int)$this->settings['mask'])) {
                trigger_error(__d(
                    'cake_dev', 'Could not apply permission mask "%s" on cache file "%s"',
                    [$fileInfo->getPathname(), $this->settings['mask']]), E_USER_WARNING);
            }
            return $resource;
        }

        return $this->openFile($fileInfo, 'cb');
    }

    /**
     * @param SplFileInfo $fileInfo
     * @param string $mode
     * @return false|resource
     */
    private function openFile(SplFileInfo $fileInfo, $mode = 'rb')
    {
        $resource = fopen($fileInfo->getPathname(), $mode);
        if (!$resource) {
            trigger_error(__d(
                'cake_dev', 'Could not open file %s',
                array($fileInfo->getPathname())), E_USER_WARNING);
        }
        return $resource;
    }

    /**
     * @param string $key
     * @return SplFileInfo
     */
    private function cacheFilePath(string $key): SplFileInfo
    {
        $groups = null;
        if (!empty($this->_groupPrefix)) {
            $groups = vsprintf($this->_groupPrefix, $this->groups());
        }
        $dir = $this->settings['path'] . $groups;

        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }

        $suffix = '.bin';
        if ($this->settings['serialize'] && $this->useIgbinary) {
            $suffix = '.igbin';
        }

        return new SplFileInfo($dir . $key . $suffix);
    }

    /**
     * @param SplFileInfo $fileInfo
     * @return void
     */
    private function handleWriteError(SplFileInfo $fileInfo)
    {
        unlink($fileInfo->getPathname()); // delete file in case file was just partially written
        trigger_error(__d(
            'cake_dev', 'Could not write to file %s',
            array($fileInfo->getPathname())), E_USER_WARNING);
    }

    /**
     * @param string $cacheTimeBinary
     * @return int
     */
    private function unpackCacheTime($cacheTimeBinary)
    {
        if ($cacheTimeBinary === false || strlen($cacheTimeBinary) !== self::BINARY_CACHE_TIME_LENGTH) {
            throw new InvalidArgumentException("Invalid cache time in binary format provided '$cacheTimeBinary'");
        }
        return unpack("q", $cacheTimeBinary)[1];
    }
}