<?php
App::uses('JsonTool', 'Tools');

class FileAccessTool
{
    /**
     * @param string $path
     * @param int $permissions
     * @throws Exception
     */
    public static function createFile($path, $permissions = 0600)
    {
        if (!file_exists($path)) {
            if (!touch($path)) {
                throw new Exception("Could not create file `$path`.");
            }
        }
        @chmod($path, $permissions); // hide error if current user is not file owner
    }

    /**
     * Creates temporary file, but you have to delete it after use.
     * @param string|null $dir
     * @param string $prefix
     * @return string
     * @throws Exception
     */
    public static function createTempFile($dir = null, $prefix = 'MISP')
    {
        if ($dir === null) {
            $dir = Configure::read('MISP.tmpdir') ?: APP . 'tmp';
        }
        $tempFile = tempnam($dir, $prefix);
        if ($tempFile === false) {
            throw new Exception("An error has occurred while attempt to create a temporary file in path `$dir`.");
        }
        return $tempFile;
    }

    /**
     * @param string $file
     * @param int $fileSize
     * @return string
     * @throws Exception
     */
    public static function readFromFile($file, $fileSize = -1)
    {
        if ($fileSize === -1) {
            $content = file_get_contents($file);
        } else {
            $content = file_get_contents($file, false, null, 0, $fileSize);
        }
        if ($content === false) {
            if (!file_exists($file)) {
                $message = "file doesn't exists";
            } else if (!is_readable($file)) {
                $message = "file is not readable";
            } else {
                $message = 'unknown error';
            }
            throw new Exception("An error has occurred while attempt to read file `$file`: $message.");
        }
        return $content;
    }

    /**
     * @param string $file
     * @return mixed
     * @throws Exception
     */
    public static function readJsonFromFile($file)
    {
        $content = self::readFromFile($file);
        try {
            return JsonTool::decode($content);
        } catch (Exception $e) {
            throw new Exception("Could not decode JSON from file `$file`", 0, $e);
        }
    }

    /**
     * @param string $file
     * @return string
     * @throws Exception
     */
    public static function readAndDelete($file)
    {
        $content = self::readFromFile($file);
        self::deleteFile($file);
        return $content;
    }

    /**
     * @param string $file
     * @param mixed $content
     * @param bool $createFolder
     * @throws Exception
     */
    public static function writeToFile($file, $content, $createFolder = false)
    {
        $dir = dirname($file);
        if ($createFolder && !is_dir($dir)) {
            if (!mkdir($dir, 0766, true)) {
                throw new Exception("An error has occurred while attempt to create directory `$dir`.");
            }
        }

        if (file_put_contents($file, $content, LOCK_EX) === false) {
            $freeSpace = disk_free_space($dir);
            throw new Exception("An error has occurred while attempt to write to file `$file`. Maybe not enough space? ($freeSpace bytes left)");
        }
    }

    /**
     * @param mixed $content
     * @param string|null $dir
     * @return string Path to temp file
     * @throws Exception
     */
    public static function writeToTempFile($content, $dir = null)
    {
        $tempFile = self::createTempFile($dir);
        if (file_put_contents($tempFile, $content) === false) {
            self::deleteFile($tempFile);
            $freeSpace = disk_free_space(dirname($tempFile));
            throw new Exception("An error has occurred while attempt to write to file `$tempFile`. Maybe not enough space? ($freeSpace bytes left)");
        }
        return $tempFile;
    }

    /**
     * @param string $file
     * @param mixed $content
     * @throws Exception
     */
    public static function writeCompressedFile($file, $content)
    {
        $res = gzopen($file, 'wb1');
        if ($res === false) {
            throw new Exception("An error has occurred while attempt to open file `$file` for writing.");
        }
        $result = gzwrite($res, $content);
        if ($result === false) {
            throw new Exception("An error has occurred while attempt to write into file `$file`.");
        }
        gzclose($res);
        return $result;
    }

    /**
     * @param string $file
     * @return bool
     */
    public static function deleteFile($file)
    {
        return unlink($file);
    }

    /**
     * @param string $file
     * @return bool
     */
    public static function deleteFileIfExists($file)
    {
        if (file_exists($file)) {
            return unlink($file);
        } else {
            return true;
        }
    }
}
