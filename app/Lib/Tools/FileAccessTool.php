<?php
class FileAccessTool
{
    /**
     * Creates temporary file, but you have to delete it after use.
     * @param string|null $dir
     * @param string $prefix
     * @return string Path to temp file
     * @throws Exception
     */
    public static function createTempFile($dir = null, $prefix = 'MISP-')
    {
        if ($dir === null) {
            $dir = Configure::read('MISP.tmpdir') ?: sys_get_temp_dir();
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
        $fileSize = $fileSize === -1 ? null : $fileSize;
        $content = file_get_contents($file, false, null, 0, $fileSize);
        if ($content === false) {
            throw new Exception("An error has occurred while attempt to read file `$file`.");
        }
        return $content;
    }

    /**
     * @param string $file
     * @param mixed $content
     * @throws Exception
     */
    public static function writeToFile($file, $content)
    {
        if (file_put_contents($file, $content, LOCK_EX) === false) {
            $freeSpace = disk_free_space($file);
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
        self::writeToFile($tempFile, $content);
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
