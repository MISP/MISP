<?php

namespace App\Lib\Tools;

use Cake\Core\Configure;
use Cake\Http\Exception\InternalErrorException;
use Cake\Http\Exception\MethodNotAllowedException;
use Exception;

class FileAccessTool
{
    /**
     * @param string $path
     * @param int $permissions
     * @throws Exception
     */
    public static function createFile(string $path, int $permissions = 0600): void
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
    public static function createTempFile(?string $dir = null, string $prefix = 'MISP'): string
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
    public static function readFromFile(string $file, int $fileSize = -1): string
    {
        if ($fileSize === -1) {
            $content = @file_get_contents($file);
        } else {
            $content = @file_get_contents($file, false, null, 0, $fileSize);
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
     * @param bool $mustBeArray If true, exception will be thrown if deserialized data are not array type
     * @return mixed
     * @throws Exception
     */
    public static function readJsonFromFile(string $file, bool $mustBeArray = false): mixed
    {
        $content = self::readFromFile($file);
        try {
            require_once ROOT . '/src/Lib/Tools/JsonTool.php';
            return $mustBeArray ? JsonTool::decodeArray($content) : JsonTool::decode($content);
        } catch (Exception $e) {
            throw new Exception("Could not decode JSON from file `$file`", 0, $e);
        }
    }

    /**
     * @param string $file
     * @return string
     * @throws Exception
     */
    public static function readAndDelete(string $file): string
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
    public static function writeToFile(string $file, mixed $content, bool $createFolder = false, $append = false): void
    {
        $dir = dirname($file);
        if ($createFolder && !is_dir($dir)) {
            if (!mkdir($dir, 0766, true)) {
                throw new Exception("An error has occurred while attempt to create directory `$dir`.");
            }
        }

        if (file_put_contents($file, $content, LOCK_EX | (!empty($append) ? FILE_APPEND : 0)) === false) {
            if (file_exists($file) && !is_writable($file)) {
                $errorMessage = 'File is not writeable.';
            } else {
                $freeSpace = disk_free_space($dir);
                $errorMessage = "Maybe not enough space? ($freeSpace bytes left)";
            }

            throw new Exception("An error has occurred while attempt to write to file `$file`. $errorMessage");
        }
    }

    /**
     * @param mixed $content
     * @param string|null $dir
     * @return string Path to temp file
     * @throws Exception
     */
    public static function writeToTempFile(mixed $content, ?string $dir = null): string
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
    public static function writeCompressedFile(string $file, mixed $content, bool $createFolder = false): int
    {
        $dir = dirname($file);
        if ($createFolder && !is_dir($dir)) {
            if (!mkdir($dir, 0766, true)) {
                throw new Exception("An error has occurred while attempt to create directory `$dir`.");
            }
        }

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
     * @return string
     * @throws Exception
     */
    public static function readCompressedFile(string $file): mixed
    {
        $content = file_get_contents("compress.zlib://$file");
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
     * @return bool
     */
    public static function deleteFile(string $file): bool
    {
        return unlink($file);
    }

    /**
     * @param string $file
     * @return bool
     */
    public static function deleteFileIfExists(string $file): bool
    {
        if (file_exists($file)) {
            return unlink($file);
        } else {
            return true;
        }
    }

    /**
     * @param array $submittedFile
     * @param string $alternate
     * @return string
     */
    public static function getTempUploadedFile(array $submittedFile, string $alternate = ''): string
    {
        if ($submittedFile['name'] != '' && $alternate != '') {
            throw new MethodNotAllowedException(__('Only one import field can be used'));
        }
        if ($submittedFile['size'] > 0) {
            $filename = basename($submittedFile['name']);
            if (!is_uploaded_file($submittedFile['tmp_name'])) {
                throw new InternalErrorException(__('PHP says file was not uploaded. Are you attacking me?'));
            }
            $file = new \SplFileObject($submittedFile['tmp_name']);
            $file_content = $file->fread($file->getSize());
            $file = null; // closing a file in SplFileObject
            if (
                (isset($submittedFile['error']) && $submittedFile['error'] == 0) ||
                (!empty($submittedFile['tmp_name']) && $submittedFile['tmp_name'] != '')
            ) {
                if (!$file_content) {
                    throw new InternalErrorException(__('PHP says file was not uploaded. Are you attacking me?'));
                }
            }
            $text = $file_content;
        } else {
            $text = $alternate ? $alternate : '';
        }
        return $text;
    }
}
