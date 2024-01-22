<?php

namespace App\Lib\Tools;

use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\JsonTool;

class MISPTool
{

    /**
     * Returns MISP version from VERSION.json file as array with major, minor and hotfix keys.
     *
     * @return array
     * @throws JsonException
     */
    public static function getVersion()
    {
        
        static $versionArray;
        if ($versionArray === null) {
            $content = FileAccessTool::readFromFile(ROOT . DS . 'VERSION.json');
            $versionArray = JsonTool::decode($content);
        }
        return $versionArray;
    }
}