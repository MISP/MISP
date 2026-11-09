<?php
// Only loaded inside isolated PHPUnit test processes.
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package) {}
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel {}
}
if (!class_exists('Configure', false)) {
    class Configure
    {
        public static function read($key)
        {
            return $key === 'MISP.disable_sighting_loading' ? false : null;
        }
    }
}
if (!class_exists('Validation', false)) {
    class Validation
    {
        public static function uuid($value)
        {
            return is_string($value) &&
                preg_match('/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/iD', $value) === 1;
        }
    }
}
if (!class_exists('JsonTool', false)) {
    class JsonTool
    {
        public static function convertIntegersToStrings(&$sightings) {}
    }
}
if (!class_exists('TmpFileTool', false)) {
    class TmpFileTool
    {
        public function write($content) {}
        public function writeWithSeparator($content, $separator) {}
    }
}
if (!class_exists('JsonExport', false)) {
    class JsonExport
    {
        public function header($params) { return ''; }
        public function separator($params) { return ','; }
        public function footer($params) { return ''; }
    }
}
if (!class_exists('SightingOrgFilterFakeAttribute', false)) {
    class SightingOrgFilterFakeAttribute
    {
        public function setTimestampConditions($range, $conditions, $scope)
        {
            return $conditions;
        }
    }
}
if (!class_exists('SightingOrgFilterFakeOrganisation', false)) {
    class SightingOrgFilterFakeOrganisation
    {
        public function find($type, $options)
        {
            $uuids = [
                'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' => 9101,
                'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' => 9102,
            ];
            $uuid = $options['conditions']['Organisation.uuid'];
            return isset($uuids[$uuid]) ? ['Organisation' => ['id' => $uuids[$uuid]]] : [];
        }
    }
}
require_once __DIR__ . '/../Model/Sighting.php';

class SightingOrgFilterTestModel extends Sighting
{
    public $Attribute;
    public $Organisation;
    public $capturedConditions;

    public function __construct()
    {
        $this->Attribute = new SightingOrgFilterFakeAttribute();
        $this->Organisation = new SightingOrgFilterFakeOrganisation();
    }

    public function find($type, $options = [])
    {
        if ($type !== 'column') {
            throw new RuntimeException('Unexpected query type: ' . $type);
        }
        $this->capturedConditions = $options['conditions'];
        return [];
    }
}
