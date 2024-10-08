<?php
App::uses('JSONConverterTool', 'Tools');
App::uses('TmpFileTool', 'Tools');
App::uses('JsonTool', 'Tools');
App::uses('ProcessTool', 'Tools');

abstract class StixExport
{
    const SCRIPTS_DIR = APP . 'files/scripts/',
        FRAMING_SCRIPT = APP . 'files/scripts/misp_framing.py';

    public $additional_params = array(
        'includeEventTags' => 1,
        'includeGalaxy' => 1
    );
    protected $__return_format = 'json';
    protected $__return_type = null;

    /** @var array Full paths to files to convert */
    protected $__filenames = array();
    protected $__version = null;
    protected $__scope = null;
    protected $stixFile = null;

    private $__cluster_uuids = array();
    private $__empty_file = null;
    private $__event_galaxies = array();
    /** @var File */
    private $__tmp_file = null;
    private $__n_attributes = 0;

    public $non_restrictive_export = true;

    public function setDefaultFilters($filters)
    {
        $sane_version = !empty($filters['stix-version']) && in_array($filters['stix-version'], $this->__sane_versions, true);
        $this->__version = $sane_version ? $filters['stix-version'] : $this->__default_version;
    }

    public function handler($data, $options = array())
    {
        if ($this->__scope === 'Attribute') {
            return $this->__attributesHandler($data);
        }
        if ($this->__scope === 'Event') {
            return $this->__eventsHandler($data);
        }
        return '';
    }

    public function modify_params($user, $params)
    {
        if (empty($params['contain'])) {
            $params['contain'] = array();
        }
        $params['contain'] = array_merge($params['contain'], array(
            'AttributeTag' => array('Tag'),
            'Event' => array('fields' => array('Event.timestamp'), 'Org.name', 'Org.uuid', 'Orgc.name', 'Orgc.uuid')
        ));
        unset($params['fields']);
        $params['includeContext'] = 0;
        return $params;
    }

    public function header($options = array())
    {
        $this->__scope = $options['scope'];
        $this->__return_type = $options['returnFormat'];
        if ($this->__return_type === 'stix-json') {
            $this->__return_type = 'stix';
        } else if ($this->__return_type === 'stix') {
            $this->__return_format = 'xml';
        }
        $this->__initialize_misp_file();
        return '';
    }

    /**
     * @return TmpFileTool
     * @throws Exception
     */
    public function footer()
    {
        if ($this->__empty_file) {
            $this->__tmp_file->close();
            $this->__tmp_file->delete();
            if (empty($this->__filenames)) {
                $framing = $this->getFraming();
                $tmpFile = new TmpFileTool();
                $tmpFile->write($framing['header'] . $framing['footer']);
                return $tmpFile;
            }
        } else {
            if (!empty($this->__event_galaxies)) {
                $this->__write_event_galaxies();
            }
            $this->__tmp_file->append($this->__scope === 'Attribute' ? ']}}' : ']}');
            $this->__tmp_file->close();
            $this->__filenames[] = $this->__tmp_file->path;
        }
        $result = $this->__parse_misp_data();
        $decoded = JsonTool::decode($result);
        if (!isset($decoded['success']) || !$decoded['success']) {
            if (!empty($decoded['filenames'])) {
                $this->__delete_temporary_files(false, $decoded['filename']);
            } else {
                $this->__delete_temporary_files(true);
            }
            $error = $decoded && !empty($decoded['error']) ? $decoded['error'] : $result;
            throw new Exception('Error while processing your query during STIX export: ' . $error);
        }
        $this->__delete_temporary_files();
        $framing = $this->getFraming();
        $this->stixFile = new TmpFileTool();
        $this->stixFile->write($framing['header']);
        $separator = $framing['separator'];
        if (!empty($decoded['filenames'])) {
            foreach ($decoded['filenames'] as $filename) {
                $this->__write_stix_content($filename, $separator);
            }
        } else {
            foreach ($this->__filenames as $filename) {
                $this->__write_stix_content($filename . '.out', $separator);
            }
        }
        $this->stixFile->write($framing['footer']);
        return $this->stixFile;
    }

    public function separator()
    {
        return '';
    }

    private function __addMetadataToAttribute($raw_attribute)
    {
        $attribute = $raw_attribute['Attribute'];
        if (isset($attribute['SharingGroup']) && empty($attribute['SharingGroup'])) {
            unset($attribute['SharingGroup']);
        }
        unset($attribute['value1']);
        unset($attribute['value2']);
        if (!empty($raw_attribute['Galaxy'])) {
            $galaxies = array(
                'Attribute' => array(),
                'Event' => array()
            );
            if (!empty($raw_attribute['AttributeTag'])) {
                $tags = array();
                foreach($raw_attribute['AttributeTag'] as $tag) {
                    $tag_name = $tag['Tag']['name'];
                    if (str_starts_with($tag_name, 'misp-galaxy:')) {
                        $this->__merge_galaxy_tag($galaxies['Attribute'], $tag_name);
                    } else {
                        $tags[] = $tag['Tag'];
                    }
                }
                if (!empty($tags)) {
                    $attribute['Tag'] = $tags;
                }
            }
            if (!empty($raw_attribute['EventTag'])) {
                foreach($raw_attribute['EventTag'] as $tag) {
                    $tag_name = $tag['Tag']['name'];
                    if (str_starts_with($tag_name, 'misp-galaxy:')) {
                        $this->__merge_galaxy_tag($galaxies['Event'], $tag_name);
                    }
                }
            }
            if (!empty($galaxies['Attribute'])) {
                $attribute['Galaxy'] = array();
            }
            $timestamp = $raw_attribute['Event']['timestamp'];
            foreach($raw_attribute['Galaxy'] as $galaxy) {
                $galaxy_type = $galaxy['type'];
                if (!empty($galaxies['Attribute'][$galaxy_type])) {
                    if (empty($galaxies['Event'][$galaxy_type])) {
                        $attribute['Galaxy'][] = $this->__arrange_galaxy($galaxy, $attribute['timestamp']);
                        unset($galaxies['Attribute'][$galaxy_type]);
                        continue;
                    }
                    $in_attribute = array();
                    $in_event = array();
                    foreach($galaxy['GalaxyCluster'] as $cluster) {
                        $cluster_value = $cluster['value'];
                        $in_attribute[] = in_array($cluster_value, $galaxies['Attribute'][$galaxy_type]);
                        $in_event[] = in_array($cluster_value, $galaxies['Event'][$galaxy_type]);
                    }
                    if (!in_array(false, $in_attribute)) {
                        $attribute['Galaxy'][] = $this->__arrange_galaxy($galaxy, $attribute['timestamp']);
                        unset($galaxies['Attribute'][$galaxy_type]);
                        if (!in_array(false, $in_event)) {
                            $this->__handle_event_galaxies($galaxy, $timestamp);
                            unset($galaxies['Event'][$galaxy_type]);
                        }
                        continue;
                    }
                }
                if (!empty($galaxies['Event'][$galaxy_type])) {
                    $this->__handle_event_galaxies($galaxy, $timestamp);
                    unset($galaxies['Event'][$galaxy_type]);
                }
            }
        } else {
            if (!empty($raw_attribute['AttributeTag'])) {
                $attribute['Tag'] = array();
                foreach($raw_attribute['AttributeTag'] as $tag) {
                    $attribute['Tag'][] = $tag['Tag'];
                }
            }
        }
        $attribute['Org'] = $raw_attribute['Event']['Org'];
        $attribute['Orgc'] = $raw_attribute['Event']['Orgc'];
        return $attribute;
    }

    private function __arrange_cluster($cluster, $timestamp)
    {
        $arranged_cluster = array(
            'collection_uuid' => $cluster['collection_uuid'],
            'type' => $cluster['type'],
            'value' => $cluster['value'],
            'tag_name' => $cluster['tag_name'],
            'description' => $cluster['description'],
            'source' => $cluster['source'],
            'authors' => $cluster['authors'],
            'uuid' => $cluster['uuid'],
            'timestamp' => $timestamp
        );
        return $arranged_cluster;
    }

    private function __arrange_galaxy($galaxy, $timestamp)
    {
        $arranged_galaxy = array(
            'uuid' => $galaxy['uuid'],
            'name' => $galaxy['name'],
            'type' => $galaxy['type'],
            'description' => $galaxy['description'],
            'namespace' => $galaxy['namespace'],
            'GalaxyCluster' => array()
        );
        foreach($galaxy['GalaxyCluster'] as $cluster) {
            $arranged_galaxy['GalaxyCluster'][] = $this->__arrange_cluster($cluster, $timestamp);
        }
        return $arranged_galaxy;
    }

    private function __attributesHandler($attribute)
    {
        $attribute = json_encode($this->__addMetadataToAttribute($attribute));
        if ($this->__n_attributes < $this->__attributes_limit) {
            $this->__tmp_file->append($this->__n_attributes == 0 ? $attribute : ', ' . $attribute);
            $this->__n_attributes += 1;
            $this->__empty_file = false;
        } else {
            if (!empty($this->__event_galaxies)) {
                $this->__write_event_galaxies();
            }
            $this->__terminate_misp_file($attribute);
            $this->__n_attributes = 1;
        }
        return '';
    }

    private function __eventsHandler($event)
    {
        $attributes_count = count($event['Attribute']);
        foreach ($event['Object'] as $_object) {
            if (!empty($_object['Attribute'])) {
                $attributes_count += count($_object['Attribute']);
            }
        }
        $event = JsonTool::encode(JSONConverterTool::convert($event, false, true)); // we don't need pretty printed JSON
        if ($this->__n_attributes + $attributes_count <= $this->__attributes_limit) {
            $this->__tmp_file->append($this->__n_attributes == 0 ? $event : ', ' . $event);
            $this->__n_attributes += $attributes_count;
            $this->__empty_file = false;
        } elseif ($attributes_count > $this->__attributes_limit) {
            $filePath = FileAccessTool::writeToTempFile($event);
            $this->__filenames[] = $filePath;
        } else {
            $this->__terminate_misp_file($event);
            $this->__n_attributes = $attributes_count;
        }
        return '';
    }

    private function __handle_event_galaxies($galaxy, $timestamp)
    {
        $galaxy_type = $galaxy['type'];
        if (!empty($this->__event_galaxies[$galaxy['type']])) {
            foreach($galaxy['GalaxyCluster'] as $cluster) {
                if (!in_array($cluster['uuid'], $this->__cluster_uuids)) {
                    $this->__event_galaxies[$galaxy_type]['GalaxyCluster'][] = $this->__arrange_cluster(
                        $cluster,
                        $timestamp
                    );
                    $this->__cluster_uuids[] = $cluster['uuid'];
                }
            }
        } else {
            $this->__event_galaxies[$galaxy_type] = $this->__arrange_galaxy($galaxy, $timestamp);
            foreach($galaxy['GalaxyCluster'] as $cluster) {
                $this->__cluster_uuids[] = $cluster['uuid'];
            }
        }
    }

    private function __initialize_misp_file()
    {
        $tmpFile = FileAccessTool::createTempFile();
        $this->__tmp_file = new File($tmpFile);
        $this->__tmp_file->write('{"response": ' . ($this->__scope === 'Attribute' ? '{"Attribute": [' : '['));
        $this->__empty_file = true;
    }

    protected function __delete_temporary_files($removeOutput = false, $custom = null)
    {
        if (!is_null($custom)) {
            foreach ($custom as $filename) {
                FileAccessTool::deleteFileIfExists($filename);
            }
        }
        foreach ($this->__filenames as $filename) {
            FileAccessTool::deleteFileIfExists($filename);
            if ($removeOutput) {
                FileAccessTool::deleteFileIfExists($filename . '.out');
            }
        }
    }

    /**
     * @return array
     * @throws Exception
     */
    private function getFraming()
    {
        $framingCmd = $this->__initiate_framing_params();
        try {
            $framing = JsonTool::decode(ProcessTool::execute($framingCmd, null, true));
            if (isset($framing['error'])) {
                throw new Exception("Framing command error: " . $framing['error']);
            }
            return $framing;
        } catch (Exception $e) {
            throw new Exception("Could not get results from framing cmd when exporting STIX file.", 0, $e);
        }
    }

    private function __merge_galaxy_tag(&$galaxies, $tag_name)
    {
        list($galaxy_type, $value) = explode('=', explode(':', $tag_name)[1]);
        $value = substr($value, 1, -1);
        if (empty($galaxies[$galaxy_type])) {
            $galaxies[$galaxy_type] = array($value);
        } else {
            $galaxies[$galaxy_type][] = $value;
        }
    }

    private function __terminate_misp_file($content)
    {
        $this->__tmp_file->append($this->__scope === 'Attribute' ? ']}}' : ']}');
        $this->__tmp_file->close();
        $this->__filenames[] = $this->__tmp_file->path;
        $this->__initialize_misp_file();
        $this->__tmp_file->append($content);
    }

    private function __write_event_galaxies()
    {
        $this->__tmp_file->append('], "Galaxy": [');
        $galaxies = array();
        foreach($this->__event_galaxies as $type => $galaxy) {
            $galaxies[] = json_encode($galaxy);
        }
        $this->__tmp_file->append(implode(', ', $galaxies));
        $this->__event_galaxies = array();
    }

    private function __write_stix_content($filename, $separator)
    {
        $stix_content = FileAccessTool::readAndDelete($filename);
        if ($this->__return_type === 'stix2') {
            $stix_content = substr($stix_content, 1, -1);
        }
        $this->stixFile->writeWithSeparator($stix_content, $separator);
    }

    /**
     * @return string
     */
    abstract protected function __parse_misp_data();

    /**
     * @return array
     */
    abstract protected function __initiate_framing_params();
}
