<?php

class StixExport
{
    public $additional_params = array(
        'includeEventTags' => 1,
        'includeGalaxy' => 1
    );
    protected $__return_format = 'json';
    protected $__scripts_dir = APP . 'files/scripts/';
    protected $__tmp_dir = APP . 'files/scripts/tmp/';
    protected $__framing_script = APP . 'files/scripts/misp_framing.py';
    protected $__end_of_cmd = ' 2>' . APP . 'tmp/logs/exec-errors.log';
    protected $__return_type = null;
    protected $__filenames = array();
    protected $__default_filters = null;
    protected $__version = null;
    protected $__scope = null;

    private $__cluster_uuids = array();
    private $__converter = null;
    private $__current_filename = null;
    private $__empty_file = true;
    private $__event_galaxies = array();
    private $__framing = null;
    private $__stix_file = null;
    private $__tmp_file = null;
    private $__n_attributes = 0;

    public $non_restrictive_export = true;
    public $use_default_filters = true;

    public function setDefaultFilters($filters)
    {
        $sane_version = (!empty($filters['stix-version']) && in_array($filters['stix-version'], $this->__sane_versions));
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
        App::uses('JSONConverterTool', 'Tools');
        $this->__converter = new JSONConverterTool();
        $this->__scope = $options['scope'];
        $this->__return_type = $options['returnFormat'];
        if ($this->__return_type == 'stix-json') {
            $this->__return_type = 'stix';
        } else if ($this->__return_type == 'stix') {
            $this->__return_format = 'xml';
        }
        $framing_cmd = $this->__initiate_framing_params();
        $randomFileName = $this->__generateRandomFileName();
        $this->__framing = json_decode(shell_exec($framing_cmd), true);
        $this->__stix_file = new File($this->__tmp_dir . $randomFileName . '.' . $this->__return_type);
        unset($randomFileName);
        $this->__stix_file->write($this->__framing['header']);
        $this->__initialize_misp_file();
        return '';
    }

    public function footer()
    {
        if ($this->__empty_file) {
            $this->__tmp_file->close();
            $this->__tmp_file->delete();
        } else {
            if (!empty($this->__event_galaxies)) {
                $this->__write_event_galaxies();
            }
            $this->__tmp_file->append($this->__scope === 'Attribute' ? ']}}' : ']}');
            $this->__tmp_file->close();
            $this->__filenames[] = $this->__current_filename;
        }
        $filenames = implode(' ' . $this->__tmp_dir, $this->__filenames);
        $result = $this->__parse_misp_data($filenames);
        $decoded = json_decode($result, true);
        if (!isset($decoded['success']) || !$decoded['success']) {
            $this->__delete_temporary_files();
            $error = !empty($decoded['error']) ? $decoded['error'] : $result;
            return 'Error while processing your query: ' . $error;
        }
        foreach ($this->__filenames as $f => $filename) {
            $file = new File($this->__tmp_dir . $filename . '.out');
            $stix_event = ($this->__return_type == 'stix') ? $file->read() : substr($file->read(), 1, -1);
            $file->close();
            $file->delete();
            @unlink($this->__tmp_dir . $filename);
            $this->__stix_file->append($stix_event . $this->__framing['separator']);
            unset($stix_event);
        }
        $stix_event = $this->__stix_file->read();
        $this->__stix_file->close();
        $this->__stix_file->delete();
        $sep_len = strlen($this->__framing['separator']);
        $stix_event = (empty($this->__filenames) ? $stix_event : substr($stix_event, 0, -$sep_len)) . $this->__framing['footer'];
        return $stix_event;
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
                    if (substr($tag_name, 0, 12) === 'misp-galaxy:') {
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
                    if (substr($tag_name, 0, 12) === 'misp-galaxy:') {
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
        $event = $this->__converter->convert($event);
        if ($this->__n_attributes + $attributes_count <= $this->__attributes_limit) {
            $this->__tmp_file->append($this->__n_attributes == 0 ? $event : ', ' . $event);
            $this->__n_attributes += $attributes_count;
            $this->__empty_file = false;
        } else {
            if ($attributes_count > $this->__attributes_limit) {
                $randomFileName = $this->__generateRandomFileName();
                $tmpFile = new File($this->__tmp_dir . $randomFileName, true, 0644);
                $tmpFile->write($event);
                $tmpFile->close();
                $this->__filenames[] = $randomFileName;
            } else {
                $this->__terminate_misp_file($event);
                $this->__n_attributes = $attributes_count;
            }
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
        $this->__current_filename = $this->__generateRandomFileName();
        $this->__tmp_file = new File($this->__tmp_dir . $this->__current_filename, true, 0644);
        $this->__tmp_file->write('{"response": ' . ($this->__scope === 'Attribute' ? '{"Attribute": [' : '['));
        $this->__empty_file = true;
    }

    private function __generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }

    private function __delete_temporary_files()
    {
        foreach ($this->__filenames as $f => $filename) {
            @unlink($this->__tmp_dir . $filename);
        }
        $this->__stix_file->close();
        $this->__stix_file->delete();
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
        $this->__filenames[] = $this->__current_filename;
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
}
