<?php
App::uses('AppModel', 'Model');
class Galaxy extends AppModel
{
    public $useTable = 'galaxies';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
    );

    public $hasMany = array(
        'GalaxyCluster' => array('dependent' => true)
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

    public function beforeDelete($cascade = true)
    {
        $this->GalaxyCluster->deleteAll(array('GalaxyCluster.galaxy_id' => $this->id));
    }

    private function __load_galaxies($force = false)
    {
        $dir = new Folder(APP . 'files' . DS . 'misp-galaxy' . DS . 'galaxies');
        $files = $dir->find('.*\.json');
        $galaxies = array();
        foreach ($files as $file) {
            $file = new File($dir->pwd() . DS . $file);
            $galaxies[] = json_decode($file->read(), true);
            $file->close();
        }
        $galaxyTypes = array();
        foreach ($galaxies as $galaxy) {
            $galaxyTypes[$galaxy['type']] = $galaxy['type'];
        }
        $temp = $this->find('all', array(
            'fields' => array('uuid', 'version', 'id', 'icon'),
            'recursive' => -1
        ));
        $existingGalaxies = array();
        foreach ($temp as $k => $v) {
            $existingGalaxies[$v['Galaxy']['uuid']] = $v['Galaxy'];
        }
        foreach ($galaxies as $k => $galaxy) {
            if (isset($existingGalaxies[$galaxy['uuid']])) {
                if (
                    $force ||
                    $existingGalaxies[$galaxy['uuid']]['version'] < $galaxy['version'] ||
                    (!empty($galaxy['icon']) && ($existingGalaxies[$galaxy['uuid']]['icon'] != $galaxy['icon']))
                ) {
                    $galaxy['id'] = $existingGalaxies[$galaxy['uuid']]['id'];
                    $this->save($galaxy);
                }
            } else {
                $this->create();
                $this->save($galaxy);
            }
        }
        return $this->find('list', array('recursive' => -1, 'fields' => array('type', 'id')));
    }

    public function update($force = false)
    {
        $galaxies = $this->__load_galaxies($force);
        $dir = new Folder(APP . 'files' . DS . 'misp-galaxy' . DS . 'clusters');
        $files = $dir->find('.*\.json');
        $cluster_packages = array();
        foreach ($files as $file) {
            $file = new File($dir->pwd() . DS . $file);
            $cluster_package = json_decode($file->read(), true);
            $file->close();
            if (!isset($galaxies[$cluster_package['type']])) {
                continue;
            }
            $template = array(
                'source' => isset($cluster_package['source']) ? $cluster_package['source'] : '',
                'authors' => json_encode(isset($cluster_package['authors']) ? $cluster_package['authors'] : array(), true),
                'uuid' => isset($cluster_package['uuid']) ? $cluster_package['uuid'] : '',
                'galaxy_id' => $galaxies[$cluster_package['type']],
                'type' => $cluster_package['type'],
                'tag_name' => 'misp-galaxy:' . $cluster_package['type'] . '="'
            );
            $elements = array();
            $temp = $this->GalaxyCluster->find('all', array(
                'conditions' => array(
                    'GalaxyCluster.galaxy_id' => $galaxies[$cluster_package['type']]
                ),
                'recursive' => -1,
                'fields' => array('version', 'id', 'value', 'uuid')
            ));
            $existingClusters = array();
            foreach ($temp as $k => $v) {
                $existingClusters[$v['GalaxyCluster']['value']] = $v;
            }
            $clusters_to_delete = array();

            // Delete all existing outdated clusters
            foreach ($cluster_package['values'] as $k => $cluster) {
                if (empty($cluster['value'])) {
                    debug($cluster);
                    throw new Exception();
                }
                if (isset($cluster['version'])) {
                } elseif (!empty($cluster_package['version'])) {
                    $cluster_package['values'][$k]['version'] = $cluster_package['version'];
                } else {
                    $cluster_package['values'][$k]['version'] = 0;
                }
                if (!empty($existingClusters[$cluster['value']])) {
                    if ($force || $existingClusters[$cluster['value']]['GalaxyCluster']['version'] < $cluster_package['values'][$k]['version']) {
                        $clusters_to_delete[] = $existingClusters[$cluster['value']]['GalaxyCluster']['id'];
                    } else {
                        unset($cluster_package['values'][$k]);
                    }
                }
            }
            if (!empty($clusters_to_delete)) {
                $this->GalaxyCluster->GalaxyElement->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $clusters_to_delete), false, false);
                $this->GalaxyCluster->delete($clusters_to_delete, false, false);
            }

            // create all clusters
            foreach ($cluster_package['values'] as $cluster) {
                $template['version'] = $cluster['version'];
                $this->GalaxyCluster->create();
                $cluster_to_save = $template;
                if (isset($cluster['description'])) {
                    $cluster_to_save['description'] = $cluster['description'];
                    unset($cluster['description']);
                }
                $cluster_to_save['value'] = $cluster['value'];
                $cluster_to_save['tag_name'] = $cluster_to_save['tag_name'] . $cluster['value'] . '"';
                unset($cluster['value']);
                if (empty($cluster_to_save['description'])) {
                    $cluster_to_save['description'] = '';
                }
                $result = $this->GalaxyCluster->save($cluster_to_save, false);
                $galaxyClusterId = $this->GalaxyCluster->id;
                if (isset($cluster['meta'])) {
                    foreach ($cluster['meta'] as $key => $value) {
                        if (is_array($value)) {
                            foreach ($value as $v) {
                                $elements[] = array(
                                    $galaxyClusterId,
                                    $key,
                                    $v
                                );
                            }
                        } else {
                            $elements[] = array(
                                $this->GalaxyCluster->id,
                                $key,
                                $value
                            );
                        }
                    }
                }
            }
            $db = $this->getDataSource();
            $fields = array('galaxy_cluster_id', 'key', 'value');
            if (!empty($elements)) {
                $db->insertMulti('galaxy_elements', $fields, $elements);
            }
        }
        return true;
    }

    public function attachCluster($user, $target_type, $target_id, $cluster_id)
    {
        $cluster = $this->GalaxyCluster->find('first', array('recursive' => -1, 'conditions' => array('id' => $cluster_id), 'fields' => array('tag_name', 'id', 'value')));
        $this->Tag = ClassRegistry::init('Tag');
        if ($target_type == 'event') {
            $event = $this->Tag->EventTag->Event->fetchEvent($user, array('eventid' => $target_id, 'metadata' => 1));
            if (empty($event)) {
                throw new NotFoundException('Invalid event.');
            }
            $event = $event[0];
            $tag_id = $this->Tag->captureTag(array('name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1), $user);
            if ($tag_id === false) {
                throw new MethodNotAllowedException('Could not attach cluster.');
            }
            $this->Tag->EventTag->create();
            $existingTag = $this->Tag->EventTag->find('first', array('conditions' => array('event_id' => $target_id, 'tag_id' => $tag_id)));
            if (!empty($existingTag)) {
                return 'Cluster already attached.';
            }
            $result = $this->Tag->EventTag->save(array('event_id' => $target_id, 'tag_id' => $tag_id));
        } elseif ($target_type == 'attribute') {
            $attribute = $this->Tag->AttributeTag->Attribute->fetchAttributes($user, array('conditions' => array('Attribute.id' => $target_id), 'flatten' => 1));
            if (empty($attribute)) {
                throw new NotFoundException('Invalid attribute.');
            }
            $attribute = $attribute[0];
            $tag_id = $this->Tag->captureTag(array('name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1), $user);
            if ($tag_id === false) {
                throw new MethodNotAllowedException('Could not attach cluster.');
            }
            $this->Tag->AttributeTag->create();
            $existingTag = $this->Tag->AttributeTag->find('first', array('conditions' => array('attribute_id' => $target_id, 'tag_id' => $tag_id)));
            if (!empty($existingTag)) {
                return 'Cluster already attached.';
            }
            $event = $this->Tag->EventTag->Event->find('first', array(
                'conditions' => array(
                    'Event.id' => $attribute['Attribute']['event_id']
                ),
                'recursive' => -1
            ));
            $result = $this->Tag->AttributeTag->save(array('attribute_id' => $target_id, 'tag_id' => $tag_id, 'event_id' => $attribute['Attribute']['event_id']));
        }
        if ($result) {
            $this->Tag->EventTag->Event->insertLock($user, $event['Event']['id']);
            $event['Event']['published'] = 0;
            $date = new DateTime();
            $event['Event']['timestamp'] = $date->getTimestamp();
            $this->Tag->EventTag->Event->save($event);
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                'org' => $user['Organisation']['name'],
                'model' => ucfirst($target_type),
                'model_id' => $target_id,
                'email' => $user['email'],
                'action' => 'galaxy',
                'title' => 'Attached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') to ' . $target_type . ' (' . $target_id . ')',
                'change' => ''
            ));
            return 'Cluster attached.';
        }
        return 'Could not attach the cluster';
    }

    public function getMitreAttackGalaxyId($type="mitre-enterprise-attack-attack-pattern")
    {
        $galaxy = $this->find('first', array(
                'recursive' => -1,
                'fields' => 'id',
                'conditions' => array('Galaxy.type' => $type),
        ));
        return empty($galaxy) ? 0 : $galaxy['Galaxy']['id'];
    }

    public function getMitreAttackMatrix()
    {
        $killChainOrderEnterprise = array(
            'initial-access',
            'execution',
            'persistence',
            'privilege-escalation',
            'defense-evasion',
            'credential-access',
            'discovery',
            'lateral-movement',
            'collection',
            'exfiltration',
            'command-and-control'
        );
        $killChainOrderMobile = array(
            'persistence',
            'privilege-escalation',
            'defense-evasion',
            'credential-access',
            'discovery',
            'lateral-movement',
            'effects', 'collection',
            'exfiltration',
            'command-and-control',
            'general-network-based',
            'cellular-network-based',
            'could-based'
        );
        $killChainOrderPre = array(
            'priority-definition-planning',
            'priority-definition-direction',
            'target-selection',
            'technical-information-gathering',
            'people-information-gathering',
            'organizational-information-gathering',
            'technical-weakness-identification',
            'people-weakness-identification',
            'organizational-weakness-identification',
            'adversary-opsec',
            'establish-&-maintain-infrastructure',
            'persona-development',
            'build-capabilities',
            'test-capabilities',
            'stage-capabilities',
            'app-delivery-via-authorized-app-store',
            'app-delivery-via-other-means',
            'exploit-via-cellular-network',
            'exploit-via-internet',
        );

        $killChainOrders = array(
            'mitre-enterprise-attack-attack-pattern' => $killChainOrderEnterprise,
            'mitre-mobile-attack-attack-pattern' => $killChainOrderMobile,
            'mitre-pre-attack-attack-pattern' => $killChainOrderPre,
        );

        $expectedDescription = 'ATT&CK Tactic';
        $expectedNamespace = 'mitre-attack';
        $conditions = array('Galaxy.description' => $expectedDescription, 'Galaxy.namespace' => $expectedNamespace);
        $contains = array(
            'GalaxyCluster' => array('GalaxyElement'),
        );

        $galaxies = $this->find('all', array(
                'recursive' => -1,
                'contain' => $contains,
                'conditions' => $conditions,
        ));

        $mispUUID = Configure::read('MISP')['uuid'];

        $attackTactic = array(
            'killChain' => $killChainOrders,
            'attackTactic' => array(),
            'attackTags' => array(),
            'instance-uuid' => $mispUUID
        );

        foreach ($galaxies as $galaxy) {
            $galaxyType = $galaxy['Galaxy']['type'];
            $clusters = $galaxy['GalaxyCluster'];
            $attackClusters = array();
            // add cluster if kill_chain is present
            foreach ($clusters as $cluster) {
                if (empty($cluster['GalaxyElement'])) {
                    continue;
                }
                $toBeAdded = false;
                $clusterType = $cluster['type'];
                $galaxyElements = $cluster['GalaxyElement'];
                foreach ($galaxyElements as $element) {
                    if ($element['key'] == 'kill_chain') {
                        $kc = explode(":", $element['value'])[2];
                        $toBeAdded = true;
                    }
                    if ($element['key'] == 'external_id') {
                        $cluster['external_id'] = $element['value'];
                    }
                }
                if ($toBeAdded) {
                    $attackClusters[$kc][] = $cluster;
                    array_push($attackTactic['attackTags'], $cluster['tag_name']);
                }
            }
            $attackTactic['attackTactic'][$galaxyType] = array(
                'clusters' => $attackClusters,
                'galaxy' => $galaxy['Galaxy'],
            );
        }

        return $attackTactic;
    }
}
