<?php
App::uses('AppModel', 'Model');
class Galaxy extends AppModel{

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

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}
	
	public function beforeDelete($cascade = true) {
		$this->GalaxyCluster->deleteAll(array('GalaxyCluster.galaxy_id' => $this->id));
	}

	private function __load_galaxies() {
		$dir = new Folder(APP . 'files' . DS . 'misp-galaxy' . DS . 'galaxies');
		$files = $dir->find('.*\.json');
		$galaxies = array();
		foreach ($files as $file) {
			$file = new File($dir->pwd() . DS . $file);
			$galaxies[] = json_decode($file->read(), true);
			$file->close();
		}
		foreach ($galaxies as $galaxy) {
			$this->deleteAll(array('Galaxy.type' => $galaxy['type']));
		}
		$this->saveMany($galaxies);
		return $this->find('list', array('recursive' => -1, 'fields' => array('type', 'id')));
	}
	
	public function update() {
		$galaxies = $this->__load_galaxies();
		$dir = new Folder(APP . 'files' . DS . 'misp-galaxy' . DS . 'clusters');
		$files = $dir->find('.*\.json');
		$cluster_packages = array();
		foreach ($files as $file) {
			$file = new File($dir->pwd() . DS . $file);
			$cluster_packages[] = json_decode($file->read(), true);
			$file->close();
		}
		foreach ($cluster_packages as $cluster_package) {
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
			foreach ($cluster_package['values'] as $cluster) {
				$this->GalaxyCluster->create();
				$cluster_to_save = $template;
				if (isset($cluster['description'])) {
					$cluster_to_save['description'] = $cluster['description'];
					unset($cluster['description']);
				}
				$cluster_to_save['value'] = $cluster['value'];
				$cluster_to_save['tag_name'] = $cluster_to_save['tag_name'] . $cluster['value'] . '"';
				unset($cluster['value']);
				$this->GalaxyCluster->save($cluster_to_save);
				$galaxyClusterId = $this->GalaxyCluster->id;
				$elements = array();
				if (isset($cluster['meta'])) {
					foreach ($cluster['meta'] as $key => $value) {
						if (is_array($value)) {
							foreach ($value as $v) {
								$elements[] = array(
									'galaxy_cluster_id' => $galaxyClusterId,
									'key' => $key,
									'value' => $v		
								);
							}
						} else {
							$elements[] = array(
								'galaxy_cluster_id' => $this->GalaxyCluster->id,
								'key' => $key,
								'value' => $value
							);
						}
					}
				}
				$this->GalaxyCluster->GalaxyElement->saveMany($elements);
			}
		}
		return true;
	}	
}
