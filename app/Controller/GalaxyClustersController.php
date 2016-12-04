<?php
App::uses('AppController', 'Controller');

class GalaxyClustersController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'recursive' => -1,
			'order' => array(
				'GalaxyCluster.value' => 'ASC'
			),
			'contain' => array(
				'GalaxyElement' => array(
					'conditions' => array('GalaxyElement.key' => 'synonyms'),
					'fields' => array('value')
				)
			)
	);

	public function index($id) {
		$this->paginate['conditions'] = array('GalaxyCluster.galaxy_id' => $id);
		$clusters = $this->paginate();
		if (!empty($clusters)) {
			$galaxyType = $clusters[0]['GalaxyCluster']['type'];
			$tagPattern = 'misp-galaxy:' . $galaxyType . '="%s"';
			$tags = $this->GalaxyCluster->getTags($galaxyType, false, $this->Auth->user());
			foreach ($clusters as $k => $v) {
				$clusters[$k]['GalaxyCluster']['synonyms'] = array();
				foreach ($v['GalaxyElement'] as $element) {
					$clusters[$k]['GalaxyCluster']['synonyms'][] = $element['value'];
				}
				if (isset($tags[sprintf($tagPattern, $v['GalaxyCluster']['value'])])) {
					$clusters[$k]['GalaxyCluster']['tags'] = $tags[sprintf($tagPattern, $v['GalaxyCluster']['value'])];
				} else {
					$clusters[$k]['GalaxyCluster']['tags'] = 0;
				}
			}
		}
		$this->set('list', $clusters);
		if ($this->request->is('ajax')) {
			$this->layout = 'ajax';
			$this->render('ajax/index');
		}
	}
	
	public function view($id) {
		$cluster = $this->GalaxyCluster->find('first', array(
			'recursive' => -1,
			'contain' => array('Galaxy'),
			'conditions' => array('GalaxyCluster.id' => $id)
		));
		if (!empty($cluster)) {
			$galaxyType = $cluster['GalaxyCluster']['type'];
			$this->loadModel('Tag');
			$tag = $this->Tag->find('first', array(
					'conditions' => array(
							'name' => $cluster['GalaxyCluster']['tag_name']
					),
					'fields' => array('id'),
					'recursive' => -1,
					'contain' => array('EventTag.tag_id')
			));
			if (!empty($tag)) {
				$cluster['GalaxyCluster']['tag_count'] = count($tag['EventTag']);
				$cluster['GalaxyCluster']['tag_id'] = $tag['Tag']['id'];
			}	
		}
		$this->set('cluster', $cluster);
	}
}
