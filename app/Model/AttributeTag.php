<?php
App::uses('AppModel', 'Model');

class AttributeTag extends AppModel {

	public $actsAs = array('Containable');

	public $validate = array(
		'attribute_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
		'tag_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
	);

	public $belongsTo = array(
		'Attribute' => array(
			'className' => 'Attribute',
		),
		'Tag' => array(
			'className' => 'Tag',
		),
	);

	public function afterSave($created, $options = array()) {
		parent::afterSave($created, $options);
		if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable')) {
			$pubSubTool = $this->getPubSubTool();
			$tag = $this->find('first', array(
				'recursive' => -1,
				'conditions' => array('AttributeTag.id' => $this->id),
				'contain' => array('Tag')
			));
			$tag['Tag']['attribute_id'] = $tag['AttributeTag']['attribute_id'];
			$tag['Tag']['event_id'] = $tag['AttributeTag']['event_id'];
			$tag = array('Tag' => $tag['Tag']);
			$pubSubTool->tag_save($tag, 'attached to attribute');
		}
	}

	public function beforeDelete($cascade = true) {
		if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_tag_notifications_enable')) {
			if (!empty($this->id)) {
				$pubSubTool = $this->getPubSubTool();
				$tag = $this->find('first', array(
					'recursive' => -1,
					'conditions' => array('AttributeTag.id' => $this->id),
					'contain' => array('Tag')
				));
				$tag['Tag']['attribute_id'] = $tag['AttributeTag']['attribute_id'];
				$tag['Tag']['event_id'] = $tag['AttributeTag']['event_id'];
				$tag = array('Tag' => $tag['Tag']);
				$pubSubTool->tag_save($tag, 'detached from attribute');
			}
		}
	}

	public function attachTagToAttribute($attribute_id, $event_id, $tag_id) {
		$existingAssociation = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array(
				'tag_id' => $tag_id,
				'attribute_id' => $attribute_id
			)
		));
		if (empty($existingAssociation)) {
			$this->create();
			if (!$this->save(array('attribute_id' => $attribute_id, 'event_id' => $event_id, 'tag_id' => $tag_id))) return false;
		}
		return true;
	}

	public function countForTag($tag_id, $user) {
		$db = $this->getDataSource();
		$subQuery = $db->buildStatement(
			array(
				'fields' => array('AttributeTag.attribute_id'),
				'table' => 'attribute_tags',
				'alias' => 'AttributeTag',
				'limit' => null,
				'offset' => null,
				'joins' => array(),
				'conditions' => array(
					'AttributeTag.tag_id' => $tag_id
				),
			),
			$this
		);
		$subQuery = 'Attribute.id IN (' . $subQuery . ') ';
		$conditions = array($db->expression($subQuery)->value);
		if (!$user['Role']['perm_site_admin']) {
			$conditions = array_merge(
				$conditions,
				array(
					'OR' => array(
						'Event.orgc_id' => $user['org_id'],
						'AND' => array(
							array(
								'OR' => array(
									'Event.distribution' => array(1, 2, 3),
								)
							),
							array(
								'OR' => array(
									'Attribute.distribution' => array(1, 2, 3, 5)
								)
							)
						)
					)
				)
			);
			if (!empty($sgids)) {
				$conditions['OR']['AND'][0]['OR'][] = array('AND' => array(
					'Event.distribution' => 4,
					'Event.sharing_group_id' => $sgids
				));
				$conditions['OR']['AND'][1]['OR'][] = array('AND' => array(
					'Attribute.distribution' => 4,
					'Attribute.sharing_group_id' => $sgids
				));
			}
		}
		return $this->Attribute->find('count', array(
			'fields' => array('Attribute.id', 'Attribute.distribution', 'Attribute.orgc_id', 'Attribute.sharing_group_id', 'Event.distribution', 'Event.sharing_group_id'),
			'conditions' => $conditions
		));
	}
}
