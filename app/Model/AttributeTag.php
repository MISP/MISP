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
		return $this->find('count', array(
			'recursive' => -1,
			'conditions' => array('AttributeTag.tag_id' => $tag_id)
		));
	}
}
