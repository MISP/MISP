<?php
App::uses('AppModel', 'Model');

class Job extends AppModel
{
    public $belongsTo = array(
            'Org' => array(
                    'className' => 'Organisation',
                    'foreignKey' => 'org_id',
                    'order' => array(),
                    'fields' => array('id', 'name', 'uuid')
            ),
        );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        $date = date('Y-m-d H:i:s');
        if (empty($this->data['Job']['id'])) {
            $this->data['Job']['date_created'] = $date;
            $this->data['Job']['date_modified'] = $date;
        } else {
            $this->data['Job']['date_modified'] = $date;
        }
    }

    public function cache($type, $user)
    {
        $extra = null;
        $extra2 = null;
        $shell = 'Event';
        $this->create();
        $data = array(
                'worker' => 'cache',
                'job_type' => 'cache_' . $type,
                'job_input' => $user['Role']['perm_site_admin'] ? 'All events.' : 'Events visible to: ' . $user['Organisation']['name'],
                'status' => 0,
                'retries' => 0,
                'org_id' => $user['Role']['perm_site_admin'] ? 0 : $user['org_id'],
                'message' => 'Fetching events.',
        );
		$this->save($data);
		$id = $this->id;
		$this->Event = ClassRegistry::init('Event');
		if (in_array($type, array_keys($this->Event->export_types))) {
			$process_id = CakeResque::enqueue(
					'cache',
					$shell . 'Shell',
					array('cache', $user['id'], $id, $type),
					true
			);
		} else if ($type === 'bro') {
            $extra = $type;
            $type = 'bro';
            $extra2 = isset($user['nids_sid']) ? $user['nids_sid'] : 0;
			$process_id = CakeResque::enqueue(
					'cache',
					$shell . 'Shell',
					array('cache' . $type, $user['id'], $id, $extra, $extra2),
					true
			);
        } else {
			throw new MethodNotAllowedException('Invalid export type.');
		}
        $this->saveField('process_id', $process_id);
        return $id;
    }
}
