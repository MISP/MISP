<?php
App::uses('AppModel', 'Model');
class Organisation extends AppModel{
	public $useTable = 'organisations';
    public $recursive = -1;
	public $actsAs = array(
		'Containable',
		'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
				'roleModel' => 'Organisation',
				'roleKey' => 'organisation_id',
				'change' => 'full'
		),
	);
	public $validate = array(
		'name' => array(
			'unique' => array(
				'rule' => 'isUnique',
				'message' => 'An organisation with this name already exists.'
			),
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
		'uuid' => array(
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'An organisation with this UUID already exists.',
            	'allowEmpty' => true
            ),
			'uuid' => array(
				'rule' => array('uuid'),
				'message' => 'Please provide a valid UUID',
				'allowEmpty' => true
			),
		)
	);
	public $hasMany = array(
		'User' => array(
			'className' => 'User',
			'foreignKey' => 'org_id'
		),
		'SharingGroupOrg' => array(
			'className' => 'SharingGroupOrg',
			'foreignKey' => 'org_id',
			'dependent'=> true,
		),
		'SharingGroup' => array(
			'className' => 'SharingGroup',
			'foreignKey' => 'org_id',
		),
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'orgc_id',
		),
		'EventOwned' => array(
			'className' => 'Event',
			'foreignKey' => 'org_id',
		),
	);

	public $countries = array('Not specified', 'International', 'Afghanistan', 'Albania', 'Algeria', 'Andorra', 'Angola', 'Antigua & Deps', 'Argentina', 'Armenia', 'Australia', 'Austria', 'Azerbaijan', 'Bahamas', 'Bahrain', 'Bangladesh', 'Barbados', 'Belarus', 'Belgium', 'Belize', 'Benin', 'Bhutan', 'Bolivia', 'Bosnia Herzegovina', 'Botswana', 'Brazil', 'Brunei', 'Bulgaria', 'Burkina', 'Burundi', 'Cambodia', 'Cameroon', 'Canada', 'Cape Verde', 'Central African Rep', 'Chad', 'Chile', 'China', 'Colombia', 'Comoros', 'Congo', 'Congo {Democratic Rep}', 'Costa Rica', 'Croatia', 'Cuba', 'Cyprus', 'Czech Republic', 'Denmark', 'Djibouti', 'Dominica', 'Dominican Republic', 'East Timor', 'Ecuador', 'Egypt', 'El Salvador', 'Equatorial Guinea', 'Eritrea', 'Estonia', 'Ethiopia', 'Fiji', 'Finland', 'France', 'Gabon', 'Gambia', 'Georgia', 'Germany', 'Ghana', 'Greece', 'Grenada', 'Guatemala', 'Guinea', 'Guinea-Bissau', 'Guyana', 'Haiti', 'Honduras', 'Hungary', 'Iceland', 'India', 'Indonesia', 'Iran', 'Iraq', 'Ireland {Republic}', 'Israel', 'Italy', 'Ivory Coast', 'Jamaica', 'Japan', 'Jordan', 'Kazakhstan', 'Kenya', 'Kiribati', 'Korea North', 'Korea South', 'Kosovo', 'Kuwait', 'Kyrgyzstan', 'Laos', 'Latvia', 'Lebanon', 'Lesotho', 'Liberia', 'Libya', 'Liechtenstein', 'Lithuania', 'Luxembourg', 'Macedonia', 'Madagascar', 'Malawi', 'Malaysia', 'Maldives', 'Mali', 'Malta', 'Marshall Islands', 'Mauritania', 'Mauritius', 'Mexico', 'Micronesia', 'Moldova', 'Monaco', 'Mongolia', 'Montenegro', 'Morocco', 'Mozambique', 'Myanmar, {Burma}', 'Namibia', 'Nauru', 'Nepal', 'Netherlands', 'New Zealand', 'Nicaragua', 'Niger', 'Nigeria', 'Norway', 'Oman', 'Pakistan', 'Palau', 'Panama', 'Papua New Guinea', 'Paraguay', 'Peru', 'Philippines', 'Poland', 'Portugal', 'Qatar', 'Romania', 'Russian Federation', 'Rwanda', 'St Kitts & Nevis', 'St Lucia', 'Saint Vincent & the Grenadines', 'Samoa', 'San Marino', 'Sao Tome & Principe', 'Saudi Arabia', 'Senegal', 'Serbia', 'Seychelles', 'Sierra Leone', 'Singapore', 'Slovakia', 'Slovenia', 'Solomon Islands', 'Somalia', 'South Africa', 'South Sudan', 'Spain', 'Sri Lanka', 'Sudan', 'Suriname', 'Swaziland', 'Sweden', 'Switzerland', 'Syria', 'Taiwan', 'Tajikistan', 'Tanzania', 'Thailand', 'Togo', 'Tonga', 'Trinidad & Tobago', 'Tunisia', 'Turkey', 'Turkmenistan', 'Tuvalu', 'Uganda', 'Ukraine', 'United Arab Emirates', 'United Kingdom', 'United States', 'Uruguay', 'Uzbekistan', 'Vanuatu', 'Vatican City', 'Venezuela', 'Vietnam', 'Yemen', 'Zambia', 'Zimbabwe');

	public $organisationAssociations = array(
			'Correlation' => array('table' => 'correlations', 'fields' => array('org_id')),
			'Event' => array('table' => 'events', 'fields' => array('org_id', 'orgc_id')),
			'Job' => array('table' => 'jobs', 'fields' => array('org_id')),
			'Server' => array('table' => 'servers', 'fields' => array('org_id', 'remote_org_id')),
			'ShadowAttribute' =>array('table' => 'shadow_attributes', 'fields' => array('org_id', 'event_org_id')),
			'SharingGroup' => array('table' => 'sharing_groups', 'fields' => array('org_id')),
			'SharingGroupOrg' => array('table' => 'sharing_group_orgs', 'fields' => array('org_id')),
			'Thread' => array('table' => 'threads', 'fields' => array('org_id')),
			'User' => array('table' => 'users', 'fields' => array('org_id'))
	);

	/*
	public $hasAndBelongsToMany = array(
		'SharingGroup' => array(
			'className' => 'SharingGroup',
			'joinTable' => 'organisations_sharing_groups',
			'foreignKey' => 'org_id',
			'associationForeignKey' => 'sharing_group_id',
		)
	);
	*/

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		if (empty($this->data['Organisation']['uuid']) && (isset($this->data['Organisation']['local']) && $this->data['Organisation']['local'])) {
			$this->data['Organisation']['uuid'] = $this->generateUuid();
		}
		$date = date('Y-m-d H:i:s');
		if (!isset($this->data['Organisation']['date_created']) || empty($this->data['Organisation']['date_created'])) $this->data['Organisation']['date_created'] = $date;
		$this->data['Organisation']['date_modified'] = $date;
		if (!isset($this->data['Organisation']['nationality']) || empty($this->data['Organisation']['nationality'])) $this->data['Organisation']['nationality'] = 'Not specified';
		return true;
	}

	public function beforeDelete($cascade = false) {
		if ($this->User->find('count', array('conditions' => array('User.org_id' => $this->id))) != 0) return false;
		if ($this->Event->find('count', array('conditions' => array('OR' => array('Event.org_id' => $this->id, 'Event.orgc_id' => $this->id)))) != 0) return false;
		return true;
	}

	public function captureOrg($org, $user, $force = false) {
		if (is_array($org)) {
			if (isset($org['uuid']) && !empty($org['uuid'])) {
				$conditions = array('uuid' => $org['uuid']);
				$uuid = $org['uuid'];
				$conditions2 = array('name' => $org['name']);
			} else {
				$conditions = array('name' => $org['name']);
			}
			$name = $org['name'];
		} else {
			$conditions = array('name' => $org);
			$name = $org;
		}

		$existingOrg = $this->find('first', array(
				'recursive' => -1,
				'conditions' => $conditions,
		));
		if (empty($existingOrg) && isset($conditions2)) {
			$existingOrg = $this->find('first', array(
					'recursive' => -1,
					'conditions' => $conditions2,
			));
		}
		if (empty($existingOrg)) {
			$date = date('Y-m-d H:i:s');
			$this->create();
			$organisation = array(
					'name' => $name,
					'local' => 0,
					'created_by' => $user['id'],
					'date_modified' => $date,
					'date_created' => $date
			);
			if (isset($uuid)) $organisation['uuid'] = $uuid;
			$this->save($organisation);
			return $this->id;
		} else {
			if (isset($org['uuid']) && empty($existingOrg['Organisation']['uuid'])) $existingOrg['Organisation']['uuid'] = $org['uuid'];
			if ($force) {
				$fields = array('type', 'date_created', 'date_modified', 'nationality', 'sector', 'contacts', 'landingpage');
				foreach ($fields as $field) {
					if (isset($org[$field])) $existingOrg['Organisation'][$field] = $org[$field];
				}
			}
			$this->save($existingOrg);
		}
		return $existingOrg[$this->alias]['id'];
	}

	public function createOrgFromName($name, $user_id, $local) {
		$existingOrg = $this->find('first', array(
				'recursive' => -1,
				'conditions' => array('name' => $name)
		));
		if (empty($existingOrg)) {
			$this->create();
			$organisation = array(
					'uuid' => $this->generateUuid(),
					'name' => $name,
					'local' => $local,
					'created_by' => $user_id
			);
			$this->save($organisation);
			return $this->id;
		}
		return $existingOrg[$this->alias]['id'];
	}

	public function orgMerge($id, $request, $user) {
		$currentOrg = $this->find('first', array('recursive' => -1, 'conditions' => array('Organisation.id' => $id)));
		$targetOrgId = $request['Organisation']['targetType'] == 0 ? $request['Organisation']['orgsLocal'] : $request['Organisation']['orgsExternal'];
		$targetOrg = $this->find(
				'first', array(
						'fields' => array('id', 'name', 'uuid', 'local'),
						'recursive' => -1,
						'conditions' => array('Organisation.id' => $targetOrgId)
				));
		if (empty($currentOrg) || empty($targetOrg)) throw new MethodNotAllowedException('Something went wrong with the organisation merge. Organisation not found.');
		$dir = new Folder();
		$this->Log = ClassRegistry::init('Log');
		$dirPath = APP . 'tmp' . DS . 'logs' . DS . 'merges';
		if (!$dir->create($dirPath)) throw new MethodNotAllowedException('Merge halted because the log directory (default: /var/www/MISP/app/tmp/logs/merges) could not be created. This is most likely a permission issue, make sure that MISP can write to the logs directory and try again.');
		$logFile = new File($dirPath . DS . 'merge_' . $currentOrg['Organisation']['id'] . '_' . $targetOrg['Organisation']['id'] . '_' . time() . '.log');
		if (!$logFile->create()) throw new MethodNotAllowedException('Merge halted because the log file (default location: /var/www/MISP/app/tmp/logs/merges/[old_org_id]_[new_org_id]_timestamp.log) could not be created. This is most likely a permission issue, make sure that MISP can write to the logs directory and try again.');
		$backupFile = new File($dirPath . DS . 'merge_' . $currentOrg['Organisation']['id'] . '_' . $targetOrg['Organisation']['id'] . '_' . time() . '.sql');
		if (!$backupFile->create()) throw new MethodNotAllowedException('Merge halted because the backup script file (default location: /var/www/MISP/app/tmp/logs/merges/[old_org_id]_[new_org_id]_timestamp.sql) could not be created. This is most likely a permission issue, make sure that MISP can write to the logs directory and try again.');
		$backupFile->append('INSERT INTO `organisations` (`' . implode('`, `', array_keys($currentOrg['Organisation'])) . '`) VALUES (\'' . implode('\', \'', array_values($currentOrg['Organisation'])) . '\');' . PHP_EOL);
		$this->Log->create();
		$this->Log->save(array(
				'org' => $user['Organisation']['name'],
				'model' => 'Organisation',
				'model_id' => $currentOrg['Organisation']['id'],
				'email' => $user['email'],
				'action' => 'merge',
				'user_id' => $user['id'],
				'title' => 'Starting merger of ' . $currentOrg['Organisation']['name'] . '(' . $currentOrg['Organisation']['id'] . ') into ' . $targetOrg['Organisation']['name'] . '(' . $targetOrg['Organisation']['name'] . ')',
				'change' => '',
		));
		$dataMoved = array('removed_org' => $currentOrg);
		$success = true;
		foreach ($this->organisationAssociations as $model => $data) {
			foreach ($data['fields'] as $field) {
				$temp = $this->query('SELECT `id` FROM `' . $data['table'] . '` WHERE `' . $field . '` = "' . $currentOrg['Organisation']['id'] . '"');
				if (!empty($temp)) {
					$dataMoved['values_changed'][$model][$field] = Set::extract('/' . $data['table'] . '/id', $temp);
					if (!empty($dataMoved['values_changed'][$model][$field])) {
						$this->Log->create();
						try {
							$result = $this->query('UPDATE `' . $data['table'] . '` SET `' . $field . '` = ' . $targetOrg['Organisation']['id'] . ' WHERE `' . $field . '` = ' . $currentOrg['Organisation']['id'] . ';');
							$backupFile->append('UPDATE `' . $data['table'] . '` SET `' . $field . '` = ' . $currentOrg['Organisation']['id'] . ' WHERE `id` IN (' . implode(',', $dataMoved['values_changed'][$model][$field]) . ');' . PHP_EOL);
							$this->Log->save(array(
									'org' => $user['Organisation']['name'],
									'model' => 'Organisation',
									'model_id' => $currentOrg['Organisation']['id'],
									'email' => $user['email'],
									'action' => 'merge',
									'user_id' => $user['id'],
									'title' => 'Update for ' . $model . '.' . $field . ' has completed successfully.',
									'change' => '',
							));
						} catch (Exception $e) {
							$this->Log->save(array(
									'org' => $user['Organisation']['name'],
									'model' => 'Organisation',
									'model_id' => $currentOrg['Organisation']['id'],
									'email' => $user['email'],
									'action' => 'merge',
									'user_id' => $user['id'],
									'title' => 'Update for ' . $model . '.' . $field . ' has failed.',
									'change' => json_encode($e->getMessage()),
							));
						}
					}
				}
			}
		}
		if ($success) $this->delete($currentOrg['Organisation']['id']);
		$backupFile->close();
		$logFile->write(json_encode($dataMoved));
		$logFile->close();
		return $success;
	}
}
