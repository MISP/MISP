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
		if (empty($this->data['Organisation']['id'])) {
			$this->data['Organisation']['date_created'] = $date;
			$this->data['Organisation']['date_modified'] = $date;
		} else {
			$this->data['Organisation']['date_modified'] = $date;
		}
		return true;
	}
	
	public function beforeDelete($cascade = false){
		if ($this->User->find('count', array('conditions' => array('User.org_id' => $this->id))) != 0) return false;
		if ($this->Event->find('count', array('conditions' => array('OR' => array('Event.org_id' => $this->id, 'Event.orgc_id' => $this->id)))) != 0) return false;
		return true;
	}
	
	public function captureOrg($org, $user) {

		if (is_array($org)) {
			if (isset($org['uuid'])) {
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
			$this->create();
			$organisation = array(
					'uuid' => $uuid, 
					'name' => $name, 
					'local' => 0, 
					'created_by' => $user['id']
			);
			if (isset($uuid)) $organisation['uuid'] = $uuid;
			$this->save($organisation);
			return $this->id;
		} else {
			if (isset($org['uuid']) && empty($existingOrg['Orgc']['uuid'])) $existingOrg['Orgc']['uuid'] = $org['uuid'];
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
}