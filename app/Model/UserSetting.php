<?php
App::uses('AppModel', 'Model');

/**
 * @property User $User
 */
class UserSetting extends AppModel
{
    public $useTable = 'user_settings';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
            'SysLogLogable.SysLogLogable' => array(
                    'userModel' => 'User',
                    'userKey' => 'user_id',
                    'change' => 'full'),
            'Containable',
    );

    public $validate = array(
        'value' => 'valueIsJson',
    );

    public $belongsTo = array(
        'User'
    );

    // private
    const VALID_SETTINGS = array(
        'publish_alert_filter' => array(
            'placeholder' => array(
                'AND' => array(
                    'NOT' => array(
                        'EventTag.name' => array(
                            '%osint%'
                        )
                    ),
                    'OR' => array(
                        'Tag.name' => array(
                            'tlp:green',
                            'tlp:amber',
                            'tlp:red',
                            '%privint%'
                        )
                    )
                )
            )
        ),
        'dashboard_access' => array(
            'placeholder' => 1,
            'restricted' => 'perm_site_admin'
        ),
        'dashboard' => array(
            'placeholder' => array(
                array(
                    'widget' => 'MispStatusWidget',
                    'config' => array(
                    ),
                    'position' => array(
                        'x' => 0,
                        'y' => 0,
                        'width' => 2,
                        'height' => 2
                    )
                )
            )
        ),
        'homepage' => array(
            'placeholder' => ['path' => '/events/index'],
        ),
        'default_restsearch_parameters' => array(
            'placeholder' => array(
                'AND' => array(
                    'NOT' => array(
                        'EventTag.name' => array(
                            '%osint%'
                        )
                    ),
                    'OR' => array(
                        'Tag.name' => array(
                            'tlp:green',
                            'tlp:amber',
                            'tlp:red',
                            '%privint%'
                        )
                    )
                )
            )
        ),
        'tag_numerical_value_override' => array(
            'placeholder' => array(
                'false-positive:risk="medium"' => 99
            )
        ),
        'event_index_hide_columns' => [
            'placeholder' => ['clusters'],
        ],
        'oidc' => [ // Data saved by OIDC plugin
            'internal' => true,
        ],
    );

    // massage the data before we send it off for validation before saving anything
    public function beforeValidate($options = array())
    {
        // add a timestamp if it is not set
        if (empty($this->data['UserSetting']['timestamp'])) {
            $this->data['UserSetting']['timestamp'] = time();
        }
        if (
            isset($this->data['UserSetting']['value']) &&
            $this->data['UserSetting']['value'] !== '' &&
            $this->data['UserSetting']['value'] !== 'null'
        ) {
            if (is_array($this->data['UserSetting']['value'])) {
                $this->data['UserSetting']['value'] = json_encode($this->data['UserSetting']['value']);
            }
        } else {
            $this->data['UserSetting']['value'] = '[]';
        }
        return true;
    }

    // Once we run a find, let us decode the JSON field so we can interact with the contents as if it was an array
    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $v) {
            if (isset($v['UserSetting']['value'])) {
                $results[$k]['UserSetting']['value'] = json_decode($v['UserSetting']['value'], true);
            }
        }
        return $results;
    }

    /**
     * @param string $setting
     * @return bool
     */
    public function checkSettingValidity($setting)
    {
        return isset(self::VALID_SETTINGS[$setting]);
    }

    /**
     * @param string $setting
     * @return bool
     */
    public function isInternal($setting)
    {
        if (!isset(self::VALID_SETTINGS[$setting]['internal'])) {
            return false;
        }
        return self::VALID_SETTINGS[$setting]['internal'];
    }

    /**
     * @param array $user
     * @return array
     */
    public function settingPlaceholders(array $user)
    {
        $output = [];
        foreach (self::VALID_SETTINGS as $setting => $config) {
            if ($this->checkSettingAccess($user, $setting) === true) {
                $output[$setting] = $config['placeholder'];
            }
        }
        return $output;
    }

    public function getInternalSettingNames()
    {
        $internal = [];
        foreach (self::VALID_SETTINGS as $setting => $config) {
            if (isset($config['internal']) && $config['internal']) {
                $internal[] = $setting;
            }
        }
        return $internal;
    }

    /**
     * @param array $user
     * @param string $setting
     * @return bool|string
     */
    public function checkSettingAccess(array $user, $setting)
    {
        if ($this->isInternal($setting)) {
            return 'site_admin';
        }
        if (!empty(self::VALID_SETTINGS[$setting]['restricted'])) {
            $roleCheck = self::VALID_SETTINGS[$setting]['restricted'];
            if (!is_array($roleCheck)) {
                $roleCheck = array($roleCheck);
            }
            foreach ($roleCheck as $role) {
                if (!empty($user['Role'][$role])) {
                    return true;
                }
            }
            foreach ($roleCheck as &$role) {
                $role = substr($role, 5);
            }
            return implode(', ', $roleCheck);
        }
        return true;
    }

    /**
     * canModify expects an auth user object or a user ID and a loaded setting as input parameters
     * check if the user can modify/remove the given entry
     * returns true for site admins
     * returns true for org admins if setting["User"]["org_id"] === $user["org_id"]
     * returns true for any user if setting["user_id"] === $user["id"]
     * @param array|int $user Current user
     * @param array $setting
     * @param int $user_id
     * @return bool
     */
     public function checkAccess($user, array $setting, $user_id = false)
     {
         if (is_numeric($user)) {
             $user = $this->User->getAuthUser($user);
         }
         if ($this->isInternal($setting['UserSetting']['setting']) && !$user['Role']['perm_site_admin']) {
             return false;
         }
         if (empty($setting) && !empty($user_id) && is_numeric($user_id)) {
             $userToCheck = $this->User->find('first', array(
                 'conditions' => array('User.id' => $user_id),
                 'recursive' => -1
             ));
             if (empty($userToCheck)) {
                 return false;
             }
             $setting = array(
                'User' => array(
                    'org_id' => $userToCheck['User']['org_id']
                ),
                'UserSetting' => array(
                    'user_id' => $userToCheck['User']['id']
                )
             );
         }
         if ($user['Role']['perm_site_admin']) {
             return true;
         } else if ($user['Role']['perm_admin']) {
             if ($user['org_id'] === $setting['User']['org_id']) {
                 return true;
             }
         } else {
             if (
                 $user['id'] === $setting['UserSetting']['user_id'] &&
                 (!Configure::check('MISP.disableUserSelfManagement') || Configure::check('MISP.disableUserSelfManagement'))
             ) {
                 return true;
             }
         }
         return false;
     }

     public function getDefaultRestSearchParameters($user)
     {
         return $this->getValueForUser($user['id'], 'default_restsearch_parameters') ?: [];
     }

     public function getTagNumericalValueOverride($userId)
     {
         return $this->getValueForUser($userId, 'tag_numerical_value_override') ?: [];
     }

    /**
     * @param int $userId
     * @param string $setting
     * @return mixed|null
     */
     public function getValueForUser($userId, $setting)
     {
         $output = $this->find('first', array(
             'recursive' => -1,
             'fields' => ['value'],
             'conditions' => array(
                 'UserSetting.user_id' => $userId,
                 'UserSetting.setting' => $setting,
             )
         ));
         if ($output) {
             return $output['UserSetting']['value'];
         }
         return null;
     }

    /**
     * Check whether the event is something the user is interested (to be alerted on)
     * @param array $user
     * @param array $event
     * @return bool
     */
    public function checkPublishFilter(array $user, array $event)
    {
        $rule = $this->getValueForUser($user['id'], 'publish_alert_filter');
        // We should return true if no setting has been configured, or there's a setting with an empty value
        if (empty($rule)) {
            return true;
        }
        // recursively evaluate the boolean tree to true/false and return the value
        $result = $this->__recursiveConvert($rule, $event);
        if (isset($result[0])) {
            return $result[0];
        } else {
            return false;
        }
    }

    /**
     * Convert a complex rule set recursively
     * takes as params a rule branch and an event to check against
     * evaluate whether the rule set evaluates as true/false
     * The full evaluation involves resolving the boolean branches
     * valid boolean operators are OR, AND, NOT all capitalised as strings
     */
    private function __recursiveConvert($rule, $event)
    {
        $toReturn = array();
        if (is_array($rule)) {
            foreach ($rule as $k => $v) {
                if (in_array($k, array('OR', 'NOT', 'AND'))) {
                    $parts = $this->__recursiveConvert($v, $event);
                    $temp = null;
                    foreach ($parts as $partValue) {
                        if ($temp === null) {
                            $temp = ($k === 'NOT') ? !$partValue : $partValue;
                        } else {
                            if ($k === 'OR') {
                                $temp = $temp || $partValue;
                            } elseif ($k === 'AND') {
                                $temp = $temp && $partValue;
                            } else {
                                $temp = $temp && !$partValue;
                            }
                        }
                    }
                    $toReturn[] = $temp;
                } else {
                    $toReturn[] = $this->__checkEvent($k, $v, $event);
                }
            }
            return $toReturn;
        } else {
            return false;
        }
    }

    /**
     * Checks if an event matches the given rule
     * valid filters:
     * - AttributeTag.name
     * - EventTag.name
     * - Tag.name (checks against both event and attribute tags)
     * - Orgc.uuid
     * - Orgc.name
     * - ThreatLevel.name
     * Values passed can be used for direct string comparisons or alternatively
     * as substring matches by encapsulating the string in a pair of "%" characters
     * Each rule can take a list of values
     *
     * @param string $rule
     * @param array|string $lookup_values
     * @param array $event
     * @return bool
     */
    private function __checkEvent($rule, $lookup_values, $event)
    {
        if (!is_array($lookup_values)) {
            $lookup_values = array($lookup_values);
        }
        foreach ($lookup_values as $k => $v) {
            $lookup_values[$k] = mb_strtolower($v);
        }
        if ($rule === 'AttributeTag.name') {
            $values = array_merge(
                Hash::extract($event, 'Attribute.{n}.AttributeTag.{n}.Tag.name'),
                Hash::extract($event, 'Object.{n}.Attribute.{n}.AttributeTag.{n}.Tag.name')
            );
        } else if ($rule === 'EventTag.name') {
            $values = Hash::extract($event, 'EventTag.{n}.Tag.name');
        } else if ($rule === 'Orgc.name') {
            $values = array($event['Event']['Orgc']['name']);
        } else if ($rule === 'Orgc.uuid') {
            $values = array($event['Event']['Orgc']['uuid']);
        } else if ($rule === 'Tag.name') {
            $values = array_merge(
                Hash::extract($event, 'Attribute.{n}.AttributeTag.{n}.Tag.name'),
                Hash::extract($event, 'Object.{n}.Attribute.{n}.AttributeTag.{n}.Tag.name'),
                Hash::extract($event, 'EventTag.{n}.Tag.name')
            );
        } else if ($rule === 'ThreatLevel.name') {
            $values = [$event['ThreatLevel']['name']];
        }
        if (!empty($values)) {
            foreach ($values as $extracted_value) {
                $extracted_value = mb_strtolower($extracted_value);
                foreach ($lookup_values as $lookup_value) {
                    $lookup_value_trimmed = trim($lookup_value, "%");
                    if (strlen($lookup_value_trimmed) !== strlen($lookup_value)) {
                        if (strpos($extracted_value, $lookup_value_trimmed) !== false) {
                            return true;
                        }
                    } else {
                        if ($extracted_value === $lookup_value) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * @param array $user
     * @param array $data
     * @return bool
     * @throws Exception
     */
    public function setSetting(array $user, array $data)
    {
        $userSetting = array();
        if (!empty($data['UserSetting']['user_id']) && is_numeric($data['UserSetting']['user_id'])) {
            $user_to_edit = $this->User->find('first', array(
                'recursive' => -1,
                'conditions' => array('User.id' => $data['UserSetting']['user_id']),
                'fields' => array('User.org_id')
            ));
            if (
                !empty($user['Role']['perm_site_admin']) ||
                (!empty($user['Role']['perm_admin']) && ($user_to_edit['User']['org_id'] == $user['org_id']))
            ) {
                $userSetting['user_id'] = $data['UserSetting']['user_id'];
            }
        }
        if (empty($userSetting['user_id'])) {
            $userSetting['user_id'] = $user['id'];
        }
        if (empty($data['UserSetting']['setting'])) {
            throw new MethodNotAllowedException(__('This endpoint expects both a setting and a value to be set.'));
        }
        if (!$this->checkSettingValidity($data['UserSetting']['setting'])) {
            throw new MethodNotAllowedException(__('Invalid setting.'));
        }
        $settingPermCheck = $this->checkSettingAccess($user, $data['UserSetting']['setting']);
        if ($settingPermCheck !== true) {
            throw new MethodNotAllowedException(__('This setting is restricted and requires the following permission(s): %s', $settingPermCheck));
        }
        $userSetting['setting'] = $data['UserSetting']['setting'];
        if ($data['UserSetting']['value'] !== '') {
            $userSetting['value'] = $data['UserSetting']['value'];
        } else {
            $userSetting['value'] = '';
        }

        return $this->setSettingInternal($userSetting['user_id'], $userSetting['setting'], $userSetting['value']);
    }

    /**
     * Set user setting without checking permission.
     * @param int $userId
     * @param string $setting
     * @param mixed $value
     * @return array|bool|mixed|null
     * @throws Exception
     */
    public function setSettingInternal($userId, $setting, $value)
    {
        $userSetting = [
            'user_id' => $userId,
            'setting' => $setting,
            'value' => $value,
        ];

        $existingSetting = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'UserSetting.user_id' => $userId,
                'UserSetting.setting' => $setting,
            ],
            'fields' =>  ['UserSetting.id'],
            'callbacks' => false,
        ]);
        if (empty($existingSetting)) {
            $this->create();
        } else {
            $userSetting['id'] = $existingSetting['UserSetting']['id'];
        }

        return $this->save($userSetting, ['skipAuditLog' => $this->isInternal($setting)]);
    }

    /**
     * @param int $user_id
     * @param string $setting
     * @return array|mixed
     * @deprecated
     */
    public function getSetting($user_id, $setting)
    {
        return $this->getValueForUser($user_id, $setting) ?: [];
    }
}
