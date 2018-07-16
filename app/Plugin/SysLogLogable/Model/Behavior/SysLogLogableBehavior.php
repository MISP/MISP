<?php

App::import('Lib', 'SysLog.SysLog');	// Audit, syslogd, extra

class SysLogLogableBehavior extends LogableBehavior {

	function afterSave(Model $Model, $created, $options = array()) {
		if (!$this->settings[$Model->alias]['enabled']) {
			return true;
		}
		if (isset($this->settings[$Model->alias]['skip']['add']) && $this->settings[$Model->alias]['skip']['add'] && $created) {
			return true;
		} else if (isset($this->settings[$Model->alias]['skip']['edit']) && $this->settings[$Model->alias]['skip']['edit'] && !$created) {
			return true;
		}
		$keys = array_keys($Model->data[$Model->alias]);
		$diff = array_diff($keys, $this->settings[$Model->alias]['ignore']);
		if (sizeof($diff) == 0 && empty($Model->logableAction)) {
			return false;
		}
		if ($Model->id) {
			$id = $Model->id;
		} else if ($Model->insertId) {
			$id = $Model->insertId;
		}
		if (isset($this->schema[$this->settings[$Model->alias]['foreignKey']])) {
			$logData['Log'][$this->settings[$Model->alias]['foreignKey']] = $id;
		}
		if (isset($this->schema['description'])) {
			$logData['Log']['description'] = $Model->alias . ' ';
			if (isset($Model->data[$Model->alias][$Model->displayField]) && $Model->displayField != $Model->primaryKey) {
				$logData['Log']['description'] .= '"' . $Model->data[$Model->alias][$Model->displayField] . '" ';
			}

			if ($this->settings[$Model->alias]['description_ids']) {
				$logData['Log']['description'] .= '(' . $id . ') ';
			}

			if ($created) {
				$logData['Log']['description'] .= __('added', true);
			} else {
				$logData['Log']['description'] .= __('updated', true);
			}
		}
		if (isset($this->schema['action'])) {
			if ($created) {
				$logData['Log']['action'] = 'add';
			} else {
				$logData['Log']['action'] = 'edit';
				if ($Model->alias === 'Attribute' && isset($Model->data[$Model->alias]['deleted']) && $Model->data[$Model->alias]['deleted']) {
					$logData['Log']['action'] = 'delete';
					unset($this->schema['change']);
				}
				if ($Model->alias === 'Attribute' && isset($Model->data[$Model->alias]['deleted']) && !$Model->data[$Model->alias]['deleted'] && $this->old[$Model->alias]['deleted']) {
					$logData['Log']['action'] = 'undelete';
					unset($this->schema['change']);
				}
			}

		}
		if (isset($this->schema['change'])) {
			$logData['Log']['change'] = '';
			$db_fields = array_keys($Model->schema());
			$changed_fields = array();
			foreach ( $Model->data[$Model->alias] as $key => $value ) {
				if (isset($Model->data[$Model->alias][$Model->primaryKey]) && !empty($this->old) && isset($this->old[$Model->alias][$key])) {
					$old = $this->old[$Model->alias][$key];
					if (is_array($old)) {
						$old = json_encode($old, true);
					}
				} else {
					$old = '';
				}
				// TODO Audit, removed 'revision' as well
				if ($key != 'lastpushedid' && $key!= 'timestamp' && $key != 'revision' && $key != 'modified' && !in_array($key, $this->settings[$Model->alias]['ignore']) && $value != $old && in_array($key, $db_fields)) {
					if ($this->settings[$Model->alias]['change'] == 'full') {
						if (($key != 'published') || (($key == 'published') && ($value == '1'))) { // remove (un-)published from edit
							$changed_fields[] = $key . ' (' . $old . ') => (' . $value . ')';
						}
					} else if ($this->settings[$Model->alias]['change'] == 'serialize') {
						$changed_fields[$key] = array(
								'old' => $old,
								'value' => $value);
					} else {
						$changed_fields[] = $key;
					}
					if (($key == 'published') && ($value == '1')) { // published action correction
						$logData['Log']['action'] = 'publish';
					}
				}
			}
			$changes = sizeof($changed_fields);
			if ($changes == 0) {
				return true;
			}
			if ($this->settings[$Model->alias]['change'] == 'serialize') {
				$logData['Log']['change'] = serialize($changed_fields);
			} else {
				$logData['Log']['change'] = implode(', ', $changed_fields);
			}
			$logData['Log']['changes'] = $changes;
		}
		$this->_saveLog($Model, $logData);
	}

	function _saveLog(&$Model, $logData, $title = null) {
		if ($title !== NULL) {
			$logData['Log']['title'] = $title;
		} else if ($Model->displayField == $Model->primaryKey) {
			$logData['Log']['title'] = $Model->alias . ' (' . $Model->id . ')';
		} else if (isset($Model->data[$Model->alias][$Model->displayField])) {
			if (($Model->alias == "User") && ($logData['Log']['action'] != 'edit')) {
				$logData['Log']['title'] = 'User (' . $Model->data[$Model->alias][$Model->primaryKey] . '): ' . $Model->data[$Model->alias][$Model->displayField];
			} else {
				$logData['Log']['title'] = $Model->data[$Model->alias][$Model->displayField];
			}
		} else {
			$logData['Log']['title'] = $Model->field($Model->displayField);
		}

		if (isset($this->schema[$this->settings[$Model->alias]['classField']])) {
			// by miha nahtigal
			$logData['Log'][$this->settings[$Model->alias]['classField']] = $Model->name;
		}

		if (isset($this->schema[$this->settings[$Model->alias]['foreignKey']]) && !isset($logData['Log'][$this->settings[$Model->alias]['foreignKey']])) {
			if ($Model->id) {
				$logData['Log'][$this->settings[$Model->alias]['foreignKey']] = $Model->id;
			} else if ($Model->insertId) {
				$logData['Log'][$this->settings[$Model->alias]['foreignKey']] = $Model->insertId;
			}
		}
		if (!isset($this->schema['action'])) {
			unset($logData['Log']['action']);
		} else if (isset($Model->logableAction) && !empty($Model->logableAction)) {
			$logData['Log']['action'] = implode(',', $Model->logableAction); // . ' ' . $logData['Log']['action'];
			unset($Model->logableAction);
		}

		if (isset($this->schema['version_id']) && isset($Model->version_id)) {
			$logData['Log']['version_id'] = $Model->version_id;
			unset($Model->version_id);
		}

		if (isset($this->schema[$this->settings[$Model->alias]['userKey']]) && $this->user) {
			$logData['Log'][$this->settings[$Model->alias]['userKey']] = $this->user[$this->UserModel->alias][$this->UserModel->primaryKey];
		}

		if (isset($this->schema['description'])) {
			if ($this->user && $this->UserModel) {
				$logData['Log']['description'] .= ' by ' . $this->settings[$Model->alias]['userModel'] . ' "' . $this->user[$this->UserModel->alias][$this->UserModel->displayField] . '"';
				if ($this->settings[$Model->alias]['description_ids']) {
					$logData['Log']['description'] .= ' (' . $this->user[$this->UserModel->alias][$this->UserModel->primaryKey] . ')';
				}
			} else {
				// UserModel is active, but the data hasnt been set. Assume system action.
				$logData['Log']['description'] .= ' by System';
			}
			$logData['Log']['description'] .= '.';
		}
		if (isset($this->schema['email'])) {	// TODO Audit, LogableBehevior email
		if ($this->user && $this->UserModel) {
			$logData['Log']['email'] = $this->user[$this->UserModel->alias][$this->UserModel->displayField];
		} else {
			// UserModel is active, but the data hasnt been set. Assume system action.
			$logData['Log']['email'] = 'SYS';
		}
		}
		if (isset($this->schema['org'])) {	// TODO Audit, LogableBehevior org CHECK!!!
		if ($this->user && $this->UserModel) {
			$logData['Log']['org'] = $this->user[$this->UserModel->alias]['Organisation']['name'];
		} else {
			// UserModel is active, but the data hasnt been set. Assume system action.
			$logData['Log']['org'] = 'SYS';
		}
		}
		if (isset($this->schema['title'])) {	// TODO LogableBehevior title
		if ($this->user && $this->UserModel) {	//  $Model->data[$Model->alias][$Model->displayField]
			switch ($Model->alias) {
				case "Attribute":
					if (isset($Model->combinedKeys)) {
						if (is_array($Model->combinedKeys)) {
							$title = 'Attribute ('. $Model->data[$Model->alias]['id'].') '.'from Event ('. $Model->data[$Model->alias]['event_id'].'): '.  $Model->data[$Model->alias][$Model->combinedKeys[1]].'/'.  $Model->data[$Model->alias][$Model->combinedKeys[2]].' '.  $Model->data[$Model->alias]['value1'];
							$logData['Log']['title'] = $title;
						}
					}
					break;
				case "Event":
					$title = 'Event ('. $Model->data[$Model->alias]['id'] .'): '. $Model->data[$Model->alias]['info'];
					$logData['Log']['title'] = $title;
					break;
				case "Organisation":
					$title = 'Organisation (' . $Model->data[$Model->alias]['id'] . '): ' . $Model->data[$Model->alias]['name'];
					break;
				case "Post":
					$title = 'Post (' . $Model->data[$Model->alias]['id'] . ')';
					break;
				case "Regexp":
					$title = 'Regexp ('. $Model->data[$Model->alias]['id'] .'): '. $Model->data[$Model->alias]['regexp'];
					$logData['Log']['title'] = $title;
					break;
				case "Role":
					$title = 'Role ('. $Model->data[$Model->alias]['id'] .'): '. $Model->data[$Model->alias]['name'];
					$logData['Log']['title'] = $title;
					break;
				case "Server":
					$title = 'Server ('. $Model->data[$Model->alias]['id'].'): '. $Model->data[$Model->alias]['url'];
					$logData['Log']['title'] = $title;
					break;
				case "ShadowAttribute":
					if (isset($Model->combinedKeys)) {
						if (is_array($Model->combinedKeys)) {
							$title = 'Proposal ('. $Model->data[$Model->alias]['id'].'): '.'to Event ('. $Model->data[$Model->alias]['event_id'].'): '.  $Model->data[$Model->alias][$Model->combinedKeys[1]].'/'.  $Model->data[$Model->alias][$Model->combinedKeys[2]].' '.  $Model->data[$Model->alias]['value1'];
							$logData['Log']['title'] = $title;
						}
					}
					break;
				case "SharingGroup":
					$title = 'SharingGroup ('. $Model->data[$Model->alias]['id'].'): '.  $Model->data[$Model->alias]['name'];
					break;
				case "Tag":
					$title = 'Tag ('. $Model->data[$Model->alias]['id'].'): '.  $Model->data[$Model->alias]['name'];
					break;
				case "Thread":
					$title = 'Thread ('. $Model->data[$Model->alias]['id'].'): '.  $Model->data[$Model->alias]['title'];
					break;
				case "User":		// TODO Audit, not used here but done in UsersController
					if (($logData['Log']['action'] == 'edit') || ($logData['Log']['action'] == 'delete')) {
						return; // handle in model itself
					}
					$title = 'User ('. $Model->data[$Model->alias]['id'].'): '.  $Model->data[$Model->alias]['email'];
					break;
				case "Whitelist":
					$title = 'Whitelist ('. $Model->data[$Model->alias]['id'] .'): '. $Model->data[$Model->alias]['name'];
					$logData['Log']['title'] = $title;
					break;
				default:
					if (isset($Model->combinedKeys)) {
						if (is_array($Model->combinedKeys)) {
							$title = '';
							foreach ($Model->combinedKeys as $combinedKey) {
								$title .= '/'.  $Model->data[$Model->alias][$combinedKey];
							}
							$title = substr($title ,1);
							$logData['Log']['title'] = $title;
						}
					}
			}
		}
		}
		$this->Log->create($logData);
		$this->Log->save(null, array('validate' => false));
	}

	function setup(Model $Model, $config = array()) {
		if (!is_array($config)) {
			$config = array();
		}
		$this->settings[$Model->alias] = array_merge($this->defaults, $config);
		$this->settings[$Model->alias]['ignore'][] = $Model->primaryKey;

		$this->Log = ClassRegistry::init('Log');
		if ($this->settings[$Model->alias]['userModel'] != $Model->alias) {
			$this->UserModel = ClassRegistry::init($this->settings[$Model->alias]['userModel']);
		} else {
			$this->UserModel = $Model;
		}
		$this->schema = $this->Log->schema();
		App::uses('AuthComponent', 'Controller/Component');
		$user = AuthComponent::user();
		if (!empty($user)) $this->user[$this->settings[$Model->alias]['userModel']] = AuthComponent::user();
		else $this->user['User'] = array('email' => 'SYSTEM', 'Organisation' => array('name' => 'SYSTEM'), 'id' => 0);
	}
}
