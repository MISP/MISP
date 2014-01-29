<?php

App::import('Lib', 'SysLog.SysLog');	// Audit, syslogd, extra
App::import('Controller', 'EventsController');
App::import('Controller', 'ServersController');

class SysLogLogableBehavior extends LogableBehavior {

	function afterSave(Model $Model, $created, $options = array()) {

		if (!$this->settings[$Model->alias]['enabled']) {
			return true;
		}
		if (isset($this->settings[$Model->alias]['skip']['add']) && $this->settings[$Model->alias]['skip']['add'] && $created) {
			return true;
		} elseif (isset($this->settings[$Model->alias]['skip']['edit']) && $this->settings[$Model->alias]['skip']['edit'] && !$created) {
			return true;
		}
		$keys = array_keys($Model->data[$Model->alias]);
		$diff = array_diff($keys, $this->settings[$Model->alias]['ignore']);
		if (sizeof($diff) == 0 && empty($Model->logableAction)) {
			return false;
		}
		if ($Model->id) {
			$id = $Model->id;
		} elseif ($Model->insertId) {
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
				$logData['Log']['description'] .= __('added', TRUE);
			} else {
				$logData['Log']['description'] .= __('updated', TRUE);
			}
		}
		if (isset($this->schema['action'])) {
			if ($created) {
				$logData['Log']['action'] = 'add';
			} else {
				$logData['Log']['action'] = 'edit';
			}

		}
		if (isset($this->schema['change'])) {
			$logData['Log']['change'] = '';
			$db_fields = array_keys($Model->schema());
			$changed_fields = array();
			foreach ( $Model->data[$Model->alias] as $key => $value ) {
				if (isset($Model->data[$Model->alias][$Model->primaryKey]) && !empty($this->old) && isset($this->old[$Model->alias][$key])) {
					$old = $this->old[$Model->alias][$key];
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
		} elseif ($Model->displayField == $Model->primaryKey) {
			$logData['Log']['title'] = $Model->alias . ' (' . $Model->id . ')';
		} elseif (isset($Model->data[$Model->alias][$Model->displayField])) {
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
			} elseif ($Model->insertId) {
				$logData['Log'][$this->settings[$Model->alias]['foreignKey']] = $Model->insertId;
			}
		}

		if (!isset($this->schema['action'])) {
			unset($logData['Log']['action']);
		} elseif (isset($Model->logableAction) && !empty($Model->logableAction)) {
			$logData['Log']['action'] = implode(',', $Model->logableAction); // . ' ' . $logData['Log']['action'];
			unset($Model->logableAction);
		}

		if (isset($this->schema['version_id']) && isset($Model->version_id)) {
			$logData['Log']['version_id'] = $Model->version_id;
			unset($Model->version_id);
		}

		if (isset($this->schema['ip']) && $this->userIP) {
			$logData['Log']['ip'] = $this->userIP;
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
			$logData['Log']['org'] = $this->user[$this->UserModel->alias][$this->UserModel->orgField];
		} else {
			// UserModel is active, but the data hasnt been set. Assume system action.
			$logData['Log']['org'] = 'SYS';
		}
		}
		if (isset($this->schema['title'])) {	// TODO LogableBehevior title
		if ($this->user && $this->UserModel) {	//  $Model->data[$Model->alias][$Model->displayField]
			switch ($Model->alias) {
				case "User":		// TODO Audit, not used here but done in UsersController
					if (($logData['Log']['action'] == 'edit') || ($logData['Log']['action'] == 'delete')) {
						return; // handle in model itself
					}
					$title = 'User ('. $Model->data[$Model->alias]['id'].') '.  $Model->data[$Model->alias]['email'];
					break;
				case "Event":
        			$title = 'Event ('. $Model->data[$Model->alias]['id'] .'): '. $Model->data[$Model->alias]['info'];
					$logData['Log']['title'] = $title;
					break;
				case "Attribute":
					if (isset($Model->combinedKeys)) {
						if (is_array($Model->combinedKeys)) {
							$title = 'Attribute ('. $Model->data[$Model->alias]['id'].') '.'from Event ('. $Model->data[$Model->alias]['event_id'].'): '.  $Model->data[$Model->alias][$Model->combinedKeys[1]].'/'.  $Model->data[$Model->alias][$Model->combinedKeys[2]].' '.  $Model->data[$Model->alias]['value1'];
							$logData['Log']['title'] = $title;
						}
					}
					break;
				case "ShadowAttribute":
					if (isset($Model->combinedKeys)) {
						if (is_array($Model->combinedKeys)) {
							$title = 'Proposal ('. $Model->data[$Model->alias]['id'].') '.'to Event ('. $Model->data[$Model->alias]['event_id'].'): '.  $Model->data[$Model->alias][$Model->combinedKeys[1]].'/'.  $Model->data[$Model->alias][$Model->combinedKeys[2]].' '.  $Model->data[$Model->alias]['value1'];
							$logData['Log']['title'] = $title;
						}
					}
					break;
				case "Server":
					$title = 'Server ('. $Model->data[$Model->alias]['id'].'): '. $Model->data[$Model->alias]['url'];
					$logData['Log']['title'] = $title;
					break;
				case "Role":
					$title = 'Role ('. $Model->data[$Model->alias]['id'] .'): '. $Model->data[$Model->alias]['name'];
					$logData['Log']['title'] = $title;
					break;
				case "Whitelist":
					$title = 'Whitelist ('. $Model->data[$Model->alias]['id'] .'): '. $Model->data[$Model->alias]['name'];
					$logData['Log']['title'] = $title;
					break;
				case "Regexp":
						$title = 'Regexp ('. $Model->data[$Model->alias]['id'] .'): '. $Model->data[$Model->alias]['regexp'];
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
		$this->Log->save(null, array(
				'validate' => false,
				'callbacks' => false));

		// write to syslogd as well
		$syslog = new SysLog();
		if (isset($logData['Log']['change'])) {
			$syslog->write('notice', $logData['Log']['description'].' -- '.$logData['Log']['change']);
		} else {
			$syslog->write('notice', $logData['Log']['description']);
		}
	}
}