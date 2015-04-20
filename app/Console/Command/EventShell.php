<?php 
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
//App::uses('AppShell', 'Console/Command');
require_once 'AppShell.php';
class EventShell extends AppShell
{
	public $uses = array('Event', 'Attribute', 'Job', 'User', 'Task', 'Whitelist');
	
	public function doPublish() {
		$id = $this->args[0];
		$this->Event->id = $id;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}
		$this->Job->create();
		$data = array(
				'worker' => 'default',
				'job_type' => 'doPublish',
				'job_input' => $id,
				'status' => 0,
				'retries' => 0,
				//'org' => $jobOrg,
				'message' => 'Job created.',
		);
		$this->Job->save($data);
		//$jobID = $this->Job->id;
		//$this->Job->add('default', 'Publish', 'Event published: ' . $id);
		// update the event and set the from field to the current instance's organisation from the bootstrap. We also need to save id and info for the logs.
		$this->Event->recursive = -1;
		$event = $this->Event->read(null, $id);
		$event['Event']['published'] = 1;
		$fieldList = array('published', 'id', 'info');
		$this->Event->save($event, array('fieldList' => $fieldList));
		// only allow form submit CSRF protection.
		$this->Job->saveField('status', 1);
		$this->Job->saveField('message', 'Job done.');
	}
	
	public function cachexml() {
		$user_id = $this->args[0];
		$id = $this->args[1];
		$user = $this->User->getAuthUser($user_id);
		$this->Job->id = $id;
		// TEMP: change to passing an options array with the user!!
		$eventIds = $this->Event->fetchEventIds($user);
		$result = array();
		$eventCount = count($eventIds);
		$dir = new Folder(APP . 'tmp/cached_exports/xml');
		if ($user['Role']['perm_site_admin']) {
			$file = new File($dir->pwd() . DS . 'misp.xml' . '.ADMIN.xml');
		} else {
			$file = new File($dir->pwd() . DS . 'misp.xml' . '.' . $user['Organisation']['name'] . '.xml');
		}
		App::uses('XMLConverterTool', 'Tools');
		$converter = new XMLConverterTool();
		$toEscape = array("&", "<", ">", "\"", "'");
		$escapeWith = array('&amp;', '&lt;', '&gt;', '&quot;', '&apos;');
		$file->write('<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL . '<response>');
		foreach ($eventIds as $k => $eventId) {
			$temp = $this->Event->fetchEvent($user, array('eventid' => $eventId['Event']['id']));
			$file->append($converter->event2XML($temp[0], $user['Role']['perm_site_admin']) . PHP_EOL);
			$this->Job->saveField('progress', ($k+1) / $eventCount *100);
		}
		$file->append('<xml_version>' . $this->Event->mispVersion . '</xml_version>');
		$file->append('</response>' . PHP_EOL);
		$file->close();
	}
	
	private function __recursiveEcho($array) {
		$text = "";
		foreach ($array as $k => $v) {
			if (is_array($v)) {
				if (empty($v)) $text .= '<' . $k . '/>';
				else {
					foreach ($v as $element) {
						$text .= '<' . $k . '>';
						$text .= $this->__recursiveEcho($element);
						$text .= '</' . $k . '>';
					}
				}
			} else {
				if ($v === false) $v = 0;
				if ($v === "" || $v === null) $text .= '<' . $k . '/>';
				else {
					$text .= '<' . $k . '>' . $v . '</' . $k . '>';
				}
			}
		}
		return $text;
	}
	
	public function cachehids() {
		$user_id = $this->args[0];
		$user = $this->User->getAuthUser($user_id);
		$id = $this->args[1];
		$this->Job->id = $id;
		$extra = $this->args[2];
		$this->Job->saveField('progress', 1);
		$rules = $this->Attribute->hids($user, $extra);
		$this->Job->saveField('progress', 80);
		$dir = new Folder(APP . DS . '/tmp/cached_exports/' . $extra);
		if ($user['Role']['perm_site_admin']) {
			$file = new File($dir->pwd() . DS . 'misp.' . $extra . '.ADMIN.txt');
		} else {
			$file = new File($dir->pwd() . DS . 'misp.' . $extra . '.' . $user['Organisation']['name'] . '.txt');
		}
		$file->write('');
		foreach ($rules as $rule) {
			$file->append($rule . PHP_EOL);
		}
		$file->close();
		$this->Job->saveField('progress', '100');
	}
	
	public function cachecsv() {
		$user_id = $this->args[0];
		$user = $this->User->getAuthUser($user_id);
		$id = $this->args[1];
		$this->Job->id = $id;
		$extra = $this->args[2];
		if ($extra == 'csv_all') $ignore = 1;
		else $ignore = 0;
		// TEMP: change to passing an options array with the user!!
		$eventIds = $this->Event->fetchEventIds($user);
		$eventCount = count($eventIds);
		$attributes = array();
		$dir = new Folder(APP . 'tmp/cached_exports/' . $extra);
		if ($user['Role']['perm_site_admin']) {
			$file = new File($dir->pwd() . DS . 'misp.' . $extra . '.ADMIN.csv');
		} else {
			$file = new File($dir->pwd() . DS . 'misp.' . $extra . '.' . $user['Organisation']['name'] . '.csv');
		}
		$file->write('uuid,event_id,category,type,value,to_ids,date' . PHP_EOL);
		foreach ($eventIds as $k => $eventId) {
			$chunk = "";
			$attributes = $this->Event->csv($user, $eventId['Event']['id'], $ignore);
			$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
			foreach ($attributes as $attribute) {
				$chunk .= $attribute['Attribute']['uuid'] . ',' . $attribute['Attribute']['event_id'] . ',' . $attribute['Attribute']['category'] . ',' . $attribute['Attribute']['type'] . ',' . $attribute['Attribute']['value'] . ',' . intval($attribute['Attribute']['to_ids']) . ',' . $attribute['Attribute']['timestamp'] . PHP_EOL;
			}
			$file->append($chunk);
			if ($k % 10 == 0) {
				$this->Job->saveField('progress', $k / $eventCount * 80);
			}
		}
		$file->close();
		$this->Job->saveField('progress', '100');
	}
	
	public function cachetext() {
		$user_id = $this->args[0];
		$user = $this->User->getAuthUser($user_id);
		$id = $this->args[1];
		$this->Job->id = $id;
		$extra = $this->args[2];
		$types = array_keys($this->Attribute->typeDefinitions);
		$typeCount = count($types);
		$dir = new Folder(APP . DS . '/tmp/cached_exports/text');
		foreach ($types as $k => $type) {
			$final = $this->Attribute->text($user, $type);
			if ($user['Role']['perm_site_admin']) {
				$file = new File($dir->pwd() . DS . 'misp.text_' . $type . '.ADMIN.txt');
			} else {
				$file = new File($dir->pwd() . DS . 'misp.text_' . $type . '.' . $user['Organisation']['name'] . '.txt');
			}
			$file->write('');
			foreach ($final as $attribute) {
				$file->append($attribute['Attribute']['value'] . PHP_EOL);
			}
			$file->close();
			$this->Job->saveField('progress', $k / $typeCount * 100);
		}
		$this->Job->saveField('progress', 100);
	}
	
	public function cachenids() {
		$user_id = $this->args[0];
		$user = $this->User->getAuthUser($user_id);
		$id = $this->args[1];
		$this->Job->id = $id;
		$format = $this->args[2];
		$sid = $this->args[3];
		// TEMP: change to passing an options array with the user!!
		$eventIds = $this->Event->fetchEventIds($user);
		$eventCount = count($eventIds);
		$dir = new Folder(APP . DS . '/tmp/cached_exports/' . $format);
		if ($user['Role']['perm_site_admin']) {
			$file = new File($dir->pwd() . DS . 'misp.' . $format . '.ADMIN.rules');
		} else {
			$file = new File($dir->pwd() . DS . 'misp.' . $format . '.' . $user['Organisation']['name'] . '.rules');
		}
		$file->write('');
		foreach ($eventIds as $k => $eventId) {
			if ($k == 0) {
				$temp = $this->Attribute->nids($user, $format, $eventId['Event']['id']);
			} else {
				$temp = $this->Attribute->nids($user, $format, $eventId['Event']['id'], true);
			}
			foreach ($temp as $line) {
				$file->append($line . PHP_EOL);
			}
			if ($k % 10 == 0) {
				$this->Job->saveField('progress', $k / $eventCount * 80);
			}
		}
		$file->close();
		$this->Job->saveField('progress', '100');
	}
	
	public function alertemail() {
		$userId = $this->args[0];
		$processId = $this->args[1];
		$job = $this->Job->read(null, $processId);
		$eventId = $this->args[2];
		$user = $this->User->getAuthUser($userId);
		$result = $this->Event->sendAlertEmail($eventId, $user, $processId);
		$job['Job']['progress'] = 100;
		$job['Job']['message'] = 'Emails sent.';
		$this->Job->save($job);
	}
	
	public function contactemail() {
		$id = $this->args[0];
		$message = $this->args[1];
		$all = $this->args[2];
		$userId = $this->args[3];
		$isSiteAdmin = $this->args[4];
		$processId = $this->args[5];
		$this->Job->id = $processId;
		$user = $this->User->read(null, $userId);
		$eventId = $this->args[2];
		$result = $this->Event->sendContactEmail($id, $message, $all, $user, $isSiteAdmin);
		$this->Job->saveField('progress', '100');
		if ($result != true) $this->Job->saveField('message', 'Job done.');
	}
	
	public function enqueueCaching() {
		$timestamp = $this->args[0];
		$task = $this->Task->findByType('cache_exports');
		
		// If the next execution time and the timestamp don't match, it means that this task is no longer valid as the time for the execution has since being scheduled
		// been updated. 
		if ($task['Task']['next_execution_time'] != $timestamp) return;
		$task['Task']['scheduled_time'] = date('H:i', $task['Task']['next_execution_time']);
		$this->Task->save($task);
		$orgs = $this->User->getOrgs();
		
		// Queue a set of exports for admins. This "ADMIN" organisation. The organisation of the admin users doesn't actually matter, it is only used to indentify
		// the special cache files containing all events
		$i = 0;
		foreach($this->Event->export_types as $k => $type) {
			foreach ($orgs as $org) {
				$this->Job->cache($k, false, $org, 'Events visible to: ' . $org, $org);
				$i++;
			}
			$this->Job->cache($k, true, 'ADMIN', 'All events.', 'ADMIN');
			$i++;
		}
		$task['Task']['message'] = $i . ' jobs started at ' . date('d/m/Y - H:i:s') . '.';
		if ($task['Task']['timer'] > 0) {
			$time = time();
			// Keep adding the timer's time interval until we get a date that is in the future! We don't want to keep queuing tasks in the past since they will execute until it catches up.
			while ($task['Task']['next_execution_time'] < $time) {
				$task['Task']['next_execution_time'] = strtotime('+' . $task['Task']['timer'] . ' hours', $task['Task']['next_execution_time']);
			}
			$task['Task']['scheduled_time'] = $this->Task->breakTime($task['Task']['scheduled_time'], $task['Task']['timer']);
			$task['Task']['scheduled_time'] = date('H:i', $task['Task']['next_execution_time']);
			
			// Now that we have figured out when the next execution should happen, it's time to enqueue it.
			$process_id = CakeResque::enqueueAt(
					$task['Task']['next_execution_time'],
					'cache',
					'EventShell',
					array('enqueueCaching', $task['Task']['next_execution_time']),
					true
			);
			$task['Task']['job_id'] = $process_id;
			$this->Task->save($task);
		}
	}
	
	public function publish() {
		$id = $this->args[0];
		$passAlong = $this->args[1];
		$jobId = $this->args[2];
		$userId = $this->args[3];
		$user = $this->User->find('first', array(
			'conditions' => array('id' => $userId),
			'fields' => array('email', 'org', 'id'),
			'recursive' => -1,
		));
		$job = $this->Job->read(null, $jobId);
		$eventId = $this->args[2];
		$this->Event->Behaviors->unload('SysLogLogable.SysLogLogable');
		$result = $this->Event->publish($id, $passAlong);
		$job['Job']['progress'] = 100;
		if ($result) {
			$job['Job']['message'] = 'Event published.';
		} else {
			$job['Job']['message'] = 'Event published, but the upload to other instances may have failed.';
		}
		$this->Job->save($job);
		$log = ClassRegistry::init('Log');
		$log->create();
		$log->createLogEntry($user, 'publish', 'Event (' . $id . '): published.', 'publised () => (1)');
	}

}

