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
		$org = $this->args[0];
		$isSiteAdmin = $this->args[1];
		$id = $this->args[2];
		$this->Job->id = $id;
		$eventIds = $this->Event->fetchEventIds($org, $isSiteAdmin);
		$results = array();
		$eventCount = count($eventIds);
		foreach ($eventIds as $k => $eventId) {
			$temp = $this->Event->fetchEvent($eventId['Event']['id'], null, $org, $isSiteAdmin, $this->Job->id);
			$results[$k] = $temp[0];
			$this->Job->saveField('progress', ($k+1) / $eventCount * 80);
		}

		// Whitelist check
		$results = $this->Whitelist->removeWhitelistedFromArray($results, false);
		
		foreach ($results as $k => $result) {
			$result['Event']['Attribute'] = $result['Attribute'];
			$result['Event']['ShadowAttribute'] = $result['ShadowAttribute'];
			$result['Event']['RelatedEvent'] = $result['RelatedEvent'];
		
			//
			// cleanup the array from things we do not want to expose
			//
			unset($result['Event']['user_id']);
			// hide the org field is we are not in showorg mode
			if ('true' != Configure::read('MISP.showorg') && !$isSiteAdmin) {
				unset($result['Event']['org']);
				unset($result['Event']['orgc']);
				unset($result['Event']['from']);
			}
			// remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
			foreach ($result['Event']['Attribute'] as $key => $value) {
				$result['Event']['Attribute'][$key]['value'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['Attribute'][$key]['value']);
				unset($result['Event']['Attribute'][$key]['value1']);
				unset($result['Event']['Attribute'][$key]['value2']);
				unset($result['Event']['Attribute'][$key]['category_order']);
			}
			// remove invalid utf8 characters for the xml parser
			foreach($result['Event']['ShadowAttribute'] as $key => $value) {
				$result['Event']['ShadowAttribute'][$key]['value'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['ShadowAttribute'][$key]['value']);
			}
		
			if (isset($result['Event']['RelatedEvent'])) {
				foreach ($result['Event']['RelatedEvent'] as $key => $value) {
					unset($result['Event']['RelatedEvent'][$key]['user_id']);
					if ('true' != Configure::read('MISP.showorg') && !$isAdmin) {
						unset($result['Event']['RelatedEvent'][$key]['org']);
						unset($result['Event']['RelatedEvent'][$key]['orgc']);
					}
				}
			}
			$xmlArray['response']['Event'][] = $result['Event'];
			if ($k % 20 == 0) {
				$this->Job->saveField('progress', (($k+1) / $eventCount * 10) + 79);
			}
		}
		$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
		$dir = new Folder(APP . DS . '/tmp/cached_exports/xml');
		if ($isSiteAdmin) {
			$file = new File($dir->pwd() . DS . 'misp.xml' . '.ADMIN.xml');
		} else {
			$file = new File($dir->pwd() . DS . 'misp.xml' . '.' . $org . '.xml');
		}
		$file->write($xmlObject->asXML());
		$file->close();
		$this->Job->saveField('progress', '100');
	}
	
	public function cachehids() {
		$org = $this->args[0];
		$isSiteAdmin = $this->args[1];
		$id = $this->args[2];
		$this->Job->id = $id;
		$extra = $this->args[3];
		$this->Job->saveField('progress', 1);
		$rules = $this->Attribute->hids($isSiteAdmin, $org, $extra);
		$this->Job->saveField('progress', 80);
		$dir = new Folder(APP . DS . '/tmp/cached_exports/' . $extra);
		if ($isSiteAdmin) {
			$file = new File($dir->pwd() . DS . 'misp.' . $extra . '.ADMIN.txt');
		} else {
			$file = new File($dir->pwd() . DS . 'misp.' . $extra . '.' . $org . '.txt');
		}
		$file->write('');
		foreach ($rules as $rule) {
			$file->append($rule . PHP_EOL);
		}
		$file->close();
		$this->Job->saveField('progress', '100');
	}
	
	public function cachecsv() {
		$org = $this->args[0];
		$isSiteAdmin = $this->args[1];
		$id = $this->args[2];
		$this->Job->id = $id;
		$extra = $this->args[3];
		if ($extra == 'csv_all') $ignore = 1;
		else $ignore = 0;
		$eventIds = $this->Event->fetchEventIds($org, $isSiteAdmin);
		$eventCount = count($eventIds);
		$attributes[] = array();
		foreach ($eventIds as $k => $eventId) {
			$attributes = array_merge($this->Event->csv($org, $isSiteAdmin, $eventId['Event']['id'], $ignore), $attributes);
			if ($k % 10 == 0) {
				$this->Job->saveField('progress', $k / $eventCount * 80);
			}
		}
		$final = array();
		$final[] = 'uuid,event_id,category,type,value,to_ids';
		$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
		foreach ($attributes as $attribute) {
			if (!empty($attribute)) {
				$final[] = $attribute['Attribute']['uuid'] . ',' . $attribute['Attribute']['event_id'] . ',' . $attribute['Attribute']['category'] . ',' . $attribute['Attribute']['type'] . ',' . $attribute['Attribute']['value'] . ',' . intval($attribute['Attribute']['to_ids']);
			}
		}
		$dir = new Folder(APP . DS . '/tmp/cached_exports/' . $extra);
		if ($isSiteAdmin) {
			$file = new File($dir->pwd() . DS . 'misp.' . $extra . '.ADMIN.csv');
		} else {
			$file = new File($dir->pwd() . DS . 'misp.' . $extra . '.' . $org . '.csv');
		}
		$file->write('');
		foreach ($final as $line) {
			$file->append($line . PHP_EOL);
		}
		$file->close();
		$this->Job->saveField('progress', '100');
	}
	
	public function cachetext() {
		$org = $this->args[0];
		$isSiteAdmin = $this->args[1];
		$id = $this->args[2];
		$this->Job->id = $id;
		$extra = $this->args[3];
		$types = array_keys($this->Attribute->typeDefinitions);
		$typeCount = count($types);
		$dir = new Folder(APP . DS . '/tmp/cached_exports/text');
		foreach ($types as $k => $type) {
			$final = $this->Attribute->text($org, $isSiteAdmin, $type);
			if ($isSiteAdmin) {
				$file = new File($dir->pwd() . DS . 'misp.text_' . $type . '.ADMIN.txt');
			} else {
				$file = new File($dir->pwd() . DS . 'misp.text_' . $type . '.' . $org . '.txt');
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
		$org = $this->args[0];
		$isSiteAdmin = $this->args[1];
		$id = $this->args[2];
		$this->Job->id = $id;
		$format = $this->args[3];
		$sid = $this->args[4];
		$eventIds = $this->Event->fetchEventIds($org, $isSiteAdmin);
		$eventCount = count($eventIds);
		$dir = new Folder(APP . DS . '/tmp/cached_exports/' . $format);
		if ($isSiteAdmin) {
			$file = new File($dir->pwd() . DS . 'misp.' . $format . '.ADMIN.rules');
		} else {
			$file = new File($dir->pwd() . DS . 'misp.' . $format . '.' . $org . '.rules');
		}
		$file->write('');
		foreach ($eventIds as $k => $eventId) {
			if ($k == 0) {
				$temp = $this->Attribute->nids($isSiteAdmin, $org, $format, $sid, $eventId['Event']['id']);
			} else {
				$temp = $this->Attribute->nids($isSiteAdmin, $org, $format, $sid, $eventId['Event']['id'], true);
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
		$org = $this->args[0];
		$processId = $this->args[1];
		$job = $this->Job->read(null, $processId);
		$eventId = $this->args[2];
		$result = $this->Event->sendAlertEmail($eventId, $org, $processId);
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
			$this->Task->save($task);
		}
	}
	
	public function publish() {
		$id = $this->args[0];
		$passAlong = $this->args[1];
		$jobId = $this->args[2];
		$org = $this->args[3];
		$email = $this->args[4];
		$user = $this->User->find('first', array(
			'conditions' => array('email' => $email),
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
		$log->save(array(
				'org' => $user['User']['org'],
				'email' =>$user['User']['email'],
				'user_id' => $user['User']['id'],
				'action' => 'publish',
				'title' => 'Event (' . $id . '): published.',
				'change' => 'published () => (1)'));
	}

}

