<?php 
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
//App::uses('AppShell', 'Console/Command');
require_once 'AppShell.php';
class EventShell extends AppShell
{
	public $uses = array('Event', 'Attribute', 'Job', 'User', 'Task');
	
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
		$this->loadModel('Whitelist');
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
			if ('true' != Configure::read('CyDefSIG.showorg') && !$isSiteAdmin) {
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
					if ('true' != Configure::read('CyDefSIG.showorg') && !$isAdmin) {
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
		$eventIds = $this->Event->fetchEventIds($org, $isSiteAdmin);
		$eventCount = count($eventIds);
		foreach ($eventIds as $k => $eventId) {
			$attributes = $this->Event->csv($org, $isSiteAdmin, $eventId['Event']['id'], $extra);
			if ($k % 10 == 0) {
				$this->Job->saveField('progress', $k / $eventCount * 80);
			}
		}
		$this->loadModel('Whitelist');
		$final = array();
		$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
		foreach ($attributes as $attribute) {
			$final[] = $attribute['Attribute']['uuid'] . ',' . $attribute['Attribute']['event_id'] . ',' . $attribute['Attribute']['category'] . ',' . $attribute['Attribute']['type'] . ',' . $attribute['Attribute']['value'];
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
		$isSiteAdmin = $this->args[1];
		$ProcessId = $this->args[2];
		$this->Job->id = $ProcessId;
		$eventId = $this->args[3];
		$result = $this->Event->sendAlertEmail($eventId, $org, $isSiteAdmin, $ProcessId);
		$this->Job->saveField('progress', '100');
		if ($result != true) $this->Job->saveField('message', 'Job done.');
	}
	
	public function enqueueCaching() {
		$timestamp = $this->args[0];
		$task = $this->Task->findByType('cache_exports');
		
		// If the next execution time and the timestamp don't match, it means that this task is no longer valid as the time for the execution has since being scheduled
		// been updated. 
		if ($task['Task']['next_execution_time'] != $timestamp) return;
		
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
			$task['Task']['next_execution_time'] = strtotime('+' . $task['Task']['timer'] . ' hours', $task['Task']['next_execution_time']);
			$task['Task']['scheduled_time'] = $this->Task->breakTime($task['Task']['scheduled_time'], $task['Task']['timer']);
		}
		$this->Task->save($task);
	}
}

