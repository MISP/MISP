<?php 
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
//App::uses('AppShell', 'Console/Command');
require_once 'AppShell.php';
class EventShell extends AppShell
{
	public $uses = array('Event', 'Job');
	
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
		$target = null;
		if ($isSiteAdmin) {
			$target = 'All events.';
			$jobOrg = 'ADMIN';
		} else {
			$target = 'Events visible to: '.$org;
			$jobOrg = $org;
		}
		
		
		$this->Job->create();
		$data = array(
				'worker' => 'default',
				'job_type' => 'cache_xml',
				'job_input' => $target,
				'status' => 0,
				'retries' => 0,
				'org' => $jobOrg,
				'message' => 'Fetching events.',
		);
		$this->Job->save($data);
		$eventIds = $this->Event->fetchEventIds($org, $isSiteAdmin);
		$results = array();
		$eventCount = count($eventIds);
		foreach ($eventIds as $k => $eventId) {
			$temp = $this->Event->fetchEvent($eventId['Event']['id'], null, $org, $isSiteAdmin, $this->Job->id);
			$results[$k] = $temp[0];
			$this->Job->saveField('progress', ($k+1) / $eventCount * 100);
			sleep(1);
		}

		// Whitelist check
		$this->loadModel('Whitelist');
		$results = $this->Whitelist->removeWhitelistedFromArray($results, false);
		
		foreach ($results as $result) {
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
		}
		$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
		$dir = new Folder(APP . DS . '/tmp/cached_exports/xml');
		$file = new File($dir->pwd() . DS . $org . '.xml');
		$file->write($xmlObject->asXML());
		$file->close();
	}
}

