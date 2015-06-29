<?php

App::uses('AppModel', 'Model');
App::uses('CakeEmail', 'Network/Email');

/**
 * Post Model
 *
*/
class Post extends AppModel {
	public $actsAs = array('Containable');
	
	public $belongsTo = array(
			'Thread',
			'User' => array(
				'fields' => array('email', 'org', 'id'),
					
			)
	);

	public function sendPostsEmailRouter($user_id, $post_id, $event_id, $title, $message, $JobId = false) {
		if (Configure::read('MISP.background_jobs')) {
			$user = $this->User->findById($user_id);
			$job = ClassRegistry::init('Job');
			$job->create();
			$data = array(
					'worker' => 'email',
					'job_type' => 'posts_alert',
					'job_input' => 'Post: ' . $post_id,
					'status' => 0,
					'retries' => 0,
					'org' => $user['User']['org'],
					'message' => 'Sending..',
			);
			$job->save($data);
			$jobId = $job->id;
			$process_id = CakeResque::enqueue(
					'email',
					'EventShell',
					array('postsemail', $user_id, $post_id, $event_id, $title, $message, $jobId)
			);
			$job->saveField('process_id', $process_id);
			return true;
		} else {
			$result = $this->sendPostsEmail($user_id, $post_id, $event_id, $title, $message);
			return $result;
		}
	}

	public function sendPostsEmail($user_id, $post_id, $event_id, $title, $message) {
		// fetch the post
		$post = $this->read(null, $post_id);
		$this->User = ClassRegistry::init('User');

		// If the post belongs to an event, E-mail all users in the org that have contactalert set
		if ($event_id) {
			$this->Event = ClassRegistry::init('Event');;
			$event = $this->Event->read(null, $event_id);
			//Insert extra field here: alertOrg or something, then foreach all the org members
			//limit this array to users with contactalerts turned on!
			$orgMembers = array();
			$this->User->recursive = -1;
			$temp = $this->User->findAllByOrg($event['Event']['org'], array('email', 'gpgkey', 'contactalert', 'id'));
			foreach ($temp as $tempElement) {
				if ($tempElement['User']['id'] != $user_id && ($tempElement['User']['contactalert'] || $tempElement['User']['id'] == $event['Event']['user_id'])) {
					array_push($orgMembers, $tempElement);
				}
			}
		} else {
			// Not an event: E-mail the user that started the thread
			$thread = $this->Thread->read(null, $post['Post']['thread_id']);
			if ($thread['Thread']['user_id'] == $user_id ) {
				$orgMembers = array();
			} else {
				$orgMembers = $this->User->findAllById($thread['Thread']['user_id'], array('email', 'gpgkey', 'contactalert', 'id'));
			}
		}

		// Add all users who posted in this thread
		$temp = $this->findAllByThreadId($post['Post']['thread_id'],array('user_id'));
		foreach ($temp as $tempElement) {
			$user = $this->User->findById($tempElement['Post']['user_id'], array('email', 'gpgkey', 'contactalert', 'id'));
			if(!empty($user) && $user['User']['id'] != $user_id && !in_array($user, $orgMembers)) {
				array_push($orgMembers, $user);
			}
		}

		// The mail body, h() is NOT needed as we are sending plain-text mails.
		$body = "";
		$body .= "Hello, \n";
		$body .= "\n";
		$body .= "Someone just posted to a MISP discussion you participated in.\n";
		$body .= "\n";
		$body .= "The full discussion can be found at: \n";
		$body .= Configure::read('MISP.baseurl') . '/posts/view/' . $post['Post']['id'] . "\n";

		// body containing all details ($title and $message)
		$bodyDetail = "";
		$bodyDetail .= "Hello, \n";
		$bodyDetail .= "\n";
		$bodyDetail .= "Someone just posted to a MISP discussion you participated in with title:\n";
		$bodyDetail .= $title . "\n";
		$bodyDetail .= "\n";
		$bodyDetail .= "The full discussion can be found at: \n";
		$bodyDetail .= Configure::read('MISP.baseurl') . '/posts/view/' . $post['Post']['id'] . "\n";
		$bodyDetail .= "\n";
		$bodyDetail .= "The following message was added: \n";
		$bodyDetail .= "\n";
		$bodyDetail .= $message . "\n";
		$subject = "[" . Configure::read('MISP.org') . " MISP] New post in discussion " . $post['Post']['thread_id'] . " - TLP Amber";
		foreach ($orgMembers as &$recipient) {
			$this->User->sendEmail($recipient, $bodyDetail, $body, $subject);
		}
	}
}
