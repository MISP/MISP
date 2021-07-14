<?php
App::uses('AppModel', 'Model');

/**
 * @property Thread $Thread
 * @property User $User
 */
class Post extends AppModel
{
    public $actsAs = array(
        'AuditLog',
            'Containable',
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                    'roleModel' => 'Post',
                    'roleKey' => 'post_id',
                    'change' => 'full'
            ),
    );

    public $belongsTo = array(
            'Thread',
            'User'
    );

    public $validate = array(
            'contents' => array(
                    'rule' => array('valueNotEmpty'),
            ),
    );

    public function sendPostsEmailRouter($user_id, $post_id, $event_id, $title, $message)
    {
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
                    'org_id' => $user['User']['org_id'],
                    'message' => 'Sending...',
            );
            $job->save($data);
            $jobId = $job->id;
            $process_id = CakeResque::enqueue(
                    'email',
                    'EventShell',
                    array('postsemail', $user_id, $post_id, $event_id, $title, $message, $jobId),
                    true
            );
            $job->saveField('process_id', $process_id);
            return true;
        } else {
            return $this->sendPostsEmail($user_id, $post_id, $event_id, $title, $message);
        }
    }

    /**
     * @param int $userId
     * @param int $postId
     * @param int|null $eventId
     * @param string $title
     * @param string $message
     * @return bool
     * @throws Exception
     */
    public function sendPostsEmail($userId, $postId, $eventId, $title, $message)
    {
        $post = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['id' => $postId],
            'fields' => ['id', 'thread_id'],
        ]);
        if (empty($post)) {
            throw new Exception("Post with ID $postId not found.");
        }

        $userFields = ['id', 'email', 'gpgkey', 'certif_public', 'disabled'];

        // If the post belongs to an event, E-mail all users in the org that have contactalert set
        if ($eventId) {
            $this->Event = ClassRegistry::init('Event');
            $event = $this->Event->find('first', [
                'recursive' => -1,
                'conditions' => ['id' => $eventId],
                'fields' => ['id', 'org_id', 'user_id'],
            ]);
            if (empty($event)) {
                throw new Exception("Event with ID $eventId not found.");
            }
            // Insert extra field here: alertOrg or something, then foreach all the org members
            // limit this array to users with contactalerts turned on!
            $orgMembers = $this->User->find('all', [
                'recursive' => -1,
                'conditions' => [
                    'org_id' => $event['Event']['org_id'],
                    'disabled' => 0,
                    'NOT' => ['id' => $userId], // do not send to post creator
                    'OR' => [ // send just to users with contactalert or to event creator
                       'contactalert' => 1,
                       'id' => $event['Event']['user_id'],
                    ],
               ],
               'fields' => $userFields,
            ]);
        } else {
            // Not an event: E-mail the user that started the thread
            $thread = $this->Thread->read(null, $post['Post']['thread_id']);
            if ($thread['Thread']['user_id'] == $userId) {
                $orgMembers = array();
            } else {
                $orgMembers = $this->User->find('all', [
                    'recursive' => -1,
                    'fields' => $userFields,
                    'conditions' => [
                        'id' => $thread['Thread']['user_id'],
                        'disabled' => 0,
                    ]
                ]);
            }
        }

        // Add all users who posted in this thread
        $excludeUsers = Hash::extract($orgMembers, '{n}.User.id');
        $excludeUsers[] = $userId;
        $temp = $this->find('all', [
            'recursive' => -1,
            'fields' => ['Post.id'],
            'conditions' => [
                'Post.thread_id' => $post['Post']['thread_id'],
                'User.disabled' => 0,
                'NOT' => ['User.id' => $excludeUsers]
            ],
            'contain' => ['User' => ['fields' => $userFields]],
            'group' => ['User.id', 'Post.id', 'User.email', 'User.gpgkey', 'User.certif_public', 'User.disabled'], // remove duplicates
        ]);
        $orgMembers = array_merge($orgMembers, $temp);

        // The mail body, h() is NOT needed as we are sending plain-text mails.
        $body = "";
        $body .= "Hello, \n";
        $body .= "\n";
        $body .= "Someone just posted to a MISP discussion you participated in.\n";
        $body .= "\n";
        $body .= "The full discussion can be found at: \n";
        $body .= Configure::read('MISP.baseurl') . '/threads/view/' . $post['Post']['thread_id'] . '/post_id:' . $post['Post']['id'] . "\n";

        // body containing all details ($title and $message)
        $bodyDetail = "";
        $bodyDetail .= "Hello, \n";
        $bodyDetail .= "\n";
        $bodyDetail .= "Someone just posted to a MISP discussion you participated in with title:\n";
        $bodyDetail .= $title . "\n";
        $bodyDetail .= "\n";
        $bodyDetail .= "The full discussion can be found at: \n";
        $bodyDetail .= Configure::read('MISP.baseurl') . '/threads/view/' . $post['Post']['thread_id'] . '/post_id:' . $post['Post']['id'] . "\n";
        $bodyDetail .= "\n";
        $bodyDetail .= "The following message was added: \n";
        $bodyDetail .= "\n";
        $bodyDetail .= $message . "\n";

        $tplColorString = Configure::read('MISP.email_subject_TLP_string') ?: "tlp:amber";
        $subject = "[" . Configure::read('MISP.org') . " MISP] New post in discussion " . $post['Post']['thread_id'] . " - " . strtoupper($tplColorString);
        foreach ($orgMembers as $recipient) {
            $this->User->sendEmail($recipient, $bodyDetail, $body, $subject);
        }

        return true;
    }

    public function findPageNr($id, $context = 'thread', $post_id = false)
    {
        // find the current post and its position in the thread
        if ($context == 'event') {
            $conditions = array('Thread.event_id' => $id);
        } else {
            $conditions = array('Thread.id' => $id);
        }
        $posts = $this->find('all', array('conditions' => $conditions, 'fields' => array('Post.id', 'thread_id'), 'contain' => array('Thread' => array('fields' => array('Thread.id', 'Thread.event_id')))));
        if (empty($posts)) {
            return false;
        }
        if (!$post_id) {
            $pageNr = intval(ceil(count($posts)/10));
            $lastItem = end($posts);
            $post_id = $lastItem['Post']['id'];
        } else {
            foreach ($posts as $k => $post) {
                if ($post['Post']['id'] == $post_id) {
                    $pageNr = intval(ceil($k/10));
                    continue;
                }
            }
        }
        return $pageNr;
    }
}
