<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_post_after_save extends WorkflowBaseTriggerModule
{
    public $id = 'post-after-save';
    public $scope = 'post';
    public $name = 'Post After Save';
    public $description = 'This trigger is called after a Post has been saved in the database';
    public $icon = 'comment';
    public $blocking = false;
    public $misp_core_format = false;
    public $trigger_overhead = self::OVERHEAD_LOW;

    private $Thread;
    private $Event;

    public function __construct()
    {
        parent::__construct();
    }

    public function normalizeData(array $data)
    {
        parent::normalizeData($data);

        if (empty($data['Post'])) {
            return false;
        }

        $this->Thread = ClassRegistry::init('Thread');
        $thread = $this->Thread->find('first', [
            'recursive' => -1,
            'conditions' => ['id' => $data['Post']['thread_id']],
        ]);
        $data['Thread'] = !empty($thread) ? $thread['Thread'] : [];
        if (!empty($thread) && !empty($thread['Thread']['event_id'])) {
            $this->Event = ClassRegistry::init('Event');
            $event = $this->Event->find('first', [
                'recursive' => -1,
                'conditions' => ['id' => $thread['Thread']['event_id']],
            ]);
            $event = $this->convertData($event);
            $data['Event'] = $event['Event'];
        }
        return $data;
    }
}
