<?php
App::uses('AppModel', 'Model');
class Inbox extends AppModel
{
    public $useTable = 'inbox';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        $this->data['Inbox']['uuid'] = CakeText::uuid();
        $this->data['Inbox']['timestamp'] = time();
        $this->data['Inbox']['ip'] = $_SERVER['REMOTE_ADDR'];
        $this->data['Inbox']['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        $this->data['Inbox']['user_agent_sha256'] = hash('sha256', $_SERVER['HTTP_USER_AGENT']);
        return true;
    }


}
