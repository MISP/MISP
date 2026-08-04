<?php
include_once APP . 'Model/WorkflowModules/action/Module_send_mail.php';

class Module_send_log_mail extends Module_send_mail
{
    public $id = 'send-log-mail';
    public $name = 'Send Log Mail';
    public $description = 'Allow to send a Mail to a list or recipients, based on a Log trigger. Requires functional misp-modules to be functional.';
    public $icon = 'envelope';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = false;
    public $params = [];

    protected function getRecipientsList() : array
    {
        $rcpts = array_merge(
            ['All accounts'],
            ['All admins'],
            ['Org admins'],
            array_column(array_column($this->all_users, 'User'), 'email'));
        return $rcpts;
    }

    protected function conditionsFromRData(&$conditions, &$params, $rData)
    {
        // transform 'Org admins' to a search condition 
        if (in_array('Org admins', $params['recipients']['value'])) {
            $params['recipients']['value'] = array_diff($params['recipients']['value'], ['Org admins']);
            $org_id = $this->User->find('first', [
                'conditions' => ['User.id' => $rData['Log']['user_id']],
                'recursive' => -1,
                'fields' => [ 'org_id']
            ]);
            if (empty($org_id)) return;  // when user_id=0 or other cases we need to have a fail open to not break all email
            $admin_roles = $this->User->Role->find('all', [
                'conditions' => ['Role.perm_admin' => '1'],
                'fields' => 'Role.id']);
            $conditions['OR'][]['AND'] = [
                'User.role_id' => Hash::extract($admin_roles, '{n}.Role.id'),
                'User.org_id' => Hash::extract($org_id, 'User.org_id')
            ];
        }
        // no need to return as variables are passed as reference
    }


}
