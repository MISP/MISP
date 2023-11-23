<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

class Module_send_mail extends WorkflowBaseActionModule
{
    public $id = 'send-mail';
    public $name = 'Send Mail';
    public $description = 'Allow to send a Mail to a list or recipients. Requires functional misp-modules to be functional.';
    public $icon = 'envelope';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = false;
    public $params = [];

    protected $User;
    protected $all_users;

    public function __construct()
    {
        parent::__construct();

        $this->User = ClassRegistry::init('User');
        $this->all_users = $this->User->find('all', [
            'conditions' => [],
            'recursive' => -1,
        ]);
        $users = $this->getRecipientsList();
        $this->params = [
            [
                'id' => 'recipients',
                'label' => 'Recipients',
                'type' => 'picker',
                'multiple' => true,
                'options' => $users,
                'default' => ['All admins'],
            ],
            [
                'id' => 'mail_template_subject',
                'label' => 'Mail template subject',
                'type' => 'textarea',
                'placeholder' => __('The **template** will be rendered using *Jinja2*!'),
                'jinja_supported' => true,
            ],
            [
                'id' => 'mail_template_body',
                'label' => 'Mail template body',
                'type' => 'textarea',
                'placeholder' => __('The **template** will be rendered using *Jinja2*!'),
                'jinja_supported' => true,
            ],
        ];
    }

    protected function getRecipientsList() : array
    {
        return array_merge(
            ['All accounts'],
            ['All admins'],
            array_column(array_column($this->all_users, 'User'), 'email'));
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['recipients']['value'])) {
            $errors[] = __('No recipient set.');
            return false;
        }
        if (empty($params['mail_template_subject']['value'])) {
            $errors[] = __('The mail template is empty.');
            return false;
        }

        $renderedBody = $params['mail_template_body']['value'];
        $renderedSubject = $params['mail_template_subject']['value'];

        $users = [];
        if (in_array('All accounts', $params['recipients']['value'])) {
            $users = $this->all_users;
        } else {
            $conditions = [];
            // transform 'All admins' to a search condition 
            if (in_array('All admins', $params['recipients']['value'])) {
                $params['recipients']['value'] = array_diff($params['recipients']['value'], ['All admins']);
                $admin_roles = $this->User->Role->find('all', [
                    'conditions' => ['Role.perm_site_admin' => '1'],
                    'fields' => 'Role.id']);
                $conditions['OR']['User.role_id'] = Hash::extract($admin_roles, '{n}.Role.id'); 
            }
            // call any subclass function using the data
            $this->conditionsFromRData($conditions, $params, $rData);  // variables are passed as reference
            // last but not least, add the remaining items from the list
            if (!empty($params['recipients']['value']))
                $conditions['OR']['User.email'] = $params['recipients']['value'];
            if (empty($conditions)) {
                return false;
            }
            $users = $this->User->find('all', [
                'conditions' => $conditions,
                'recursive' => 0,
            ]);
        }

        foreach ($users as $user) {
            $this->sendMail($user, $renderedBody, $renderedSubject);
        }
        return true;
    }

    protected function conditionsFromRData(&$conditions, &$params, $rData)
    {
    }

    protected function sendMail(array $user, string $content, string $subject): void
    {
        $res = $this->User->sendEmail($user, $content, false, $subject);
    }
}
