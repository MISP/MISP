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

    private $User;
    private $all_users;

    public function __construct()
    {
        parent::__construct();

        $this->User = ClassRegistry::init('User');
        $this->all_users = $this->User->find('all', [
            'conditions' => [],
            'recursive' => -1,
        ]);
        $users = array_merge(['All accounts'], array_column(array_column($this->all_users, 'User'), 'email'));
        $this->params = [
            [
                'id' => 'recipients',
                'label' => 'Recipients',
                'type' => 'picker',
                'multiple' => true,
                'options' => $users,
                'default' => ['All accounts'],
            ],
            [
                'id' => 'mail_template_subject',
                'label' => 'Mail template subject',
                'type' => 'textarea',
                'placeholder' => __('The **template** will be rendered using *Jinja2*!'),
            ],
            [
                'id' => 'mail_template_body',
                'label' => 'Mail template body',
                'type' => 'textarea',
                'placeholder' => __('The **template** will be rendered using *Jinja2*!'),
            ],
        ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $params = $this->getParamsWithValues($node);
        if (empty($params['recipients']['value'])) {
            $errors[] = __('No recipient set.');
            return false;
        }
        if (empty($params['mail_template_subject']['value'])) {
            $errors[] = __('The mail template is empty.');
            return false;
        }
        $rData = $roamingData->getData();

        $renderedBody = $this->render_jinja_template($params['mail_template_body']['value'], $rData);
        $renderedSubject = $this->render_jinja_template($params['mail_template_subject']['value'], $rData);

        $users = [];
        if (in_array('All accounts', $params['recipients']['value'])) {
            $users = $this->all_users;
        } else {
            $users = $this->User->find('all', [
                'conditions' => [
                    'User.email' => $params['recipients']['value']
                ],
                'recursive' => -1,
            ]);
        }

        foreach ($users as $user) {
            $this->sendMail($user, $renderedBody, $renderedSubject);
        }
        return true;
    }

    protected function sendMail(array $user, string $content, string $subject): void
    {
        $res = $this->User->sendEmail($user, $content, false, $subject);
    }
}
