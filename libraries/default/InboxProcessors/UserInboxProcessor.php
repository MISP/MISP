<?php
use Cake\ORM\TableRegistry;
use Authentication\PasswordHasher\DefaultPasswordHasher;

require_once(ROOT . DS . 'libraries' . DS . 'default' . DS . 'InboxProcessors' . DS . 'GenericInboxProcessor.php'); 

class UserInboxProcessor extends GenericInboxProcessor
{
    protected $scope = 'User';
    protected $action = 'not-specified'; //overriden when extending
    protected $description = ''; // overriden when extending
    protected $registeredActions = [
        'Registration'
    ];
    protected $Users;

    public function __construct($loadFromAction=false) {
        parent::__construct($loadFromAction);
        $this->Users = TableRegistry::getTableLocator()->get('Users');
    }

    public function create($requestData)
    {
        return parent::create($requestData);
    }
}

class RegistrationProcessor extends UserInboxProcessor implements GenericInboxProcessorActionI {
    public $action = 'Registration';
    protected $description;

    public function __construct() {
        parent::__construct();
        $this->description = __('Handle user account for this cerebrate instance');
    }

    protected function addValidatorRules($validator)
    {
        return $validator
            ->notEmptyString('username', 'A username must be provided.')
            ->add('email', 'validFormat', [
                'rule' => 'email',
                'message' => 'E-mail must be valid'
            ])
            ->notEmptyString('first_name', 'A first name must be provided')
            ->notEmptyString('last_name', 'A last name must be provided')
            ->add('password', 'password_complexity', [
                'rule' => function($value, $context) {
                    if (!preg_match('/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/s', $value) || strlen($value) < 12) {
                        return false;
                    }
                    return true;
                },
                'message' => __('Invalid password. Passwords have to be either 16 character long or 12 character long with 3/4 special groups.')
            ]);
    }
    
    public function create($requestData) {
        $this->validateRequestData($requestData);
        $requestData['data']['password'] = (new DefaultPasswordHasher())->hash($requestData['data']['password']);
        $requestData['title'] = __('User account creation requested for {0}', $requestData['data']['email']);
        $creationResponse = parent::create($requestData);
        $creationResponse['message'] = __('User account creation requested. Please wait for an admin to approve your account.');
        return $creationResponse;
    }

    public function getViewVariables($request)
    {
        $dropdownData = [
            'role' => $this->Users->Roles->find('list', [
                'sort' => ['name' => 'asc']
            ]),
            'organisation' => $this->Users->Organisations->find('list', [
                'sort' => ['name' => 'asc']
            ]),
            'individual' => [-1 => __('-- New individual --')] + $this->Users->Individuals->find('list', [
                'sort' => ['email' => 'asc']
            ])->toArray()
        ];
        $individualEntity = $this->Users->Individuals->newEntity([
            'email' => !empty($request['data']['email']) ? $request['data']['email'] : '',
            'first_name' => !empty($request['data']['first_name']) ? $request['data']['first_name'] : '',
            'last_name' => !empty($request['data']['last_name']) ? $request['data']['last_name'] : '',
            'position' => !empty($request['data']['position']) ? $request['data']['position'] : '',
        ]);
        $userEntity = $this->Users->newEntity([
            'individual_id' => -1,
            'username' => !empty($request['data']['username']) ? $request['data']['username'] : '',
            'role_id' => !empty($request['data']['role_id']) ? $request['data']['role_id'] : '',
            'disabled' => !empty($request['data']['disabled']) ? $request['data']['disabled'] : '',

            'email' => !empty($request['data']['email']) ? $request['data']['email'] : '',
            'first_name' => !empty($request['data']['first_name']) ? $request['data']['first_name'] : '',
            'last_name' => !empty($request['data']['last_name']) ? $request['data']['last_name'] : '',
            'position' => !empty($request['data']['position']) ? $request['data']['position'] : '',
        ]);
        return [
            'dropdownData' => $dropdownData,
            'userEntity' => $userEntity,
            'individualEntity' => $individualEntity
        ];
    }

    public function process($id, $requestData, $inboxRequest)
    {
        $hashedPassword = $inboxRequest['data']['password'];
        if ($requestData['individual_id'] == -1) {
            $individual = $this->Users->Individuals->newEntity([
                'uuid' => $requestData['uuid'],
                'email' => $requestData['email'],
                'first_name' => $requestData['first_name'],
                'last_name' => $requestData['last_name'],
                'position' => $requestData['position'],
            ]);
            $individual = $this->Users->Individuals->save($individual);
        } else {
            $individual = $this->Users->Individuals->get($requestData['individual_id']);
        }
        $user = $this->Users->newEntity([
            'individual_id' => $individual->id,
            'username' => $requestData['username'],
            'password' => '~PASSWORD_TO_BE_REPLACED~',
            'role_id' => $requestData['role_id'],
            'disabled' => $requestData['disabled'],
        ]);
        $user->set('password', $hashedPassword, ['setter' => false]); // ignore default password hashing as it has already been hashed
        $user = $this->Users->save($user);

        if ($user !== false) {
            $this->discard($id, $requestData);
        }
        return $this->genActionResult(
            $user,
            $user !== false,
            $user !== false ? __('User `{0}` created', $user->username) : __('Could not create user `{0}`.', $user->username),
            $user->getErrors()
        );
    }

    public function discard($id, $requestData)
    {
        return parent::discard($id, $requestData);
    }
}