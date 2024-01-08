<?php
namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Utility\Hash;
use Cake\Database\Schema\TableSchemaInterface;
// use Cake\Database\Type;
use Cake\ORM\Table;
use Cake\ORM\RulesChecker;
use Cake\Validation\Validator;
use Cake\Http\Exception\NotFoundException;

use App\Utility\UI\Notification;

// Type::map('json', 'Cake\Database\Type\JsonType'); // Not sure what it is for but it was in Cerebrate

class InboxTable extends AppTable
{
    public const SEVERITY_PRIMARY   = 0,
        SEVERITY_INFO               = 1,
        SEVERITY_WARNING            = 2,
        SEVERITY_DANGER             = 3;

    public $severityVariant = [
        self::SEVERITY_PRIMARY  => 'primary',
        self::SEVERITY_INFO     => 'info',
        self::SEVERITY_WARNING  => 'warning',
        self::SEVERITY_DANGER   => 'danger',
    ];

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('UUID');
        $this->addBehavior('Timestamp');
        $this->addBehavior('AuditLog');
        $this->addBehavior(
            'JsonFields',
            [
                'fields' => ['data' => []],
            ]
        );
        $this->belongsTo('Users');
        $this->setDisplayField('title');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('scope')
            ->notEmptyString('action')
            ->notEmptyString('title')
            ->notEmptyString('origin')
            ->datetime('created')

            ->requirePresence([
                'scope' => ['message' => __('The field `scope` is required')],
                'action' => ['message' => __('The field `action` is required')],
                'title' => ['message' => __('The field `title` is required')],
                'origin' => ['message' => __('The field `origin` is required')],
            ], 'create');
        return $validator;
    }

    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->existsIn('user_id', 'Users'), [
            'message' => 'The provided `user_id` does not exist'
        ]);

        return $rules;
    }

    public function getAllUsername($currentUser): array
    {
        $this->Users = \Cake\ORM\TableRegistry::getTableLocator()->get('Users');
        $conditions = [];
        if (empty($currentUser['role']['perm_admin'])) {
            $conditions['organisation_id IN'] = [$currentUser['organisation_id']];
        }
        $users = $this->Users->find()->where($conditions)->all()->extract('username')->toList();
        return Hash::combine($users, '{n}', '{n}');
    }

    public function createEntry($entryData)
    {
        $savedEntry = $this->save($entryData);
        return $savedEntry;
    }

    public function collectNotifications(\App\Model\Entity\User $user): array
    {
        $allNotifications = [];
        $inboxNotifications = $this->getNotificationsForUser($user);
        foreach ($inboxNotifications as $notification) {
            $title = $notification->title;
            $details = $notification->message;
            $router = [
                'controller' => 'inbox',
                'action' => 'process',
                'plugin' => null,
                $notification->id
            ];
            $allNotifications[] = (new Notification($title, $router, [
                'icon' => 'envelope',
                'details' => $details,
                'datetime' => $notification->created,
                'variant' => $notification->severity_variant,
                '_useModal' => true,
                '_sidebarId' => 'inbox',
            ]))->get();
        }
        return $allNotifications;
    }

    public function getNotificationsForUser(\App\Model\Entity\User $user): iterable
    {
        $query = $this->find();
        $conditions = [
            'Inbox.user_id' => $user->id
        ];
        $query->where($conditions);
        $notifications = $query->all();
        return $notifications;
    }
}
