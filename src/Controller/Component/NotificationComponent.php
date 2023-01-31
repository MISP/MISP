<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use Cake\Core\Configure;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\ORM\TableRegistry;

class NotificationComponent extends Component
{
    private $tables = [
        'Inbox',
    ];

    public function initialize(array $config): void
    {
        $this->request = $config['request'];
        $this->Controller = $this->getController();
    }

    public function getNotifications(): array
    {
        $notifications = [];
        $notifications = $this->collectNotificationsFromTables();
        return $notifications;
    }

    private function collectNotificationsFromTables(): array
    {
        $notifications = [];
        foreach ($this->tables as $tableName) {
            $table = TableRegistry::getTableLocator()->get($tableName);
            $tableNotifications = $this->collectNotificationFromTable($table);
            $notifications = array_merge($notifications, $tableNotifications);
        }
        return $notifications;
    }

    private function collectNotificationFromTable($table): array
    {
        $notifications = [];
        if (method_exists($table, 'collectNotifications')) {
            $notifications = $table->collectNotifications($this->Controller->ACL->getUser());
        }
        return $notifications;
    }
}
