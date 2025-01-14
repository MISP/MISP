<?php

App::uses('Component', 'Controller');


class NotificationComponent extends Component
{
    private $tables = [
        'Inbox',
    ];

    public function initialize(Controller $controller) {
        $this->Controller = $controller;
        $this->request = $controller->request;
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
            $table = ClassRegistry::init($tableName);
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
