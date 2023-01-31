<?php
    if (!empty($row['user'])) {
        if (isset($row['user']['id'])) {
            $users = [$row['user']];
        } else {
            $users = $row['user'];
        }
        $links = [];
        foreach ($users as $user) {
            $orgPrepend = '';
            if (!empty($user['organisation']['name']) && !empty($user['organisation']['id'])) {
                $orgPrepend = '[' . $this->Html->link(
                    h($user['organisation']['name']),
                    ['controller' => 'organisations', 'action' => 'view', $user['organisation']['id']]
                ) . '] ';
            }
            $links[] = $orgPrepend . $this->Html->link(
                h($user['username']),
                ['controller' => 'users', 'action' => 'view', $user['id']]
            );
        }
        echo implode('<br />', $links);
    }

?>
