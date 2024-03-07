<?php

/**
 * @property User $User
 * @property Log $Log
 * @property UserLoginProfile $UserLoginProfile
 */
class RoleShell extends AppShell
{
    public $uses = ['Role'];

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('list', [
            'help' => __('Get list of the roles.'),
            'parser' => [
                'arguments' => [
                    'filter' => ['help' => __('Filter list by name.'), 'required' => false],
                ],
                'options' => [
                    'json' => ['help' => __('Output as JSON.'), 'boolean' => true],
                ],
            ]
        ]);
        return $parser;
    }

    public function list()
    {
        $filter = $this->args[0] ?? null;
        if ($filter) {
            $conditions = ['OR' => [
                'Role.name LIKE' => "%$filter%"
            ]];
        } else {
            $conditions = [];
        }
        $roles = $this->Role->find('all', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
        if ($this->params['json']) {
            $this->out($this->json($roles));
        } else {
            foreach ($roles as $role) {
                $this->out(sprintf(
                    '%d. %s',
                    $role['Role']['id'],
                    $role['Role']['name']
                ));
            }
        }
        $this->out(count($roles) . ' hits.');
    }
}
