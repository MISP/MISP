<?php

/**
 * @property User $User
 * @property Log $Log
 * @property UserLoginProfile $UserLoginProfile
 */
class OrganisationShell extends AppShell
{
    public $uses = ['Organisation'];

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('list', [
            'help' => __('Get list of organisations.'),
            'parser' => [
                'arguments' => [
                    'filter' => ['help' => __('Filter the list by name.'), 'required' => false],
                    'local' => ['help' => __('Filter the list by local/known organisations.'), 'required' => false],
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
        $local = isset($this->args[1]) ? $this->args[1] : null;
        $conditions = [];
        if ($filter) {
            $conditions = ['OR' => [
                'Organisation.name LIKE' => "%$filter%",
                'Organisation.uuid LIKE' => "%$filter%"
            ]];
        }
        if ($local !== null) {
            $conditions['OR'][] = [
                'Organisation.local' => $local
            ];
        }
        $organisations = $this->Organisation->find('all', [
            'recursive' => -1,
            'conditions' => $conditions
        ]);
        if ($this->params['json']) {
            $this->out($this->json($organisations));
        } else {
            foreach ($organisations as $organisation) {
                $this->out(sprintf(
                    '%d. [%s] %s',
                    $organisation['Organisation']['id'],
                    $organisation['Organisation']['uuid'],
                    $organisation['Organisation']['name']
                ));
            }
            $this->out(count($organisations) . ' hits.');
        }
    }
}
