<?php

/**
 * MISP Interactive CLI Shell
 *
 * Provides an interactive REPL for browsing and managing MISP data.
 * Launch: cake CLI <user_id>
 *
 * @property Event $Event
 * @property MispAttribute $MispAttribute
 * @property MispObject $MispObject
 * @property Tag $Tag
 * @property EventTag $EventTag
 * @property AttributeTag $AttributeTag
 * @property Organisation $Organisation
 * @property User $User
 * @property Server $Server
 * @property Feed $Feed
 * @property SharingGroup $SharingGroup
 * @property Galaxy $Galaxy
 * @property Taxonomy $Taxonomy
 * @property Warninglist $Warninglist
 * @property GalaxyCluster $GalaxyCluster
 */
class CLIShell extends AppShell
{
    public $uses = [
        'Event',
        'MispAttribute',
        'MispObject',
        'Tag',
        'EventTag',
        'AttributeTag',
        'Organisation',
        'User',
        'Server',
        'Feed',
        'SharingGroup',
        'Galaxy',
        'Taxonomy',
        'Warninglist',
        'GalaxyCluster',
    ];

    /** @var array Authenticated user array */
    private $__user = null;

    /** @var array Navigation context ['entity' => null, 'id' => null] */
    private $__context = ['entity' => null, 'id' => null];

    /** @var int Current pagination page */
    private $__page = 1;

    /** @var int Items per page */
    private $__perPage = 20;

    /** @var array|null Cached last query params for next/prev */
    private $__lastQuery = null;

    /** @var resource File handle for stdin */
    private $__stdin = null;

    /** @var int Currently highlighted row in browse mode (0-based) */
    private $__selectedIndex = 0;

    /** @var int Viewport offset for scrolling in browse mode */
    private $__viewportOffset = 0;

    /** @var array Current page of results for browse mode */
    private $__browseData = [];

    /** @var bool Whether stdout is a TTY */
    private $__isTty = false;

    /** @var bool Whether we are in raw terminal mode */
    private $__rawMode = false;

    /** @var array Entity configuration registry */
    private $__entityConfig = [
        'event' => [
            'model' => 'Event',
            'aliases' => ['events'],
            'listFields' => [
                'id', 'date', 'info',
                'Orgc.name', 'threat_level_id',
                'analysis', 'published',
            ],
            'editableFields' => [
                'info', 'date', 'distribution',
                'threat_level_id', 'analysis',
                'sharing_group_id',
            ],
        ],
        'attribute' => [
            'model' => 'MispAttribute',
            'aliases' => ['attributes'],
            'listFields' => [
                'id', 'event_id', 'type',
                'category', 'value', 'to_ids',
                'comment',
            ],
            'editableFields' => [],
        ],
        'object' => [
            'model' => 'MispObject',
            'aliases' => ['objects'],
            'listFields' => [
                'id', 'event_id', 'name',
                'meta-category', 'description',
                'template_version',
            ],
            'editableFields' => [],
        ],
        'tag' => [
            'model' => 'Tag',
            'aliases' => ['tags'],
            'listFields' => [
                'id', 'name', 'colour',
                'exportable', 'hide_tag',
            ],
            'editableFields' => [
                'name', 'colour', 'exportable',
            ],
        ],
        'user' => [
            'model' => 'User',
            'aliases' => ['users'],
            'listFields' => [
                'id', 'email', 'org_id',
                'role_id', 'disabled',
            ],
            'editableFields' => [],
            'adminOnly' => true,
        ],
        'organisation' => [
            'model' => 'Organisation',
            'aliases' => ['organisations', 'org', 'orgs'],
            'listFields' => [
                'id', 'name', 'uuid',
                'nationality', 'sector',
            ],
            'editableFields' => [],
        ],
        'server' => [
            'model' => 'Server',
            'aliases' => ['servers'],
            'listFields' => [
                'id', 'name', 'url',
                'push', 'pull',
            ],
            'editableFields' => [],
            'adminOnly' => true,
        ],
        'feed' => [
            'model' => 'Feed',
            'aliases' => ['feeds'],
            'listFields' => [
                'id', 'name', 'provider',
                'url', 'enabled',
            ],
            'editableFields' => [],
        ],
        'sharing_group' => [
            'model' => 'SharingGroup',
            'aliases' => ['sharing_groups', 'sharinggroup', 'sharinggroups'],
            'listFields' => [
                'id', 'name', 'description',
                'org_id', 'active',
            ],
            'editableFields' => [],
        ],
        'galaxy' => [
            'model' => 'Galaxy',
            'aliases' => ['galaxies'],
            'listFields' => [
                'id', 'name', 'type',
                'namespace', 'version',
            ],
            'editableFields' => [],
        ],
        'taxonomy' => [
            'model' => 'Taxonomy',
            'aliases' => ['taxonomies'],
            'listFields' => [
                'id', 'namespace', 'description',
                'version', 'enabled',
            ],
            'editableFields' => [],
        ],
        'warninglist' => [
            'model' => 'Warninglist',
            'aliases' => ['warninglists'],
            'listFields' => [
                'id', 'name', 'type',
                'description', 'enabled',
            ],
            'editableFields' => [],
        ],
    ];

    /**
     * @return ConsoleOptionParser
     */
    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->description(
            'MISP Interactive CLI Shell - browse and manage '
            . 'MISP data from the command line.'
        );
        $parser->addArgument('user_id', [
            'help' => 'User ID to authenticate as. '
                . 'All operations are ACL-scoped to this user.',
            'required' => true,
        ]);
        return $parser;
    }

    /**
     * Main REPL entry point.
     *
     * @return void
     */
    public function main()
    {
        $userId = isset($this->args[0]) ? $this->args[0] : null;
        if (empty($userId) || !is_numeric($userId)) {
            $this->err('Usage: cake CLI <user_id>');
            return;
        }

        $user = $this->User->getAuthUser((int)$userId, true);
        if (empty($user)) {
            $this->err(
                'Error: User with ID ' . $userId . ' not found.'
            );
            return;
        }
        $this->__user = $user;

        $this->__isTty = function_exists('posix_isatty')
            && posix_isatty(STDOUT);
        $this->__stdin = fopen('php://stdin', 'r');

        register_shutdown_function([$this, 'restoreTerminal']);

        $this->__printWelcome();

        while (true) {
            $prompt = $this->__buildPrompt();
            if ($this->__isTty) {
                $this->out($prompt, 0);
                $line = fgets($this->__stdin);
            } else {
                $line = fgets($this->__stdin);
            }

            if ($line === false) {
                $this->out('');
                break;
            }

            $line = trim($line);
            if ($line === '') {
                continue;
            }

            if ($line === 'exit' || $line === 'quit') {
                break;
            }

            $this->__dispatch($line);
        }

        $this->__cleanup();
    }

    /**
     * Print welcome banner.
     *
     * @return void
     */
    private function __printWelcome()
    {
        $email = $this->__user['email'];
        $emailParts = explode('@', $email);
        $username = $emailParts[0];
        $orgName = '';
        if (!empty($this->__user['Organisation']['name'])) {
            $orgName = $this->__user['Organisation']['name'];
        } elseif (!empty($this->__user['org_id'])) {
            $org = $this->Organisation->find('first', [
                'conditions' => [
                    'Organisation.id' => $this->__user['org_id'],
                ],
                'fields' => ['Organisation.name'],
                'recursive' => -1,
            ]);
            if (!empty($org)) {
                $orgName = $org['Organisation']['name'];
            }
        }
        $role = '';
        if (!empty($this->__user['Role']['perm_site_admin'])) {
            $role = ' [Site Admin]';
        } elseif (!empty($this->__user['Role']['perm_admin'])) {
            $role = ' [Org Admin]';
        }

        $this->out('');
        $this->out(
            'Welcome to MISP Interactive CLI Shell v1.0'
        );
        $this->out(
            'Logged in as: ' . $email
            . ' (' . $orgName . ')' . $role
        );
        $this->out("Type 'help' for available commands.");
        $this->out('');
    }

    /**
     * Build the REPL prompt string.
     *
     * @return string
     */
    private function __buildPrompt()
    {
        $email = $this->__user['email'];
        $emailParts = explode('@', $email);
        $username = $emailParts[0];
        $orgName = '';
        if (!empty($this->__user['Organisation']['name'])) {
            $orgName = $this->__user['Organisation']['name'];
        }

        $contextStr = '';
        if (
            !empty($this->__context['entity'])
            && !empty($this->__context['id'])
        ) {
            $contextStr = ' '
                . $this->__context['entity']
                . ':' . $this->__context['id'];
        }

        return 'MISP [' . $username . '@' . $orgName . ']'
            . $contextStr . ' > ';
    }

    /**
     * Parse and dispatch a command line.
     *
     * @param string $line Raw input line
     * @return void
     */
    private function __dispatch($line)
    {
        $parsed = $this->__parseCommand($line);
        if ($parsed === false) {
            return;
        }

        $command = $parsed['command'];
        $entity = $parsed['entity'];
        $id = $parsed['id'];
        $args = $parsed['args'];

        switch ($command) {
            case 'help':
                $this->__cmdHelp($entity);
                break;
            case 'context':
                $this->__cmdContext();
                break;
            case 'clear':
                $this->__cmdClear();
                break;
            case 'use':
                $this->__cmdUse($entity, $id);
                break;
            case 'list':
                $this->__cmdList($entity, $args);
                break;
            case 'view':
                $this->__cmdView($entity, $id);
                break;
            case 'search':
                $this->__cmdSearch($entity, $args);
                break;
            case 'next':
                $this->__cmdNext();
                break;
            case 'prev':
                $this->__cmdPrev();
                break;
            default:
                $this->err(
                    "Unknown command: '" . $command . "'. "
                    . "Type 'help' for available commands."
                );
                break;
        }
    }

    /**
     * Parse a command line into structured parts.
     *
     * @param string $line Raw input
     * @return array|false Parsed command or false on error
     */
    private function __parseCommand($line)
    {
        $tokens = $this->__tokenize($line);
        if (empty($tokens)) {
            return false;
        }

        $command = strtolower(array_shift($tokens));
        $entity = null;
        $id = null;
        $args = [];

        if (!empty($tokens)) {
            $next = $tokens[0];
            if (strpos($next, '=') === false) {
                $resolved = $this->__resolveEntity($next);
                if ($resolved !== false) {
                    $entity = $resolved;
                    array_shift($tokens);
                }
            }
        }

        if (!empty($tokens)) {
            $next = $tokens[0];
            if (
                is_numeric($next)
                && strpos($next, '=') === false
            ) {
                $id = (int)$next;
                array_shift($tokens);
            }
        }

        $args = $tokens;

        return [
            'command' => $command,
            'entity' => $entity,
            'id' => $id,
            'args' => $args,
        ];
    }

    /**
     * Tokenize input, respecting quoted strings.
     *
     * @param string $line Raw input
     * @return array Tokens
     */
    private function __tokenize($line)
    {
        $tokens = [];
        $current = '';
        $inQuote = false;
        $quoteChar = '';
        $len = strlen($line);

        for ($i = 0; $i < $len; $i++) {
            $ch = $line[$i];
            if ($inQuote) {
                if ($ch === $quoteChar) {
                    $inQuote = false;
                } else {
                    $current .= $ch;
                }
            } elseif ($ch === '"' || $ch === "'") {
                $inQuote = true;
                $quoteChar = $ch;
            } elseif ($ch === ' ' || $ch === "\t") {
                if ($current !== '') {
                    $tokens[] = $current;
                    $current = '';
                }
            } else {
                $current .= $ch;
            }
        }
        if ($current !== '') {
            $tokens[] = $current;
        }

        return $tokens;
    }

    /**
     * Resolve an entity name (or alias) to canonical name.
     *
     * @param string $name Entity name or alias
     * @return string|false Canonical name or false
     */
    private function __resolveEntity($name)
    {
        $name = strtolower($name);
        if (isset($this->__entityConfig[$name])) {
            return $name;
        }
        foreach ($this->__entityConfig as $canonical => $config) {
            if (in_array($name, $config['aliases'], true)) {
                return $canonical;
            }
        }
        return false;
    }

    /**
     * Get terminal size as [cols, rows].
     *
     * @return array [cols, rows]
     */
    private function __getTerminalSize()
    {
        $output = shell_exec('stty size 2>/dev/null');
        if (!empty($output)) {
            $parts = explode(' ', trim($output));
            if (count($parts) === 2) {
                return [(int)$parts[1], (int)$parts[0]];
            }
        }
        return [80, 24];
    }

    /**
     * help command.
     *
     * @param string|null $topic Specific command to show help for
     * @return void
     */
    private function __cmdHelp($topic = null)
    {
        if ($topic === null) {
            $this->out('Available commands:');
            $this->out('');
            $this->out(
                '  list <entity> [filters]'
                . '  - Paginated list with optional filters'
            );
            $this->out(
                '  view <entity> <id>'
                . '      - Detailed view of a single record'
            );
            $this->out(
                '  search <entity> [filters]'
                . ' - Search with filters'
            );
            $this->out(
                '  use <entity> <id>'
                . '       - Set navigation context'
            );
            $this->out(
                '  context'
                . '                  - Show current context'
            );
            $this->out(
                '  clear'
                . '                    - Clear navigation context'
            );
            $this->out(
                '  next / prev'
                . '              - Next/previous page'
            );
            $this->out(
                '  help [command]'
                . '           - Show help'
            );
            $this->out(
                '  exit / quit'
                . '              - Exit the shell'
            );
            $this->out('');
            $this->out('Entities: ' . implode(
                ', ',
                array_keys($this->__entityConfig)
            ));
            $this->out('');
            $this->out(
                "Type 'help filters' for filter syntax."
            );
            return;
        }

        if ($topic === 'filters' || $topic === 'filter') {
            $this->out('Filter Syntax:');
            $this->out('');
            $this->out('  key=value         Exact match');
            $this->out('  key=a,b,c         OR (any of)');
            $this->out('  key=!value        NOT (exclude)');
            $this->out(
                '  tag=X,Y           Tag OR'
            );
            $this->out(
                '  tag+=X            Tag AND (must have)'
            );
            $this->out(
                '  tag=!X            Tag NOT'
            );
            $this->out(
                '  from=YYYY-MM-DD   Date range start'
            );
            $this->out(
                '  to=YYYY-MM-DD     Date range end'
            );
            $this->out(
                '  last=7d           Relative time (d/h/m)'
            );
            $this->out(
                '  searchall=text    Wildcard across fields'
            );
            $this->out(
                '  value=%text%      LIKE match'
            );
            return;
        }

        $this->out(
            "No detailed help available for '" . $topic . "'."
        );
    }

    /**
     * context command - show current context.
     *
     * @return void
     */
    private function __cmdContext()
    {
        if (
            empty($this->__context['entity'])
            || empty($this->__context['id'])
        ) {
            $this->out('No context set.');
        } else {
            $this->out(
                'Current context: '
                . $this->__context['entity']
                . ':' . $this->__context['id']
            );
        }
    }

    /**
     * clear command - clear navigation context.
     *
     * @return void
     */
    private function __cmdClear()
    {
        $this->__context = ['entity' => null, 'id' => null];
        $this->out('Context cleared.');
    }

    /**
     * use command - set navigation context.
     *
     * @param string|null $entity Entity name
     * @param int|null $id Entity ID
     * @return void
     */
    private function __cmdUse($entity, $id)
    {
        if (empty($entity)) {
            $this->err('Usage: use <entity> <id>');
            return;
        }
        if (empty($id)) {
            $this->err('Usage: use <entity> <id>');
            return;
        }
        if (!isset($this->__entityConfig[$entity])) {
            $this->err("Unknown entity: '" . $entity . "'");
            return;
        }
        $this->__context = [
            'entity' => $entity,
            'id' => $id,
        ];
        $this->out(
            'Context set to '
            . $entity . ':' . $id
        );
    }

    /**
     * list command - paginated listing.
     *
     * @param string|null $entity Entity name
     * @param array $args Filter arguments
     * @return void
     */
    private function __cmdList($entity, $args)
    {
        if (empty($entity)) {
            $this->err(
                'Usage: list <entity> [key=value ...]'
            );
            return;
        }
        if (!isset($this->__entityConfig[$entity])) {
            $this->err("Unknown entity: '" . $entity . "'");
            return;
        }
        $config = $this->__entityConfig[$entity];
        if (
            !empty($config['adminOnly'])
            && empty($this->__user['Role']['perm_site_admin'])
        ) {
            $this->err(
                'Permission denied: '
                . $entity . ' requires site admin access.'
            );
            return;
        }

        $filters = $this->__parseFilters($args);

        if (!isset($filters['limit'])) {
            $filters['limit'] = $this->__perPage;
        }
        if (!isset($filters['page'])) {
            $filters['page'] = 1;
        }
        $this->__page = (int)$filters['page'];

        $this->__lastQuery = [
            'entity' => $entity,
            'filters' => $filters,
        ];

        $results = $this->__fetchList($entity, $filters);
        if (empty($results)) {
            $this->out('No results found.');
            return;
        }

        if ($this->__isTty) {
            $this->__browseData = $results;
            $this->__selectedIndex = 0;
            $this->__viewportOffset = 0;
            $this->__browseLoop(
                $entity,
                $config['listFields']
            );
        } else {
            $this->__renderStaticTable(
                $entity,
                $results,
                $config['listFields']
            );
        }
    }

    /**
     * view command - show single record detail.
     *
     * @param string|null $entity Entity name
     * @param int|null $id Entity ID
     * @return void
     */
    private function __cmdView($entity, $id)
    {
        if (empty($entity)) {
            $this->err('Usage: view <entity> <id>');
            return;
        }
        if (!isset($this->__entityConfig[$entity])) {
            $this->err("Unknown entity: '" . $entity . "'");
            return;
        }
        if (empty($id) && !is_numeric($id)) {
            $this->err('Usage: view <entity> <id>');
            return;
        }
        if (!is_numeric($id)) {
            $this->err("Invalid ID: '" . $id . "'");
            return;
        }

        $config = $this->__entityConfig[$entity];
        if (
            !empty($config['adminOnly'])
            && empty($this->__user['Role']['perm_site_admin'])
        ) {
            $this->err(
                'Permission denied: '
                . $entity . ' requires site admin access.'
            );
            return;
        }

        $record = $this->__fetchDetail($entity, (int)$id);
        if (empty($record)) {
            $this->err(
                ucfirst($entity)
                . ' with ID ' . $id . ' not found.'
            );
            return;
        }

        $this->__renderDetail($entity, $record);

        if (in_array($entity, ['event', 'object'])) {
            $this->__context = [
                'entity' => $entity,
                'id' => (int)$id,
            ];
        }
    }

    /**
     * search command - search with filters.
     *
     * @param string|null $entity Entity name
     * @param array $args Filter arguments
     * @return void
     */
    private function __cmdSearch($entity, $args)
    {
        $this->__cmdList($entity, $args);
    }

    /**
     * next command - go to next page.
     *
     * @return void
     */
    private function __cmdNext()
    {
        if (empty($this->__lastQuery)) {
            $this->err('No previous query to paginate.');
            return;
        }
        $this->__page++;
        $this->__lastQuery['filters']['page'] = $this->__page;
        $entity = $this->__lastQuery['entity'];
        $filters = $this->__lastQuery['filters'];
        $config = $this->__entityConfig[$entity];

        $results = $this->__fetchList($entity, $filters);
        if (empty($results)) {
            $this->__page--;
            $this->__lastQuery['filters']['page'] =
                $this->__page;
            $this->out('No more results.');
            return;
        }

        if ($this->__isTty) {
            $this->__browseData = $results;
            $this->__selectedIndex = 0;
            $this->__viewportOffset = 0;
            $this->__browseLoop(
                $entity,
                $config['listFields']
            );
        } else {
            $this->__renderStaticTable(
                $entity,
                $results,
                $config['listFields']
            );
        }
    }

    /**
     * prev command - go to previous page.
     *
     * @return void
     */
    private function __cmdPrev()
    {
        if (empty($this->__lastQuery)) {
            $this->err('No previous query to paginate.');
            return;
        }
        if ($this->__page <= 1) {
            $this->out('Already on the first page.');
            return;
        }
        $this->__page--;
        $this->__lastQuery['filters']['page'] = $this->__page;
        $entity = $this->__lastQuery['entity'];
        $filters = $this->__lastQuery['filters'];
        $config = $this->__entityConfig[$entity];

        $results = $this->__fetchList($entity, $filters);
        if ($this->__isTty) {
            $this->__browseData = $results;
            $this->__selectedIndex = 0;
            $this->__viewportOffset = 0;
            $this->__browseLoop(
                $entity,
                $config['listFields']
            );
        } else {
            $this->__renderStaticTable(
                $entity,
                $results,
                $config['listFields']
            );
        }
    }

    /**
     * Parse filter arguments into restSearch-compatible array.
     *
     * @param array $args Raw key=value arguments
     * @return array Filters
     */
    private function __parseFilters($args)
    {
        $filters = [];
        $tagsOr = [];
        $tagsAnd = [];
        $tagsNot = [];

        foreach ($args as $arg) {
            if (strpos($arg, '=') === false) {
                continue;
            }

            $eqPos = strpos($arg, '=');
            $key = substr($arg, 0, $eqPos);
            $value = substr($arg, $eqPos + 1);

            if ($key === 'tag+') {
                $tagsAnd[] = $value;
                continue;
            }
            if ($key === 'tag') {
                $parts = explode(',', $value);
                foreach ($parts as $part) {
                    if (strpos($part, '!') === 0) {
                        $tagsNot[] = substr($part, 1);
                    } else {
                        $tagsOr[] = $part;
                    }
                }
                continue;
            }

            if (strpos($value, ',') !== false) {
                $parts = explode(',', $value);
                $orValues = [];
                $notValues = [];
                foreach ($parts as $part) {
                    if (strpos($part, '!') === 0) {
                        $notValues[] = substr($part, 1);
                    } else {
                        $orValues[] = $part;
                    }
                }
                $filterValue = [];
                if (!empty($orValues)) {
                    $filterValue['OR'] = $orValues;
                }
                if (!empty($notValues)) {
                    $filterValue['NOT'] = $notValues;
                }
                $filters[$key] = $filterValue;
            } elseif (strpos($value, '!') === 0) {
                $filters[$key] = [
                    'NOT' => [substr($value, 1)],
                ];
            } else {
                $filters[$key] = $value;
            }
        }

        if (
            !empty($tagsOr)
            || !empty($tagsAnd)
            || !empty($tagsNot)
        ) {
            $tagFilter = [];
            if (!empty($tagsOr)) {
                $tagFilter['OR'] = $tagsOr;
            }
            if (!empty($tagsAnd)) {
                $tagFilter['AND'] = $tagsAnd;
            }
            if (!empty($tagsNot)) {
                $tagFilter['NOT'] = $tagsNot;
            }
            $filters['tags'] = $tagFilter;
        }

        return $filters;
    }

    /**
     * Fetch a list of records for the given entity.
     *
     * @param string $entity Canonical entity name
     * @param array $filters Filters
     * @return array Results
     */
    private function __fetchList($entity, $filters)
    {
        $limit = isset($filters['limit'])
            ? (int)$filters['limit'] : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        switch ($entity) {
            case 'event':
                return $this->__fetchEventList($filters);
            case 'attribute':
                return $this->__fetchAttributeList($filters);
            case 'object':
                return $this->__fetchObjectList($filters);
            case 'tag':
                return $this->__fetchTagList($filters);
            case 'user':
                return $this->__fetchSimpleList(
                    'User', $filters
                );
            case 'organisation':
                return $this->__fetchSimpleList(
                    'Organisation', $filters
                );
            case 'server':
                return $this->__fetchSimpleList(
                    'Server', $filters
                );
            case 'feed':
                return $this->__fetchSimpleList(
                    'Feed', $filters
                );
            case 'sharing_group':
                return $this->__fetchSharingGroupList(
                    $filters
                );
            case 'galaxy':
                return $this->__fetchSimpleList(
                    'Galaxy', $filters
                );
            case 'taxonomy':
                return $this->__fetchSimpleList(
                    'Taxonomy', $filters
                );
            case 'warninglist':
                return $this->__fetchSimpleList(
                    'Warninglist', $filters
                );
            default:
                return [];
        }
    }

    /**
     * Fetch event list using Event model.
     *
     * @param array $filters Filters
     * @return array
     */
    private function __fetchEventList($filters)
    {
        $params = [
            'minimal' => true,
            'limit' => isset($filters['limit'])
                ? (int)$filters['limit'] : $this->__perPage,
            'page' => isset($filters['page'])
                ? (int)$filters['page'] : 1,
        ];

        $passthrough = [
            'value', 'type', 'category', 'org',
            'orgc_id', 'tags', 'searchall', 'from',
            'to', 'last', 'eventid', 'uuid',
            'published', 'threat_level_id', 'analysis',
            'timestamp', 'publish_timestamp', 'order',
        ];
        foreach ($passthrough as $key) {
            if (isset($filters[$key])) {
                $params[$key] = $filters[$key];
            }
        }

        if (
            $this->__context['entity'] === 'event'
            && !empty($this->__context['id'])
            && !isset($params['eventid'])
        ) {
            $params['eventid'] = $this->__context['id'];
        }

        $eventIds = $this->Event->filterEventIds(
            $this->__user, $params
        );

        if (empty($eventIds)) {
            return [];
        }

        $ids = [];
        foreach ($eventIds as $row) {
            if (isset($row['Event']['id'])) {
                $ids[] = $row['Event']['id'];
            } elseif (is_numeric($row)) {
                $ids[] = $row;
            }
        }

        if (empty($ids)) {
            return [];
        }

        $events = $this->Event->find('all', [
            'conditions' => ['Event.id' => $ids],
            'fields' => [
                'Event.id', 'Event.date', 'Event.info',
                'Event.threat_level_id', 'Event.analysis',
                'Event.published', 'Event.orgc_id',
            ],
            'contain' => [
                'Orgc' => ['fields' => ['Orgc.name']],
            ],
            'order' => ['Event.id' => 'DESC'],
        ]);

        $results = [];
        foreach ($events as $event) {
            $results[] = [
                'id' => $event['Event']['id'],
                'date' => $event['Event']['date'],
                'info' => $event['Event']['info'],
                'Orgc.name' => isset($event['Orgc']['name'])
                    ? $event['Orgc']['name'] : '',
                'threat_level_id' =>
                    $event['Event']['threat_level_id'],
                'analysis' => $event['Event']['analysis'],
                'published' => $event['Event']['published']
                    ? 'Yes' : 'No',
            ];
        }

        return $results;
    }

    /**
     * Fetch attribute list.
     *
     * @param array $filters Filters
     * @return array
     */
    private function __fetchAttributeList($filters)
    {
        $params = [
            'limit' => isset($filters['limit'])
                ? (int)$filters['limit'] : $this->__perPage,
            'page' => isset($filters['page'])
                ? (int)$filters['page'] : 1,
        ];

        $passthrough = [
            'value', 'type', 'category', 'to_ids',
            'tags', 'from', 'to', 'last', 'eventid',
            'uuid', 'published', 'timestamp',
            'object_relation', 'first_seen',
            'last_seen', 'deleted', 'searchall',
            'includeCorrelations', 'order',
        ];
        foreach ($passthrough as $key) {
            if (isset($filters[$key])) {
                $params[$key] = $filters[$key];
            }
        }

        if (
            $this->__context['entity'] === 'event'
            && !empty($this->__context['id'])
            && !isset($params['eventid'])
        ) {
            $params['eventid'] = $this->__context['id'];
        }

        $params['return'] = 'attributes';
        $attributes = $this->MispAttribute->fetchAttributes(
            $this->__user, $params
        );

        if (empty($attributes)) {
            return [];
        }

        $results = [];
        foreach ($attributes as $attr) {
            $a = isset($attr['Attribute'])
                ? $attr['Attribute'] : $attr;
            $results[] = [
                'id' => $a['id'],
                'event_id' => $a['event_id'],
                'type' => $a['type'],
                'category' => $a['category'],
                'value' => $a['value'],
                'to_ids' => !empty($a['to_ids'])
                    ? 'Yes' : 'No',
                'comment' => isset($a['comment'])
                    ? $a['comment'] : '',
            ];
        }

        return $results;
    }

    /**
     * Fetch object list.
     *
     * @param array $filters Filters
     * @return array
     */
    private function __fetchObjectList($filters)
    {
        $conditions = [];
        $limit = isset($filters['limit'])
            ? (int)$filters['limit'] : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        if (
            $this->__context['entity'] === 'event'
            && !empty($this->__context['id'])
        ) {
            $conditions['MispObject.event_id'] =
                $this->__context['id'];
        }

        if (isset($filters['object_name'])) {
            $conditions['MispObject.name'] =
                $filters['object_name'];
        }

        $objects = $this->MispObject->find('all', [
            'conditions' => $conditions,
            'fields' => [
                'MispObject.id',
                'MispObject.event_id',
                'MispObject.name',
                'MispObject.meta-category',
                'MispObject.description',
                'MispObject.template_version',
            ],
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => ['MispObject.id' => 'DESC'],
        ]);

        $results = [];
        foreach ($objects as $obj) {
            $o = $obj['MispObject'];
            $results[] = [
                'id' => $o['id'],
                'event_id' => $o['event_id'],
                'name' => $o['name'],
                'meta-category' => isset($o['meta-category'])
                    ? $o['meta-category'] : '',
                'description' => isset($o['description'])
                    ? $o['description'] : '',
                'template_version' =>
                    isset($o['template_version'])
                        ? $o['template_version'] : '',
            ];
        }

        return $results;
    }

    /**
     * Fetch tag list.
     *
     * @param array $filters Filters
     * @return array
     */
    private function __fetchTagList($filters)
    {
        $conditions = [];
        $limit = isset($filters['limit'])
            ? (int)$filters['limit'] : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        if (
            $this->__context['entity'] === 'event'
            && !empty($this->__context['id'])
        ) {
            $eventTags = $this->EventTag->find('list', [
                'conditions' => [
                    'EventTag.event_id' =>
                        $this->__context['id'],
                ],
                'fields' => ['EventTag.tag_id'],
            ]);
            if (empty($eventTags)) {
                return [];
            }
            $conditions['Tag.id'] = array_values($eventTags);
        }

        $tags = $this->Tag->find('all', [
            'conditions' => $conditions,
            'fields' => [
                'Tag.id', 'Tag.name', 'Tag.colour',
                'Tag.exportable', 'Tag.hide_tag',
            ],
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => ['Tag.name' => 'ASC'],
        ]);

        $results = [];
        foreach ($tags as $tag) {
            $t = $tag['Tag'];
            $results[] = [
                'id' => $t['id'],
                'name' => $t['name'],
                'colour' => $t['colour'],
                'exportable' => !empty($t['exportable'])
                    ? 'Yes' : 'No',
                'hide_tag' => !empty($t['hide_tag'])
                    ? 'Yes' : 'No',
            ];
        }

        return $results;
    }

    /**
     * Generic simple list fetch for entities using find().
     *
     * @param string $modelName Model class name
     * @param array $filters Filters
     * @return array
     */
    private function __fetchSimpleList($modelName, $filters)
    {
        $limit = isset($filters['limit'])
            ? (int)$filters['limit'] : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        $records = $this->{$modelName}->find('all', [
            'recursive' => -1,
            'limit' => $limit,
            'page' => $page,
            'order' => [$modelName . '.id' => 'DESC'],
        ]);

        $results = [];
        foreach ($records as $record) {
            $data = $record[$modelName];
            $row = [];
            $entity = null;
            foreach (
                $this->__entityConfig as $eName => $eConfig
            ) {
                if ($eConfig['model'] === $modelName) {
                    $entity = $eName;
                    break;
                }
            }
            if ($entity === null) {
                continue;
            }
            $listFields =
                $this->__entityConfig[$entity]['listFields'];
            foreach ($listFields as $field) {
                $row[$field] = isset($data[$field])
                    ? $data[$field] : '';
            }
            $results[] = $row;
        }

        return $results;
    }

    /**
     * Fetch sharing group list.
     *
     * @param array $filters Filters
     * @return array
     */
    private function __fetchSharingGroupList($filters)
    {
        $sgs = $this->SharingGroup->fetchAllAuthorised(
            $this->__user
        );

        if (empty($sgs)) {
            return [];
        }

        $limit = isset($filters['limit'])
            ? (int)$filters['limit'] : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;
        $offset = ($page - 1) * $limit;

        $sgs = array_slice($sgs, $offset, $limit);

        $results = [];
        foreach ($sgs as $sg) {
            $s = isset($sg['SharingGroup'])
                ? $sg['SharingGroup'] : $sg;
            $results[] = [
                'id' => $s['id'],
                'name' => isset($s['name'])
                    ? $s['name'] : '',
                'description' => isset($s['description'])
                    ? $s['description'] : '',
                'org_id' => isset($s['org_id'])
                    ? $s['org_id'] : '',
                'active' => !empty($s['active'])
                    ? 'Yes' : 'No',
            ];
        }

        return $results;
    }

    /**
     * Fetch detail for a single record.
     *
     * @param string $entity Entity name
     * @param int $id Record ID
     * @return array|null Record data or null
     */
    private function __fetchDetail($entity, $id)
    {
        switch ($entity) {
            case 'event':
                $events = $this->Event->fetchEvent(
                    $this->__user,
                    ['eventid' => $id, 'metadata' => true]
                );
                return !empty($events[0]) ? $events[0] : null;

            case 'attribute':
                $attrs = $this->MispAttribute->fetchAttributes(
                    $this->__user,
                    [
                        'conditions' => [
                            'Attribute.id' => $id,
                        ],
                    ]
                );
                return !empty($attrs[0]) ? $attrs[0] : null;

            case 'object':
                $objects = $this->MispObject->find('first', [
                    'conditions' => [
                        'MispObject.id' => $id,
                    ],
                    'recursive' => 1,
                ]);
                return !empty($objects) ? $objects : null;

            case 'tag':
                return $this->Tag->find('first', [
                    'conditions' => ['Tag.id' => $id],
                    'recursive' => -1,
                ]);

            case 'user':
                return $this->User->getAuthUser($id);

            case 'organisation':
                return $this->Organisation->find('first', [
                    'conditions' => [
                        'Organisation.id' => $id,
                    ],
                    'recursive' => -1,
                ]);

            case 'server':
                return $this->Server->find('first', [
                    'conditions' => ['Server.id' => $id],
                    'recursive' => -1,
                ]);

            case 'feed':
                return $this->Feed->find('first', [
                    'conditions' => ['Feed.id' => $id],
                    'recursive' => -1,
                ]);

            case 'sharing_group':
                return $this->SharingGroup->find('first', [
                    'conditions' => [
                        'SharingGroup.id' => $id,
                    ],
                    'recursive' => -1,
                ]);

            case 'galaxy':
                return $this->Galaxy->find('first', [
                    'conditions' => ['Galaxy.id' => $id],
                    'recursive' => -1,
                ]);

            case 'taxonomy':
                return $this->Taxonomy->find('first', [
                    'conditions' => ['Taxonomy.id' => $id],
                    'recursive' => -1,
                ]);

            case 'warninglist':
                return $this->Warninglist->find('first', [
                    'conditions' => [
                        'Warninglist.id' => $id,
                    ],
                    'recursive' => -1,
                ]);

            default:
                return null;
        }
    }

    /**
     * Render a static (non-interactive) table for piped mode.
     *
     * @param string $entity Entity name
     * @param array $results Result rows
     * @param array $fields Field names for columns
     * @return void
     */
    private function __renderStaticTable(
        $entity,
        $results,
        $fields
    ) {
        $termSize = $this->__getTerminalSize();
        $termWidth = $termSize[0];

        $colWidths = [];
        foreach ($fields as $field) {
            $label = $this->__fieldLabel($field);
            $colWidths[$field] = strlen($label);
        }

        foreach ($results as $row) {
            foreach ($fields as $field) {
                $val = isset($row[$field])
                    ? (string)$row[$field] : '';
                $len = strlen($val);
                if ($len > $colWidths[$field]) {
                    $colWidths[$field] = $len;
                }
            }
        }

        $totalWidth = array_sum($colWidths)
            + (count($fields) - 1) * 3;
        if ($totalWidth > $termWidth) {
            $lastField = end($fields);
            $excess = $totalWidth - $termWidth;
            $colWidths[$lastField] = max(
                5,
                $colWidths[$lastField] - $excess
            );
        }

        foreach ($colWidths as $field => $width) {
            $colWidths[$field] = min($width, 60);
        }

        $header = '';
        $separator = '';
        foreach ($fields as $i => $field) {
            $label = $this->__fieldLabel($field);
            $width = $colWidths[$field];
            $header .= str_pad(
                substr($label, 0, $width), $width
            );
            $separator .= str_repeat('-', $width);
            if ($i < count($fields) - 1) {
                $header .= ' | ';
                $separator .= '-+-';
            }
        }

        $this->out($header);
        $this->out($separator);

        foreach ($results as $row) {
            $line = '';
            foreach ($fields as $i => $field) {
                $val = isset($row[$field])
                    ? (string)$row[$field] : '';
                $width = $colWidths[$field];
                if (strlen($val) > $width) {
                    $val = substr($val, 0, $width - 2) . '..';
                }
                $line .= str_pad($val, $width);
                if ($i < count($fields) - 1) {
                    $line .= ' | ';
                }
            }
            $this->out($line);
        }

        $this->out('');
        $this->out(
            'Page ' . $this->__page
            . ' (' . count($results) . ' results)'
        );
    }

    /**
     * Interactive browse mode loop.
     *
     * Enters raw terminal mode and renders a browsable table.
     * Handles keystrokes for navigation, viewing, and paging.
     * Returns to normal mode when user presses q or Escape.
     *
     * @param string $entity Entity name
     * @param array $fields Field names for columns
     * @return void
     */
    private function __browseLoop($entity, $fields)
    {
        $this->__enterRawMode();

        $totalResults = count($this->__browseData);
        $this->__renderBrowsableTable(
            $entity,
            $this->__browseData,
            $fields,
            $totalResults
        );

        while (true) {
            $key = $this->__readKeypress();
            if ($key === false) {
                break;
            }

            $rowCount = count($this->__browseData);
            $redraw = false;

            switch ($key) {
                case 'UP':
                case 'k':
                    if ($this->__selectedIndex > 0) {
                        $this->__selectedIndex--;
                        $redraw = true;
                    }
                    break;

                case 'DOWN':
                case 'j':
                    if (
                        $this->__selectedIndex < $rowCount - 1
                    ) {
                        $this->__selectedIndex++;
                        $redraw = true;
                    }
                    break;

                case 'ENTER':
                    if (
                        $rowCount > 0
                        && isset(
                            $this->__browseData[
                                $this->__selectedIndex
                            ]['id']
                        )
                    ) {
                        $id = $this->__browseData[
                            $this->__selectedIndex
                        ]['id'];
                        $this->__exitRawMode();
                        $this->__cmdView($entity, (int)$id);
                    }
                    break 2;

                case 'n':
                    if (empty($this->__lastQuery)) {
                        break;
                    }
                    $this->__page++;
                    $this->__lastQuery['filters']['page'] =
                        $this->__page;
                    $results = $this->__fetchList(
                        $entity,
                        $this->__lastQuery['filters']
                    );
                    if (empty($results)) {
                        $this->__page--;
                        $this->__lastQuery['filters']['page'] =
                            $this->__page;
                    } else {
                        $this->__browseData = $results;
                        $this->__selectedIndex = 0;
                        $this->__viewportOffset = 0;
                        $totalResults =
                            count($this->__browseData);
                    }
                    $redraw = true;
                    break;

                case 'p':
                    if (
                        empty($this->__lastQuery)
                        || $this->__page <= 1
                    ) {
                        break;
                    }
                    $this->__page--;
                    $this->__lastQuery['filters']['page'] =
                        $this->__page;
                    $results = $this->__fetchList(
                        $entity,
                        $this->__lastQuery['filters']
                    );
                    if (!empty($results)) {
                        $this->__browseData = $results;
                        $this->__selectedIndex = 0;
                        $this->__viewportOffset = 0;
                        $totalResults =
                            count($this->__browseData);
                    }
                    $redraw = true;
                    break;

                case 'q':
                case 'ESCAPE':
                    break 2;

                default:
                    break;
            }

            if ($redraw) {
                $this->__renderBrowsableTable(
                    $entity,
                    $this->__browseData,
                    $fields,
                    $totalResults
                );
            }
        }

        $this->__exitRawMode();
    }

    /**
     * Render an interactive browsable table with highlighting
     * and viewport scrolling.
     *
     * Draws a full-screen table with the selected row in
     * inverse video. Handles viewport scrolling when results
     * exceed screen height.
     *
     * @param string $entity Entity name
     * @param array $results Result rows
     * @param array $fields Field names for columns
     * @param int $totalResults Total result count for footer
     * @return void
     */
    private function __renderBrowsableTable(
        $entity,
        $results,
        $fields,
        $totalResults = 0
    ) {
        $termSize = $this->__getTerminalSize();
        $termWidth = $termSize[0];
        $termHeight = $termSize[1];

        $viewportRows = $termHeight - 4;
        if ($viewportRows < 1) {
            $viewportRows = 1;
        }

        $colWidths = $this->__calcColumnWidths(
            $results, $fields, $termWidth
        );

        $this->out("\033[H\033[J", 0);

        $header = '';
        $separator = '';
        foreach ($fields as $i => $field) {
            $label = $this->__fieldLabel($field);
            $width = $colWidths[$field];
            $header .= str_pad(
                substr($label, 0, $width), $width
            );
            $separator .= str_repeat(
                "\xe2\x94\x80", $width
            );
            if ($i < count($fields) - 1) {
                $header .= " \xe2\x94\x82 ";
                $separator .= "\xe2\x94\x80\xe2\x94\xbc"
                    . "\xe2\x94\x80";
            }
        }
        $this->out(' ' . $header);
        $this->out(' ' . $separator);

        $rowCount = count($results);
        if ($this->__selectedIndex >= $rowCount) {
            $this->__selectedIndex = $rowCount - 1;
        }
        if ($this->__selectedIndex < 0) {
            $this->__selectedIndex = 0;
        }

        if (
            $this->__selectedIndex
            >= $this->__viewportOffset + $viewportRows
        ) {
            $this->__viewportOffset =
                $this->__selectedIndex - $viewportRows + 1;
        }
        if (
            $this->__selectedIndex < $this->__viewportOffset
        ) {
            $this->__viewportOffset = $this->__selectedIndex;
        }

        $start = $this->__viewportOffset;
        $end = min($rowCount, $start + $viewportRows);

        for ($r = $start; $r < $end; $r++) {
            $row = $results[$r];
            $line = '';
            foreach ($fields as $i => $field) {
                $val = isset($row[$field])
                    ? (string)$row[$field] : '';
                $width = $colWidths[$field];
                if (strlen($val) > $width) {
                    $val = substr($val, 0, $width - 2)
                        . '..';
                }
                $cell = str_pad($val, $width);

                if ($r === $this->__selectedIndex) {
                    if ($this->__isTty) {
                        $cell = "\033[7m" . $cell
                            . "\033[0m";
                    }
                }
                $line .= $cell;
                if ($i < count($fields) - 1) {
                    $line .= ' | ';
                }
            }
            $this->out(' ' . $line);
        }

        $remaining = $viewportRows - ($end - $start);
        for ($i = 0; $i < $remaining; $i++) {
            $this->out('');
        }

        $this->out('');
        $totalPages = 1;
        if (
            $totalResults > 0
            && $this->__perPage > 0
        ) {
            $totalPages = (int)ceil(
                $totalResults / $this->__perPage
            );
        }
        $footer = ' [' . "\xe2\x86\x91" . '/'
            . "\xe2\x86\x93" . '/j/k] Navigate'
            . '  [Enter] View  [e] Edit  [d] Delete'
            . '  [q] Back  [n/p] Page';
        $pageInfo = '  Page ' . $this->__page . '/'
            . $totalPages;
        if ($totalResults > 0) {
            $pageInfo .= ' (' . $totalResults . ' results)';
        }
        $this->out($footer . $pageInfo);
    }

    /**
     * Calculate column widths for a set of results.
     *
     * @param array $results Result rows
     * @param array $fields Field names
     * @param int $termWidth Terminal width
     * @return array Field => width mapping
     */
    private function __calcColumnWidths(
        $results,
        $fields,
        $termWidth
    ) {
        $colWidths = [];
        foreach ($fields as $field) {
            $label = $this->__fieldLabel($field);
            $colWidths[$field] = strlen($label);
        }

        foreach ($results as $row) {
            foreach ($fields as $field) {
                $val = isset($row[$field])
                    ? (string)$row[$field] : '';
                $len = strlen($val);
                if ($len > $colWidths[$field]) {
                    $colWidths[$field] = $len;
                }
            }
        }

        foreach ($colWidths as $field => $width) {
            $colWidths[$field] = min($width, 60);
        }

        $totalWidth = array_sum($colWidths)
            + (count($fields) - 1) * 3 + 1;
        if ($totalWidth > $termWidth) {
            $lastField = end($fields);
            $excess = $totalWidth - $termWidth;
            $colWidths[$lastField] = max(
                5,
                $colWidths[$lastField] - $excess
            );
        }

        return $colWidths;
    }

    /**
     * Render a detail view for a single record.
     *
     * @param string $entity Entity name
     * @param array $record Record data
     * @return void
     */
    private function __renderDetail($entity, $record)
    {
        $this->out('');

        $modelName =
            $this->__entityConfig[$entity]['model'];

        if (isset($record[$modelName])) {
            $data = $record[$modelName];
        } elseif (isset($record[ucfirst($entity)])) {
            $data = $record[ucfirst($entity)];
        } elseif (isset($record['Event'])) {
            $data = $record['Event'];
        } else {
            $data = $record;
        }

        $maxKeyLen = 0;
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                continue;
            }
            if (strlen($key) > $maxKeyLen) {
                $maxKeyLen = strlen($key);
            }
        }

        $this->out(
            '=== ' . ucfirst($entity) . ' Detail ==='
        );
        $this->out('');

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                continue;
            }
            $paddedKey = str_pad($key, $maxKeyLen);
            $this->out('  ' . $paddedKey . ' : ' . $value);
        }

        foreach ($record as $section => $sectionData) {
            if ($section === $modelName) {
                continue;
            }
            if ($section === ucfirst($entity)) {
                continue;
            }
            if ($section === 'Event') {
                continue;
            }
            if (!is_array($sectionData)) {
                continue;
            }
            if ($this->__isAssocArray($sectionData)) {
                $this->out('');
                $this->out('  [' . $section . ']');
                foreach ($sectionData as $k => $v) {
                    if (is_array($v)) {
                        continue;
                    }
                    $this->out('    ' . $k . ': ' . $v);
                }
            }
        }

        $this->out('');
    }

    /**
     * Get display label for a field name.
     *
     * @param string $field Field name
     * @return string Label
     */
    private function __fieldLabel($field)
    {
        $labels = [
            'id' => 'ID',
            'event_id' => 'Event',
            'date' => 'Date',
            'info' => 'Info',
            'Orgc.name' => 'Org',
            'threat_level_id' => 'Threat',
            'analysis' => 'Analysis',
            'published' => 'Pub',
            'type' => 'Type',
            'category' => 'Category',
            'value' => 'Value',
            'to_ids' => 'IDS',
            'comment' => 'Comment',
            'name' => 'Name',
            'colour' => 'Colour',
            'exportable' => 'Export',
            'hide_tag' => 'Hidden',
            'email' => 'Email',
            'org_id' => 'Org ID',
            'role_id' => 'Role',
            'disabled' => 'Disabled',
            'uuid' => 'UUID',
            'nationality' => 'Country',
            'sector' => 'Sector',
            'url' => 'URL',
            'push' => 'Push',
            'pull' => 'Pull',
            'provider' => 'Provider',
            'enabled' => 'Enabled',
            'active' => 'Active',
            'description' => 'Description',
            'namespace' => 'Namespace',
            'version' => 'Version',
            'meta-category' => 'Category',
            'template_version' => 'Tpl Ver',
        ];

        return isset($labels[$field]) ? $labels[$field] : $field;
    }

    /**
     * Check if array is associative.
     *
     * @param array $arr Array to check
     * @return bool
     */
    private function __isAssocArray($arr)
    {
        if (empty($arr) || !is_array($arr)) {
            return false;
        }
        return array_keys($arr) !== range(
            0, count($arr) - 1
        );
    }

    /**
     * Enter raw terminal mode (disable line buffering and echo).
     *
     * @return void
     */
    private function __enterRawMode()
    {
        if ($this->__rawMode || !$this->__isTty) {
            return;
        }
        shell_exec('stty -icanon -echo 2>/dev/null');
        $this->__rawMode = true;
    }

    /**
     * Exit raw terminal mode (restore line buffering and echo).
     *
     * @return void
     */
    private function __exitRawMode()
    {
        if (!$this->__rawMode) {
            return;
        }
        shell_exec('stty icanon echo 2>/dev/null');
        $this->__rawMode = false;
    }

    /**
     * Read a single keypress from stdin.
     *
     * Handles multi-byte escape sequences for arrow keys
     * and other special keys.
     *
     * @return string|false Key identifier or false on EOF
     */
    private function __readKeypress()
    {
        $ch = fread($this->__stdin, 1);
        if ($ch === false || $ch === '') {
            return false;
        }

        if ($ch === "\033") {
            $seq = fread($this->__stdin, 1);
            if ($seq === '[') {
                $code = fread($this->__stdin, 1);
                switch ($code) {
                    case 'A':
                        return 'UP';
                    case 'B':
                        return 'DOWN';
                    case 'C':
                        return 'RIGHT';
                    case 'D':
                        return 'LEFT';
                    default:
                        return 'UNKNOWN';
                }
            }
            return 'ESCAPE';
        }

        if ($ch === "\n" || $ch === "\r") {
            return 'ENTER';
        }

        return $ch;
    }

    /**
     * Restore terminal to sane state.
     *
     * @return void
     */
    public function restoreTerminal()
    {
        if ($this->__rawMode) {
            shell_exec('stty icanon echo 2>/dev/null');
            $this->__rawMode = false;
        }
    }

    /**
     * Clean up resources.
     *
     * @return void
     */
    private function __cleanup()
    {
        $this->restoreTerminal();
        if (is_resource($this->__stdin)) {
            fclose($this->__stdin);
        }
    }
}
