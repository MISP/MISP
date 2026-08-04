<?php

require_once __DIR__ . '/CLIShell/cli_common.php';
require_once __DIR__ . '/CLIShell/cli_events.php';
require_once __DIR__ . '/CLIShell/cli_attributes.php';
require_once __DIR__ . '/CLIShell/cli_objects.php';
require_once __DIR__ . '/CLIShell/cli_tags.php';
require_once __DIR__ . '/CLIShell/cli_users.php';
require_once __DIR__
    . '/CLIShell/cli_organisations.php';
require_once __DIR__ . '/CLIShell/cli_roles.php';

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
 * @property Role $Role
 * @property Warninglist $Warninglist
 * @property GalaxyCluster $GalaxyCluster
 */
class CLIShell extends AppShell
{
    use CLICommonTrait;
    use CLIEventsTrait;
    use CLIAttributesTrait;
    use CLIObjectsTrait;
    use CLITagsTrait;
    use CLIUsersTrait;
    use CLIOrganisationsTrait;
    use CLIRolesTrait;

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
        'Role',
    ];

    /** @var array Authenticated user array */
    private $__user = null;

    /** @var array Navigation context */
    private $__context = [
        'entity' => null,
        'id' => null,
    ];

    /** @var int Current pagination page */
    private $__page = 1;

    /** @var int Items per page */
    private $__perPage = 20;

    /** @var string Sort direction: ASC or DESC */
    private $__sortOrder = 'DESC';

    /** @var array|null Cached last query params */
    private $__lastQuery = null;

    /** @var resource File handle for stdin */
    private $__stdin = null;

    /** @var int Currently highlighted row in browse mode */
    private $__selectedIndex = 0;

    /** @var int Viewport offset for scrolling */
    private $__viewportOffset = 0;

    /** @var array Current page of results for browse mode */
    private $__browseData = [];

    /** @var array Active browse-mode filters */
    private $__browseFilters = [];

    /**
     * Field metadata for interactive prompting.
     * Populated in main() from trait getters.
     *
     * @var array
     */
    private $__fieldMeta = [];

    /** @var bool Whether stdout is a TTY */
    private $__isTty = false;

    /** @var bool Whether we are in raw terminal mode */
    private $__rawMode = false;

    /**
     * Entity configuration registry.
     * Event/attribute/object configs are merged from
     * traits in main(). Remaining entities are defined
     * inline here.
     *
     * @var array
     */
    private $__entityConfig = [
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
            'aliases' => [
                'sharing_groups',
                'sharinggroup',
                'sharinggroups',
            ],
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
            'MISP Interactive CLI Shell - browse and '
            . 'manage MISP data from the command line.'
        );
        $parser->addArgument('user_id', [
            'help' => 'User ID to authenticate as. '
                . 'All operations are ACL-scoped '
                . 'to this user.',
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
        $userId = isset($this->args[0])
            ? $this->args[0] : null;
        if (empty($userId) || !is_numeric($userId)) {
            $this->err('Usage: cake CLI <user_id>');
            return;
        }

        $user = $this->User->getAuthUser(
            (int)$userId, true
        );
        if (empty($user)) {
            $this->err(
                'Error: User with ID '
                . $userId . ' not found.'
            );
            return;
        }
        $this->__user = $user;
        $this->__setUserContext($user);

        $this->__entityConfig = array_merge(
            $this->__getEventEntityConfig(),
            $this->__getAttributeEntityConfig(),
            $this->__getObjectEntityConfig(),
            $this->__getTagEntityConfig(),
            $this->__getUserEntityConfig(),
            $this->__getOrganisationEntityConfig(),
            $this->__getRoleEntityConfig(),
            $this->__entityConfig
        );
        $this->__fieldMeta = array_merge(
            $this->__getEventFieldMeta(),
            $this->__getAttributeFieldMeta(),
            $this->__getObjectFieldMeta(),
            $this->__getTagFieldMeta(),
            $this->__getUserFieldMeta(),
            $this->__getOrganisationFieldMeta(),
            $this->__getRoleFieldMeta()
        );

        $this->__isTty = function_exists('posix_isatty')
            && posix_isatty(STDOUT);
        $this->__stdin = fopen('php://stdin', 'r');

        register_shutdown_function(
            [$this, 'restoreTerminal']
        );

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

            if (
                $line === 'exit'
                || $line === 'quit'
            ) {
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
        if (
            !empty(
                $this->__user['Organisation']['name']
            )
        ) {
            $orgName =
                $this->__user['Organisation']['name'];
        } elseif (!empty($this->__user['org_id'])) {
            $org = $this->Organisation->find('first', [
                'conditions' => [
                    'Organisation.id' =>
                        $this->__user['org_id'],
                ],
                'fields' => ['Organisation.name'],
                'recursive' => -1,
            ]);
            if (!empty($org)) {
                $orgName = $org['Organisation']['name'];
            }
        }
        $role = '';
        if (
            !empty(
                $this->__user['Role']
                    ['perm_site_admin']
            )
        ) {
            $role = ' [Site Admin]';
        } elseif (
            !empty(
                $this->__user['Role']['perm_admin']
            )
        ) {
            $role = ' [Org Admin]';
        }

        $this->out('');
        $this->out(
            'Welcome to MISP Interactive CLI '
            . 'Shell v1.0'
        );
        $this->out(
            'Logged in as: ' . $email
            . ' (' . $orgName . ')' . $role
        );
        $this->out(
            "Type 'help' for available commands."
        );
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
        if (
            !empty(
                $this->__user['Organisation']['name']
            )
        ) {
            $orgName =
                $this->__user['Organisation']['name'];
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

        return 'MISP [' . $username . '@' . $orgName
            . ']' . $contextStr . ' > ';
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
            case 'add':
                $this->__cmdAdd($entity);
                break;
            case 'edit':
                $this->__cmdEdit($entity, $id);
                break;
            case 'delete':
                $this->__cmdDelete($entity, $id);
                break;
            default:
                $this->err(
                    "Unknown command: '"
                    . $command . "'. "
                    . "Type 'help' for available "
                    . 'commands.'
                );
                break;
        }
    }

    /**
     * Parse a command line into structured parts.
     *
     * @param string $line Raw input
     * @return array|false Parsed command or false
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
                $resolved =
                    $this->__resolveEntity($next);
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
            } elseif (
                $ch === '"' || $ch === "'"
            ) {
                $inQuote = true;
                $quoteChar = $ch;
            } elseif (
                $ch === ' ' || $ch === "\t"
            ) {
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
     * Resolve entity name or alias to canonical name.
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
        foreach (
            $this->__entityConfig
            as $canonical => $config
        ) {
            if (
                in_array(
                    $name, $config['aliases'], true
                )
            ) {
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
        $output = shell_exec(
            'stty size 2>/dev/null'
        );
        if (!empty($output)) {
            $parts = explode(' ', trim($output));
            if (count($parts) === 2) {
                return [
                    (int)$parts[1],
                    (int)$parts[0],
                ];
            }
        }
        return [80, 24];
    }

    /**
     * help command.
     *
     * @param string|null $topic Help topic
     * @return void
     */
    private function __cmdHelp($topic = null)
    {
        if ($topic === null) {
            $this->out('Available commands:');
            $this->out('');
            $this->out(
                '  list <entity> [filters]'
                . '  - Paginated list with '
                . 'optional filters'
            );
            $this->out(
                '  view <entity> <id>'
                . '      - Detailed view of a '
                . 'single record'
            );
            $this->out(
                '  search <entity> [filters]'
                . ' - Search with filters'
            );
            $this->out(
                '  add <entity>'
                . '             - Interactive '
                . 'guided creation'
            );
            $this->out(
                '  edit <entity> <id>'
                . '      - Interactive field editing'
            );
            $this->out(
                '  delete <entity> <id>'
                . '    - Delete with confirmation'
            );
            $this->out(
                '  use <entity> <id>'
                . '       - Set navigation context'
            );
            $this->out(
                '  context'
                . '                  - Show '
                . 'current context'
            );
            $this->out(
                '  clear'
                . '                    - Clear '
                . 'navigation context'
            );
            $this->out(
                '  next / prev'
                . '              - Next/previous '
                . 'page'
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
                "Type 'help filters' for filter "
                . 'syntax.'
            );
            return;
        }

        if (
            $topic === 'filters'
            || $topic === 'filter'
        ) {
            $this->out('Filter Syntax:');
            $this->out('');
            $this->out(
                '  key=value         Exact match'
            );
            $this->out(
                '  key=a,b,c         OR (any of)'
            );
            $this->out(
                '  key=!value        NOT (exclude)'
            );
            $this->out(
                '  tag=X,Y           Tag OR'
            );
            $this->out(
                '  tag+=X            Tag AND '
                . '(must have)'
            );
            $this->out(
                '  tag=!X            Tag NOT'
            );
            $this->out(
                '  from=YYYY-MM-DD   Date range '
                . 'start'
            );
            $this->out(
                '  to=YYYY-MM-DD     Date range end'
            );
            $this->out(
                '  last=7d           Relative time '
                . '(d/h/m)'
            );
            $this->out(
                '  searchall=text    Wildcard '
                . 'across fields'
            );
            $this->out(
                '  value=%text%      LIKE match'
            );
            return;
        }

        $this->out(
            "No detailed help available for '"
            . $topic . "'."
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
        $this->__context = [
            'entity' => null,
            'id' => null,
        ];
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
        if (
            !isset($this->__entityConfig[$entity])
        ) {
            $this->err(
                "Unknown entity: '"
                . $entity . "'"
            );
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
                'Usage: list <entity> '
                . '[key=value ...]'
            );
            return;
        }
        if (
            !isset($this->__entityConfig[$entity])
        ) {
            $this->err(
                "Unknown entity: '"
                . $entity . "'"
            );
            return;
        }
        $config = $this->__entityConfig[$entity];
        if (
            !empty($config['adminOnly'])
            && empty(
                $this->__user['Role']
                    ['perm_site_admin']
            )
        ) {
            $this->err(
                'Permission denied: '
                . $entity
                . ' requires site admin access.'
            );
            return;
        }

        $this->__browseFilters = [];
        foreach ($args as $arg) {
            if (strpos($arg, '=') !== false) {
                $this->__browseFilters[] = $arg;
            }
        }

        $filters = $this->__parseFilters($args);

        if (!isset($filters['limit'])) {
            $filters['limit'] = $this->__perPage;
        }
        if (!isset($filters['page'])) {
            $filters['page'] = 1;
        }
        $filters['sort_order'] =
            $this->__sortOrder;
        $this->__page = (int)$filters['page'];

        $this->__lastQuery = [
            'entity' => $entity,
            'filters' => $filters,
        ];

        $results = $this->__fetchList(
            $entity, $filters
        );
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
        if (
            !isset($this->__entityConfig[$entity])
        ) {
            $this->err(
                "Unknown entity: '"
                . $entity . "'"
            );
            return;
        }
        if (empty($id) && !is_numeric($id)) {
            $this->err('Usage: view <entity> <id>');
            return;
        }
        if (!is_numeric($id)) {
            $this->err(
                "Invalid ID: '" . $id . "'"
            );
            return;
        }

        $config = $this->__entityConfig[$entity];
        if (
            !empty($config['adminOnly'])
            && empty(
                $this->__user['Role']
                    ['perm_site_admin']
            )
        ) {
            $this->err(
                'Permission denied: '
                . $entity
                . ' requires site admin access.'
            );
            return;
        }

        $record = $this->__fetchDetail(
            $entity, (int)$id
        );
        if (empty($record)) {
            $this->err(
                ucfirst($entity)
                . ' with ID ' . $id
                . ' not found.'
            );
            return;
        }

        if (
            in_array($entity, ['event', 'object'])
        ) {
            $this->__context = [
                'entity' => $entity,
                'id' => (int)$id,
            ];
        }

        if ($this->__isTty) {
            $this->__detailBrowseLoop(
                $entity, (int)$id, $record
            );
        } else {
            $this->__renderDetail(
                $entity, $record
            );
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
            $this->err(
                'No previous query to paginate.'
            );
            return;
        }
        $this->__page++;
        $this->__lastQuery['filters']['page'] =
            $this->__page;
        $entity = $this->__lastQuery['entity'];
        $filters = $this->__lastQuery['filters'];
        $config = $this->__entityConfig[$entity];

        $results = $this->__fetchList(
            $entity, $filters
        );
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
            $this->err(
                'No previous query to paginate.'
            );
            return;
        }
        if ($this->__page <= 1) {
            $this->out(
                'Already on the first page.'
            );
            return;
        }
        $this->__page--;
        $this->__lastQuery['filters']['page'] =
            $this->__page;
        $entity = $this->__lastQuery['entity'];
        $filters = $this->__lastQuery['filters'];
        $config = $this->__entityConfig[$entity];

        $results = $this->__fetchList(
            $entity, $filters
        );
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
     * Parse filter arguments into array.
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
                    if (
                        strpos($part, '!') === 0
                    ) {
                        $tagsNot[] = substr(
                            $part, 1
                        );
                    } else {
                        $tagsOr[] = $part;
                    }
                }
                continue;
            }

            if (
                strpos($value, ',') !== false
            ) {
                $parts = explode(',', $value);
                $orValues = [];
                $notValues = [];
                foreach ($parts as $part) {
                    if (
                        strpos($part, '!') === 0
                    ) {
                        $notValues[] = substr(
                            $part, 1
                        );
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
            } elseif (
                strpos($value, '!') === 0
            ) {
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
     * Dispatches to trait-provided fetch methods
     * for events, attributes, and objects.
     *
     * @param string $entity Canonical entity name
     * @param array $filters Filters
     * @return array Results
     */
    private function __fetchList($entity, $filters)
    {
        switch ($entity) {
            case 'event':
                return $this->__fetchEventList(
                    $filters
                );
            case 'attribute':
                return $this->__fetchAttributeList(
                    $filters
                );
            case 'object':
                return $this->__fetchObjectList(
                    $filters
                );
            case 'tag':
                return $this->__fetchTagList(
                    $filters
                );
            case 'user':
                return $this->__fetchUserList(
                    $filters
                );
            case 'organisation':
                return $this->__fetchOrganisationList(
                    $filters
                );
            case 'role':
                return $this->__fetchRoleList(
                    $filters
                );
            case 'sharing_group':
                return $this->__fetchSharingGroupList(
                    $filters
                );
            default:
                return $this->__fetchSimpleList(
                    $this->__entityConfig[$entity]
                        ['model'],
                    $filters
                );
        }
    }

    /**
     * Generic simple list fetch for entities.
     *
     * @param string $modelName Model class name
     * @param array $filters Filters
     * @return array
     */
    private function __fetchSimpleList(
        $modelName,
        $filters
    ) {
        $limit = isset($filters['limit'])
            ? (int)$filters['limit']
            : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;

        $entity = null;
        foreach (
            $this->__entityConfig
            as $eName => $eConfig
        ) {
            if (
                $eConfig['model'] === $modelName
            ) {
                $entity = $eName;
                break;
            }
        }
        if ($entity === null) {
            return [];
        }
        $alias = $this->__modelAlias($entity);

        $records = $this->{$modelName}->find(
            'all',
            [
                'recursive' => -1,
                'limit' => $limit,
                'page' => $page,
                'order' => [
                    $alias . '.id' => isset(
                        $filters['sort_order']
                    )
                    ? $filters['sort_order']
                    : 'DESC',
                ],
            ]
        );

        $results = [];
        $listFields =
            $this->__entityConfig[$entity]
                ['listFields'];
        foreach ($records as $record) {
            $data = isset($record[$alias])
                ? $record[$alias]
                : $record[$modelName];
            $row = [];
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
    private function __fetchSharingGroupList(
        $filters
    ) {
        $sgs = $this->SharingGroup
            ->fetchAllAuthorised(
                $this->__user, 'simplified'
            );

        if (empty($sgs)) {
            return [];
        }

        $limit = isset($filters['limit'])
            ? (int)$filters['limit']
            : $this->__perPage;
        $page = isset($filters['page'])
            ? (int)$filters['page'] : 1;
        $offset = ($page - 1) * $limit;

        $sgs = array_slice($sgs, $offset, $limit);

        $orgIds = [];
        foreach ($sgs as $sg) {
            $s = isset($sg['SharingGroup'])
                ? $sg['SharingGroup'] : $sg;
            if (!empty($s['org_id'])) {
                $orgIds[] = $s['org_id'];
            }
        }
        $this->__prefetchFK('org', $orgIds);

        $results = [];
        foreach ($sgs as $sg) {
            $s = isset($sg['SharingGroup'])
                ? $sg['SharingGroup'] : $sg;
            $results[] = [
                'id' => $s['id'],
                'name' => isset($s['name'])
                    ? $s['name'] : '',
                'description' =>
                    isset($s['description'])
                    ? $s['description'] : '',
                'org_id' => !empty($s['org_id'])
                    ? $this->__resolveFK(
                        'org', $s['org_id']
                    ) : '',
                'active' => !empty($s['active'])
                    ? 'Yes' : 'No',
            ];
        }

        return $results;
    }

    /**
     * Fetch detail for a single record.
     *
     * Dispatches to trait-provided fetch methods
     * for events, attributes, and objects.
     *
     * @param string $entity Entity name
     * @param int $id Record ID
     * @return array|null Record data or null
     */
    private function __fetchDetail($entity, $id)
    {
        switch ($entity) {
            case 'event':
                return $this->__fetchEventDetail(
                    $id
                );

            case 'attribute':
                return $this->__fetchAttributeDetail(
                    $id
                );

            case 'object':
                return $this->__fetchObjectDetail(
                    $id
                );

            case 'tag':
                return $this->__fetchTagDetail(
                    $id
                );

            case 'user':
                return $this->__fetchUserDetail(
                    $id
                );

            case 'organisation':
                return
                    $this->__fetchOrganisationDetail(
                        $id
                    );

            case 'role':
                return $this->__fetchRoleDetail(
                    $id
                );

            case 'server':
                return $this->Server->find(
                    'first',
                    [
                        'conditions' => [
                            'Server.id' => $id,
                        ],
                        'recursive' => -1,
                    ]
                );

            case 'feed':
                return $this->Feed->find('first', [
                    'conditions' => [
                        'Feed.id' => $id,
                    ],
                    'recursive' => -1,
                ]);

            case 'sharing_group':
                return $this->SharingGroup->find(
                    'first',
                    [
                        'conditions' => [
                            'SharingGroup.id' => $id,
                        ],
                        'recursive' => -1,
                    ]
                );

            case 'galaxy':
                return $this->Galaxy->find(
                    'first',
                    [
                        'conditions' => [
                            'Galaxy.id' => $id,
                        ],
                        'recursive' => -1,
                    ]
                );

            case 'taxonomy':
                return $this->Taxonomy->find(
                    'first',
                    [
                        'conditions' => [
                            'Taxonomy.id' => $id,
                        ],
                        'recursive' => -1,
                    ]
                );

            case 'warninglist':
                return $this->Warninglist->find(
                    'first',
                    [
                        'conditions' => [
                            'Warninglist.id' => $id,
                        ],
                        'recursive' => -1,
                    ]
                );

            default:
                return null;
        }
    }

    /**
     * Render a static table for piped mode.
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
                    $val = substr(
                        $val, 0, $width - 2
                    ) . '..';
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
            . ' (' . count($results)
            . ' results)'
        );
    }

    /**
     * Interactive browse mode loop.
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
        $this->__drainStdin();

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
                    if (
                        $this->__selectedIndex > 0
                    ) {
                        $this->__selectedIndex--;
                        $redraw = true;
                    }
                    break;

                case 'DOWN':
                case 'j':
                    if (
                        $this->__selectedIndex
                        < $rowCount - 1
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
                                $this
                                ->__selectedIndex
                            ]['id']
                        )
                    ) {
                        $id = $this->__browseData[
                            $this->__selectedIndex
                        ]['id'];
                        $this->__exitRawMode();
                        $this->__cmdView(
                            $entity, (int)$id
                        );
                    }
                    break 2;

                case 'n':
                    if (
                        empty($this->__lastQuery)
                    ) {
                        break;
                    }
                    $this->__page++;
                    $this->__lastQuery['filters']
                        ['page'] = $this->__page;
                    $results = $this->__fetchList(
                        $entity,
                        $this->__lastQuery['filters']
                    );
                    if (empty($results)) {
                        $this->__page--;
                        $this->__lastQuery['filters']
                            ['page'] = $this->__page;
                    } else {
                        $this->__browseData =
                            $results;
                        $this->__selectedIndex = 0;
                        $this->__viewportOffset = 0;
                        $totalResults = count(
                            $this->__browseData
                        );
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
                    $this->__lastQuery['filters']
                        ['page'] = $this->__page;
                    $results = $this->__fetchList(
                        $entity,
                        $this->__lastQuery['filters']
                    );
                    if (!empty($results)) {
                        $this->__browseData =
                            $results;
                        $this->__selectedIndex = 0;
                        $this->__viewportOffset = 0;
                        $totalResults = count(
                            $this->__browseData
                        );
                    }
                    $redraw = true;
                    break;

                case 'f':
                    $this->__exitRawMode();
                    $changed = $this->__filterBar(
                        $entity
                    );
                    if ($changed) {
                        $allArgs =
                            $this->__browseFilters;
                        $filters =
                            $this->__parseFilters(
                                $allArgs
                            );
                        if (
                            !isset($filters['limit'])
                        ) {
                            $filters['limit'] =
                                $this->__perPage;
                        }
                        $filters['page'] = 1;
                        $filters['sort_order'] =
                            $this->__sortOrder;
                        $this->__page = 1;
                        $this->__lastQuery = [
                            'entity' => $entity,
                            'filters' => $filters,
                        ];
                        $results =
                            $this->__fetchList(
                                $entity, $filters
                            );
                        if (empty($results)) {
                            $this->__browseData = [];
                            $totalResults = 0;
                        } else {
                            $this->__browseData =
                                $results;
                            $totalResults = count(
                                $this->__browseData
                            );
                        }
                        $this->__selectedIndex = 0;
                        $this->__viewportOffset = 0;
                    }
                    $this->__enterRawMode();
                    $redraw = true;
                    break;

                case 's':
                    $this->__sortOrder =
                        $this->__sortOrder === 'DESC'
                        ? 'ASC' : 'DESC';
                    if (
                        !empty($this->__lastQuery)
                    ) {
                        $this->__lastQuery
                            ['filters']
                            ['sort_order'] =
                                $this->__sortOrder;
                        $this->__page = 1;
                        $this->__lastQuery
                            ['filters']['page'] = 1;
                        $results =
                            $this->__fetchList(
                                $entity,
                                $this->__lastQuery
                                    ['filters']
                            );
                        if (!empty($results)) {
                            $this->__browseData =
                                $results;
                            $totalResults = count(
                                $this->__browseData
                            );
                        }
                        $this->__selectedIndex = 0;
                        $this->__viewportOffset = 0;
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
     * Render an interactive browsable table.
     *
     * @param string $entity Entity name
     * @param array $results Result rows
     * @param array $fields Field names for columns
     * @param int $totalResults Total result count
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

        // header + separator + empty + footer = 4
        // +1 for filter line when active
        $chrome = 4;
        if (!empty($this->__browseFilters)) {
            $chrome++;
        }
        $viewportRows = $termHeight - $chrome;
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
                $separator .= "\xe2\x94\x80"
                    . "\xe2\x94\xbc"
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
            >= $this->__viewportOffset
                + $viewportRows
        ) {
            $this->__viewportOffset =
                $this->__selectedIndex
                - $viewportRows + 1;
        }
        if (
            $this->__selectedIndex
            < $this->__viewportOffset
        ) {
            $this->__viewportOffset =
                $this->__selectedIndex;
        }

        $start = $this->__viewportOffset;
        $end = min(
            $rowCount, $start + $viewportRows
        );

        for ($r = $start; $r < $end; $r++) {
            $row = $results[$r];
            $line = '';
            foreach ($fields as $i => $field) {
                $val = isset($row[$field])
                    ? (string)$row[$field] : '';
                $width = $colWidths[$field];
                if (strlen($val) > $width) {
                    $val = substr(
                        $val, 0, $width - 2
                    ) . '..';
                }
                $cell = str_pad($val, $width);

                if (
                    $r === $this->__selectedIndex
                ) {
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

        $remaining = $viewportRows
            - ($end - $start);
        for ($i = 0; $i < $remaining; $i++) {
            $this->out('');
        }

        if (!empty($this->__browseFilters)) {
            $filterStr = implode(
                '  ', $this->__browseFilters
            );
            $this->out(
                ' Active filters: ' . $filterStr
            );
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
        $sortLabel = $this->__sortOrder === 'DESC'
            ? "\xe2\x86\x93" : "\xe2\x86\x91";
        $footer = ' [' . "\xe2\x86\x91" . '/'
            . "\xe2\x86\x93" . '/j/k] Navigate'
            . '  [Enter] View  [f] Filter'
            . '  [s] Sort ' . $sortLabel
            . '  [q] Back  [n/p] Page';
        $pageInfo = '  Page ' . $this->__page
            . '/' . $totalPages;
        if ($totalResults > 0) {
            $pageInfo .= ' (' . $totalResults
                . ' results)';
        }
        $this->out($footer . $pageInfo, 0);
        if ($this->__rawMode) {
            fflush(STDOUT);
        }
    }

    /**
     * Calculate column widths for results.
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
     * Get child entity relationships.
     *
     * Returns an ordered list of child entities
     * navigable from a parent detail view via
     * number-key shortcuts (1, 2, 3...).
     *
     * Each child: [entity, label, contextField]
     * contextField maps parent ID to filter key.
     *
     * @param string $entity Parent entity name
     * @param int    $id     Parent record ID
     * @return array Child definitions
     */
    private function __getChildEntities(
        $entity, $id
    ) {
        $map = [
            'event' => [
                [
                    'entity' => 'attribute',
                    'label' => 'Attributes',
                ],
                [
                    'entity' => 'object',
                    'label' => 'Objects',
                ],
                [
                    'entity' => 'tag',
                    'label' => 'Tags',
                ],
            ],
            'object' => [
                [
                    'entity' => 'attribute',
                    'label' => 'Attributes',
                ],
            ],
            'organisation' => [
                [
                    'entity' => 'user',
                    'label' => 'Users',
                    'filter' => 'org_id',
                ],
                [
                    'entity' => 'event',
                    'label' => 'Events',
                    'filter' => 'org',
                ],
            ],
            'role' => [
                [
                    'entity' => 'user',
                    'label' => 'Users',
                    'filter' => 'role_id',
                ],
            ],
        ];

        if (!isset($map[$entity])) {
            return [];
        }

        $children = [];
        foreach ($map[$entity] as $child) {
            $childEntity = $child['entity'];
            $config =
                $this->__entityConfig[$childEntity];
            if (
                !empty($config['adminOnly'])
                && empty(
                    $this->__user['Role']
                        ['perm_site_admin']
                )
            ) {
                continue;
            }
            $children[] = $child;
        }

        return $children;
    }

    /**
     * Interactive detail view with field navigation.
     *
     * @param string $entity Entity name
     * @param int    $id     Record ID
     * @param array  $record Full record data
     * @return void
     */
    private function __detailBrowseLoop(
        $entity, $id, $record
    ) {
        $rows = $this->__buildDetailRows(
            $entity, $record
        );
        if (empty($rows)) {
            $this->__renderDetail($entity, $record);
            return;
        }

        $children = $this->__getChildEntities(
            $entity, $id
        );

        $selectedIdx = 0;
        $viewportOff = 0;
        $this->__enterRawMode();

        $this->__renderDetailBrowse(
            $entity, $id, $rows,
            $selectedIdx, $viewportOff,
            $children
        );

        while (true) {
            $key = $this->__readKeypress();
            if ($key === false) {
                break;
            }

            $rowCount = count($rows);
            $redraw = false;

            if (
                is_numeric($key)
                && (int)$key >= 1
                && (int)$key <= count($children)
            ) {
                $child =
                    $children[(int)$key - 1];
                $this->out(
                    "\033[H\033[J Loading "
                    . $child['label'] . '...',
                    0
                );
                fflush(STDOUT);
                $this->__drainStdin();
                $this->__exitRawMode();
                $this->__navigateToChild(
                    $entity, $id, $child
                );
                $fresh = $this->__fetchDetail(
                    $entity, $id
                );
                if (!empty($fresh)) {
                    $record = $fresh;
                    $rows =
                        $this->__buildDetailRows(
                            $entity, $record
                        );
                    if (
                        $selectedIdx
                        >= count($rows)
                    ) {
                        $selectedIdx =
                            count($rows) - 1;
                    }
                }
                $this->__enterRawMode();
                $this->__drainStdin();
                $redraw = true;
            } else {
                switch ($key) {
                    case 'UP':
                    case 'k':
                        if ($selectedIdx > 0) {
                            $selectedIdx--;
                            $redraw = true;
                        }
                        break;

                    case 'DOWN':
                    case 'j':
                        if (
                            $selectedIdx
                            < $rowCount - 1
                        ) {
                            $selectedIdx++;
                            $redraw = true;
                        }
                        break;

                    case 'ENTER':
                    case 'e':
                        $row = $rows[$selectedIdx];
                        if (
                            empty($row['editable'])
                        ) {
                            break;
                        }
                        $this->__exitRawMode();
                        $saved =
                            $this
                            ->__editDetailField(
                                $entity, $id,
                                $row['field'],
                                $row['value']
                            );
                        if ($saved) {
                            $fresh =
                                $this
                                ->__fetchDetail(
                                    $entity, $id
                                );
                            if (!empty($fresh)) {
                                $record = $fresh;
                                $rows =
                                    $this
                                    ->__buildDetailRows(
                                        $entity,
                                        $record
                                    );
                                if (
                                    $selectedIdx
                                    >= count($rows)
                                ) {
                                    $selectedIdx =
                                        count($rows)
                                        - 1;
                                }
                            }
                        }
                        $this->__enterRawMode();
                        $redraw = true;
                        break;

                    case 'q':
                    case 'ESCAPE':
                        break 2;

                    default:
                        break;
                }
            }

            if ($redraw) {
                $this->__renderDetailBrowse(
                    $entity, $id, $rows,
                    $selectedIdx, $viewportOff,
                    $children
                );
            }
        }

        $this->__exitRawMode();
    }

    /**
     * Navigate to a child entity list from
     * the detail view.
     *
     * Sets appropriate context/filters and opens
     * a browse list for the child entity.
     *
     * @param string $parentEntity Parent entity
     * @param int    $parentId     Parent record ID
     * @param array  $child        Child definition
     * @return void
     */
    private function __navigateToChild(
        $parentEntity, $parentId, $child
    ) {
        $childEntity = $child['entity'];

        $savedContext = $this->__context;
        if (
            in_array(
                $parentEntity, ['event', 'object']
            )
        ) {
            $this->__context = [
                'entity' => $parentEntity,
                'id' => $parentId,
            ];
        }

        $args = [];
        if (!empty($child['filter'])) {
            $args[] = $child['filter']
                . '=' . $parentId;
        }

        $this->__cmdList($childEntity, $args);

        $this->__context = $savedContext;
    }

    /**
     * Build flat row list from a detail record.
     *
     * Each row: [section, field, value, editable]
     *
     * @param string $entity Entity name
     * @param array  $record Full record data
     * @return array Rows for detail browse
     */
    private function __buildDetailRows(
        $entity, $record
    ) {
        $config = $this->__entityConfig[$entity];
        $alias = $this->__modelAlias($entity);
        $editable = !empty($config['editableFields'])
            ? $config['editableFields'] : [];

        $canWrite = true;
        if (
            !empty($config['adminOnly'])
            || !empty($config['writeAdminOnly'])
        ) {
            $canWrite = !empty(
                $this->__user['Role']
                    ['perm_site_admin']
            );
        }

        if (isset($record[$alias])) {
            $data = $record[$alias];
        } elseif (
            isset($record[ucfirst($entity)])
        ) {
            $data = $record[ucfirst($entity)];
        } elseif (isset($record['Event'])) {
            $data = $record['Event'];
        } else {
            $data = $record;
        }

        $fkMap = [
            'org_id' => 'org',
            'orgc_id' => 'org',
            'event_id' => 'event',
            'role_id' => 'role',
            'sharing_group_id' => 'sharing_group',
            'object_id' => 'object',
        ];

        $rows = [];
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                continue;
            }
            $display = (string)$value;
            if (
                isset($fkMap[$key])
                && !empty($value)
            ) {
                $display = $this->__resolveFK(
                    $fkMap[$key], $value
                );
            }
            $rows[] = [
                'section' => null,
                'field' => $key,
                'value' => $display,
                'editable' => $canWrite
                    && in_array($key, $editable),
            ];
        }

        foreach ($record as $section => $sData) {
            if ($section === $alias) {
                continue;
            }
            if ($section === ucfirst($entity)) {
                continue;
            }
            if ($section === 'Event') {
                continue;
            }
            if (!is_array($sData)) {
                continue;
            }

            if (
                $entity === 'object'
                && $section === 'Attribute'
                && !$this->__isAssocArray($sData)
            ) {
                $rows[] = [
                    'section' => 'Attributes',
                    'field' => null,
                    'value' => null,
                    'editable' => false,
                ];
                foreach ($sData as $attr) {
                    $rel = isset(
                        $attr['object_relation']
                    )
                        ? $attr['object_relation']
                        : $attr['type'];
                    $ids = !empty($attr['to_ids'])
                        ? ' [IDS]' : '';
                    $rows[] = [
                        'section' => 'Attributes',
                        'field' => $rel,
                        'value' => $attr['value']
                            . $ids,
                        'editable' => false,
                    ];
                }
                continue;
            }

            if (!$this->__isAssocArray($sData)) {
                continue;
            }
            $rows[] = [
                'section' => $section,
                'field' => null,
                'value' => null,
                'editable' => false,
            ];
            foreach ($sData as $k => $v) {
                if (is_array($v)) {
                    continue;
                }
                $rows[] = [
                    'section' => $section,
                    'field' => $k,
                    'value' => (string)$v,
                    'editable' => false,
                ];
            }
        }

        return $rows;
    }

    /**
     * Render the interactive detail view.
     *
     * @param string $entity      Entity name
     * @param int    $id          Record ID
     * @param array  $rows        Detail rows
     * @param int    $selectedIdx Selected row index
     * @param int    &$viewportOff Viewport offset
     * @param array  $children    Child entity defs
     * @return void
     */
    private function __renderDetailBrowse(
        $entity, $id, $rows,
        $selectedIdx, &$viewportOff,
        $children = []
    ) {
        $termSize = $this->__getTerminalSize();
        $termWidth = $termSize[0];
        $termHeight = $termSize[1];

        $viewportRows = $termHeight - 5;
        if ($viewportRows < 1) {
            $viewportRows = 1;
        }

        $rowCount = count($rows);
        if ($selectedIdx >= $rowCount) {
            $selectedIdx = $rowCount - 1;
        }
        if ($selectedIdx < 0) {
            $selectedIdx = 0;
        }

        if (
            $selectedIdx
            >= $viewportOff + $viewportRows
        ) {
            $viewportOff =
                $selectedIdx - $viewportRows + 1;
        }
        if ($selectedIdx < $viewportOff) {
            $viewportOff = $selectedIdx;
        }

        $maxKeyLen = 0;
        foreach ($rows as $row) {
            if ($row['field'] === null) {
                continue;
            }
            $len = strlen($row['field']);
            if ($row['section'] !== null) {
                $len += 2;
            }
            if ($len > $maxKeyLen) {
                $maxKeyLen = $len;
            }
        }
        $maxKeyLen = min($maxKeyLen, 30);

        $this->out("\033[H\033[J", 0);

        $title = '=== ' . ucfirst($entity)
            . ' #' . $id . ' ===';
        $this->out(' ' . $title);
        $this->out('');

        $start = $viewportOff;
        $end = min(
            $rowCount, $start + $viewportRows
        );

        for ($r = $start; $r < $end; $r++) {
            $row = $rows[$r];

            if (
                $row['field'] === null
                && $row['section'] !== null
            ) {
                $line = '  ['
                    . $row['section'] . ']';
                if ($r === $selectedIdx) {
                    $line = "\033[7m"
                        . str_pad(
                            $line, $termWidth - 1
                        )
                        . "\033[0m";
                }
                $this->out($line);
                continue;
            }

            $indent = $row['section'] !== null
                ? '    ' : '  ';
            $keyPad = $row['section'] !== null
                ? $maxKeyLen - 2 : $maxKeyLen;
            $key = str_pad(
                $row['field'], $keyPad
            );
            $marker = $row['editable']
                ? "\xe2\x9c\x8e " : '  ';
            $valStr = $row['value'];

            $maxVal = $termWidth
                - strlen($indent) - $keyPad
                - 5 - 2;
            if ($maxVal < 10) {
                $maxVal = 10;
            }
            if (strlen($valStr) > $maxVal) {
                $valStr = substr(
                    $valStr, 0, $maxVal - 2
                ) . '..';
            }

            $line = $indent . $key
                . ' : ' . $marker . $valStr;

            if ($r === $selectedIdx) {
                $padded = str_pad(
                    $line, $termWidth - 1
                );
                $line = "\033[7m"
                    . $padded . "\033[0m";
            }

            $this->out($line);
        }

        $remaining = $viewportRows
            - ($end - $start);
        for ($i = 0; $i < $remaining; $i++) {
            $this->out('');
        }

        $this->out('');
        $editHint = '';
        if (
            $rowCount > 0
            && !empty($rows[$selectedIdx]['editable'])
        ) {
            $editHint = '  [Enter/e] Edit';
        }

        $childHints = '';
        foreach ($children as $i => $child) {
            $childHints .= '  [' . ($i + 1)
                . '] ' . $child['label'];
        }

        $footer = ' ['
            . "\xe2\x86\x91" . '/'
            . "\xe2\x86\x93"
            . '] Nav'
            . $editHint
            . $childHints
            . '  [q] Back';
        $this->out($footer, 0);
        if ($this->__rawMode) {
            fflush(STDOUT);
        }
    }

    /**
     * Edit a single field from the detail view.
     *
     * @param string $entity Entity name
     * @param int    $id     Record ID
     * @param string $field  Field name
     * @param string $current Current value
     * @return bool Whether the save succeeded
     */
    private function __editDetailField(
        $entity, $id, $field, $current
    ) {
        $config = $this->__entityConfig[$entity];
        $modelName = $config['model'];
        $alias = $this->__modelAlias($entity);

        if (
            !isset($this->__fieldMeta[$entity][$field])
        ) {
            $this->out(
                '  Field "' . $field
                . '" has no edit metadata.'
            );
            return false;
        }

        $meta = $this->__fieldMeta[$entity][$field];
        $fType = isset($meta['type'])
            ? $meta['type'] : 'string';
        if ($fType === 'boolean') {
            $current = !empty($current)
                && $current !== '0'
                ? '1' : '0';
        }

        $this->out('');
        $newVal = $this->__promptForField(
            $field, $meta, $current
        );
        if (
            $newVal === null
            || $newVal === $current
        ) {
            $this->out('  No change.');
            return false;
        }

        $this->{$modelName}->id = $id;
        $result = $this->{$modelName}->save(
            [
                $alias => [
                    'id' => $id,
                    $field => $newVal,
                ],
            ],
            true,
            [$field]
        );

        if ($result) {
            $this->out(
                '  ' . ucfirst($entity)
                . ' #' . $id . ' updated.'
            );
            return true;
        }

        $this->err(
            '  Failed to update ' . $field . '.'
        );
        if (
            !empty(
                $this->{$modelName}
                    ->validationErrors
            )
        ) {
            foreach (
                $this->{$modelName}
                    ->validationErrors
                as $f => $errs
            ) {
                $errMsg = is_array($errs)
                    ? implode(', ', $errs)
                    : $errs;
                $this->err(
                    '    ' . $f . ': ' . $errMsg
                );
            }
        }
        return false;
    }

    /**
     * Enter raw terminal mode.
     *
     * @return void
     */
    private function __enterRawMode()
    {
        if (
            $this->__rawMode || !$this->__isTty
        ) {
            return;
        }
        shell_exec(
            'stty -icanon -echo 2>/dev/null'
        );
        $this->__rawMode = true;
    }

    /**
     * Exit raw terminal mode.
     *
     * @return void
     */
    private function __exitRawMode()
    {
        if (!$this->__rawMode) {
            return;
        }
        shell_exec(
            'stty icanon echo 2>/dev/null'
        );
        $this->__rawMode = false;
    }

    /**
     * Drain any buffered input from stdin.
     *
     * Discards pending keypresses so they don't
     * interfere with the next interactive prompt.
     *
     * @return void
     */
    private function __drainStdin()
    {
        if (!$this->__rawMode) {
            return;
        }
        stream_set_blocking($this->__stdin, false);
        while (fread($this->__stdin, 64) !== false) {
            $r = [$this->__stdin];
            $w = $e = [];
            if (
                !stream_select($r, $w, $e, 0)
            ) {
                break;
            }
        }
        stream_set_blocking($this->__stdin, true);
    }

    /**
     * Read a single keypress from stdin.
     *
     * @return string|false Key identifier or false
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
     * Interactive filter bar for browse mode.
     *
     * @param string $entity Entity name
     * @return bool Whether filters changed
     */
    private function __filterBar($entity)
    {
        $changed = false;

        while (true) {
            $this->out('');
            if (
                !empty($this->__browseFilters)
            ) {
                $this->out(
                    ' Active filters: '
                    . implode(
                        '  ',
                        $this->__browseFilters
                    )
                );
            } else {
                $this->out(
                    ' No active filters.'
                );
            }

            $this->out(
                ' [Enter] Apply  [Tab] Autocomplete'
                . '  [-key] Remove  [--] Clear all'
                . '  [empty] Close'
            );
            $this->out(
                " \xe2\x96\xb8 Filter: ", 0
            );

            $input = $this->__readFilterLine(
                $entity
            );

            if (
                $input === false || $input === ''
            ) {
                break;
            }

            if ($input === '--') {
                if (
                    !empty($this->__browseFilters)
                ) {
                    $this->__browseFilters = [];
                    $changed = true;
                    $this->out(
                        ' All filters cleared.'
                    );
                }
                continue;
            }

            if (
                strpos($input, '-') === 0
                && strpos($input, '=') === false
            ) {
                $removeKey = substr($input, 1);
                $found = false;
                $newFilters = [];
                foreach (
                    $this->__browseFilters as $f
                ) {
                    $eqPos = strpos($f, '=');
                    $fKey = $eqPos !== false
                        ? substr($f, 0, $eqPos)
                        : $f;
                    if ($fKey === $removeKey) {
                        $found = true;
                        continue;
                    }
                    $newFilters[] = $f;
                }
                if ($found) {
                    $this->__browseFilters =
                        $newFilters;
                    $changed = true;
                    $this->out(
                        ' Removed filter: '
                        . $removeKey
                    );
                } else {
                    $this->out(
                        ' No filter with key: '
                        . $removeKey
                    );
                }
                continue;
            }

            if (strpos($input, '=') !== false) {
                $eqPos = strpos($input, '=');
                $newKey = substr($input, 0, $eqPos);
                $newFilters = [];
                foreach (
                    $this->__browseFilters as $f
                ) {
                    $fEq = strpos($f, '=');
                    $fKey = $fEq !== false
                        ? substr($f, 0, $fEq)
                        : $f;
                    if ($fKey !== $newKey) {
                        $newFilters[] = $f;
                    }
                }
                $newFilters[] = $input;
                $this->__browseFilters =
                    $newFilters;
                $changed = true;
                $this->out(
                    ' Applied filter: ' . $input
                );
            }
        }

        return $changed;
    }

    /**
     * Read a filter input line with tab-completion.
     *
     * @param string $entity Entity name
     * @return string|false Input or false on cancel
     */
    private function __readFilterLine($entity)
    {
        if (!$this->__isTty) {
            $line = fgets($this->__stdin);
            if ($line === false) {
                return false;
            }
            return trim($line);
        }

        $buf = '';
        shell_exec(
            'stty -icanon -echo 2>/dev/null'
        );

        while (true) {
            $ch = fread($this->__stdin, 1);
            if ($ch === false || $ch === '') {
                shell_exec(
                    'stty icanon echo 2>/dev/null'
                );
                return false;
            }

            if ($ch === "\n" || $ch === "\r") {
                $this->out('');
                shell_exec(
                    'stty icanon echo 2>/dev/null'
                );
                return $buf;
            }

            if ($ch === "\033") {
                $seq = fread($this->__stdin, 1);
                if ($seq === '[') {
                    fread($this->__stdin, 1);
                }
                shell_exec(
                    'stty icanon echo 2>/dev/null'
                );
                return false;
            }

            if (ord($ch) === 21) {
                $eraseLen = strlen($buf);
                $this->out(
                    str_repeat("\x08", $eraseLen)
                    . str_repeat(' ', $eraseLen)
                    . str_repeat(
                        "\x08", $eraseLen
                    ),
                    0
                );
                $buf = '';
                continue;
            }

            if (
                $ch === "\x7f" || ord($ch) === 8
            ) {
                if (strlen($buf) > 0) {
                    $buf = substr($buf, 0, -1);
                    $this->out("\x08 \x08", 0);
                }
                continue;
            }

            if ($ch === "\t") {
                $completion =
                    $this->__tabComplete(
                        $buf, $entity
                    );
                if (
                    $completion !== null
                    && $completion !== $buf
                ) {
                    $eraseLen = strlen($buf);
                    $this->out(
                        str_repeat(
                            "\x08", $eraseLen
                        )
                        . str_repeat(
                            ' ', $eraseLen
                        )
                        . str_repeat(
                            "\x08", $eraseLen
                        ),
                        0
                    );
                    $buf = $completion;
                    $this->out($buf, 0);
                }
                continue;
            }

            if (ord($ch) >= 32) {
                $buf .= $ch;
                $this->out($ch, 0);
            }
        }
    }

    /**
     * Tab-complete a partial filter input.
     *
     * @param string $buf Current input buffer
     * @param string $entity Entity name
     * @return string|null Completed string or null
     */
    private function __tabComplete($buf, $entity)
    {
        $filterKeys = [
            'type', 'category', 'tag', 'tag+',
            'org', 'value', 'to_ids', 'from',
            'to', 'last', 'published',
            'threat_level_id', 'analysis',
            'searchall', 'eventid', 'uuid',
            'timestamp', 'publish_timestamp',
            'object_name', 'object_relation',
            'first_seen', 'last_seen', 'deleted',
            'includeCorrelations', 'limit',
            'page', 'order',
        ];

        if (strpos($buf, '=') === false) {
            $matches = [];
            foreach ($filterKeys as $key) {
                if (
                    $buf === ''
                    || strpos($key, $buf) === 0
                ) {
                    $matches[] = $key . '=';
                }
            }
            if (count($matches) === 1) {
                return $matches[0];
            }
            return null;
        }

        $eqPos = strpos($buf, '=');
        $key = substr($buf, 0, $eqPos);
        $partial = substr($buf, $eqPos + 1);

        $lastComma = strrpos($partial, ',');
        if ($lastComma !== false) {
            $prefix = substr(
                $partial, 0, $lastComma + 1
            );
            $fragment = substr(
                $partial, $lastComma + 1
            );
        } else {
            $prefix = '';
            $fragment = $partial;
        }

        if (strpos($fragment, '!') === 0) {
            $neg = '!';
            $fragment = substr($fragment, 1);
        } else {
            $neg = '';
        }

        $candidates =
            $this->__getCompletionValues(
                $key, $entity
            );
        if (empty($candidates)) {
            return null;
        }

        $matches = [];
        foreach ($candidates as $c) {
            if (
                $fragment === ''
                || stripos($c, $fragment) === 0
            ) {
                $matches[] = $c;
            }
        }

        if (count($matches) === 1) {
            return $key . '='
                . $prefix . $neg . $matches[0];
        }

        return null;
    }

    /**
     * Get completion values for a filter key.
     *
     * @param string $key Filter key
     * @param string $entity Entity name
     * @return array Candidate values
     */
    private function __getCompletionValues(
        $key,
        $entity
    ) {
        if ($key === 'type') {
            if (
                property_exists(
                    $this->MispAttribute,
                    'typeDefinitions'
                )
            ) {
                return array_keys(
                    $this->MispAttribute
                        ->typeDefinitions
                );
            }
            return [];
        }

        if ($key === 'category') {
            if (
                property_exists(
                    $this->MispAttribute,
                    'categoryDefinitions'
                )
            ) {
                return array_keys(
                    $this->MispAttribute
                        ->categoryDefinitions
                );
            }
            return [];
        }

        if ($key === 'tag' || $key === 'tag+') {
            $tags = $this->Tag->find('list', [
                'fields' => ['Tag.name'],
                'limit' => 200,
                'order' => [
                    'Tag.name' => 'ASC',
                ],
            ]);
            return array_values($tags);
        }

        if ($key === 'org') {
            $orgs = $this->Organisation->find(
                'list',
                [
                    'fields' => [
                        'Organisation.name',
                    ],
                    'limit' => 200,
                    'order' => [
                        'Organisation.name' => 'ASC',
                    ],
                ]
            );
            return array_values($orgs);
        }

        if ($key === 'threat_level_id') {
            return ['1', '2', '3', '4'];
        }

        if ($key === 'analysis') {
            return ['0', '1', '2'];
        }

        if (
            $key === 'published'
            || $key === 'to_ids'
        ) {
            return ['0', '1'];
        }

        return [];
    }

    /**
     * add command - interactive guided creation.
     *
     * @param string|null $entity Entity name
     * @return void
     */
    private function __cmdAdd($entity)
    {
        if (empty($entity)) {
            $this->err('Usage: add <entity>');
            return;
        }
        if (
            !isset($this->__entityConfig[$entity])
        ) {
            $this->err(
                "Unknown entity: '"
                . $entity . "'"
            );
            return;
        }
        $config = $this->__entityConfig[$entity];
        if (
            (
                !empty($config['adminOnly'])
                || !empty($config['writeAdminOnly'])
            )
            && empty(
                $this->__user['Role']
                    ['perm_site_admin']
            )
        ) {
            $this->err(
                'Permission denied: '
                . $entity
                . ' requires site admin access.'
            );
            return;
        }

        switch ($entity) {
            case 'event':
                $this->__addEvent();
                break;
            case 'attribute':
                $this->__addAttribute();
                break;
            case 'object':
                $this->__addObject();
                break;
            case 'tag':
                $this->__addTag();
                break;
            case 'user':
                $this->__addUser();
                break;
            case 'organisation':
                $this->__addOrganisation();
                break;
            case 'role':
                $this->__addRole();
                break;
            default:
                $this->err(
                    'Add not supported for '
                    . $entity . '.'
                );
        }
    }

    /**
     * edit command - interactive field editing.
     *
     * @param string|null $entity Entity name
     * @param int|null $id Entity ID
     * @return void
     */
    private function __cmdEdit($entity, $id)
    {
        if (empty($entity)) {
            $this->err(
                'Usage: edit <entity> <id>'
            );
            return;
        }
        if (
            !isset($this->__entityConfig[$entity])
        ) {
            $this->err(
                "Unknown entity: '"
                . $entity . "'"
            );
            return;
        }
        if (empty($id) && !is_numeric($id)) {
            $this->err(
                'Usage: edit <entity> <id>'
            );
            return;
        }
        if (!is_numeric($id)) {
            $this->err(
                "Invalid ID: '" . $id . "'"
            );
            return;
        }
        $config = $this->__entityConfig[$entity];
        if (
            (
                !empty($config['adminOnly'])
                || !empty($config['writeAdminOnly'])
            )
            && empty(
                $this->__user['Role']
                    ['perm_site_admin']
            )
        ) {
            $this->err(
                'Permission denied: '
                . $entity
                . ' requires site admin access.'
            );
            return;
        }
        if (empty($config['editableFields'])) {
            $this->err(
                'Edit not supported for '
                . $entity . '.'
            );
            return;
        }
        if (
            !isset($this->__fieldMeta[$entity])
        ) {
            $this->err(
                'Edit not supported for '
                . $entity . '.'
            );
            return;
        }

        switch ($entity) {
            case 'event':
                $this->__editEvent($id);
                break;
            case 'attribute':
                $this->__editAttribute($id);
                break;
            case 'object':
                $this->__editObject($id);
                break;
            case 'tag':
                $this->__editTag($id);
                break;
            case 'user':
                $this->__editUser($id);
                break;
            case 'organisation':
                $this->__editOrganisation($id);
                break;
            case 'role':
                $this->__editRole($id);
                break;
            default:
                $this->err(
                    'Edit not supported for '
                    . $entity . '.'
                );
        }
    }

    /**
     * delete command - delete with confirmation.
     *
     * @param string|null $entity Entity name
     * @param int|null $id Entity ID
     * @return void
     */
    private function __cmdDelete($entity, $id)
    {
        if (empty($entity)) {
            $this->err(
                'Usage: delete <entity> <id>'
            );
            return;
        }
        if (
            !isset($this->__entityConfig[$entity])
        ) {
            $this->err(
                "Unknown entity: '"
                . $entity . "'"
            );
            return;
        }
        if (empty($id) && !is_numeric($id)) {
            $this->err(
                'Usage: delete <entity> <id>'
            );
            return;
        }
        if (!is_numeric($id)) {
            $this->err(
                "Invalid ID: '" . $id . "'"
            );
            return;
        }
        $config = $this->__entityConfig[$entity];
        if (
            (
                !empty($config['adminOnly'])
                || !empty($config['writeAdminOnly'])
            )
            && empty(
                $this->__user['Role']
                    ['perm_site_admin']
            )
        ) {
            $this->err(
                'Permission denied: '
                . $entity
                . ' requires site admin access.'
            );
            return;
        }

        switch ($entity) {
            case 'event':
                $this->__deleteEvent($id);
                break;
            case 'attribute':
                $this->__deleteAttribute($id);
                break;
            case 'object':
                $this->__deleteObject($id);
                break;
            case 'tag':
                $this->__deleteTag($id);
                break;
            case 'user':
                $this->__deleteUser($id);
                break;
            case 'organisation':
                $this->__deleteOrganisation($id);
                break;
            case 'role':
                $this->__deleteRole($id);
                break;
            default:
                $this->err(
                    'Delete not supported for '
                    . $entity . '.'
                );
        }
    }

    /**
     * Restore terminal to sane state.
     *
     * @return void
     */
    public function restoreTerminal()
    {
        if ($this->__rawMode) {
            shell_exec(
                'stty icanon echo 2>/dev/null'
            );
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
