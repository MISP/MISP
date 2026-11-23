<?php
require_once __DIR__ . '/MispQLCompiler.php';
require_once __DIR__ . '/MispQLRows.php';
require_once __DIR__ . '/MispQLBackend.php';
require_once __DIR__ . '/MispQLErrors.php';
require_once __DIR__ . '/../ComplexQueryTool.php';

/**
 * Explains scripts and runs statements for one user, through a backend that
 * reaches MISP. Replies carry the language version; refusals are thrown as
 * MispQLErrors, each error placed on the submitted text.
 */
class MispQLRunner
{
    const CLIENT_STATEMENT = 'USE and SHOW DATABASES switch between MISP servers; run them in the mispql client';

    const ONE_STATEMENT = 'run takes one statement';

    /** @var MispQLTables */
    private $tables;

    /** @var MispQLBackend */
    private $backend;

    /** @var MispQLCompiler */
    private $compiler;

    public function __construct(MispQLTables $tables, MispQLBackend $backend)
    {
        $this->tables = $tables;
        $this->backend = $backend;
        $this->compiler = new MispQLCompiler($tables);
    }

    /**
     * Parses and compiles every statement of a script and checks it against
     * this server, reading no data. Statements after a USE are compiled but
     * not checked: they may run on another server.
     *
     * @param string $script
     * @return array
     * @throws MispQLErrors
     */
    public function explain($script)
    {
        try {
            $statements = MispQLParser::parse($script);
        } catch (MispQLException $e) {
            // The script could not be split into statements
            throw new MispQLErrors([self::error($e, null)]);
        }
        $entries = [];
        $errors = [];
        $validated = true;
        foreach ($statements as $i => $statement) {
            try {
                $plan = $this->compiler->compile($statement);
            } catch (MispQLException $e) {
                $errors[] = self::error($e, $i);
                continue;
            }
            if ($validated) {
                $errors = array_merge($errors, $this->check($plan, $i));
            }
            $entries[] = self::entry($plan, $validated);
            if ($plan['kind'] === 'use') {
                $validated = false;
            }
            if (count($errors) >= MispQLErrors::MAX) {
                break;
            }
        }
        if (!empty($errors)) {
            throw new MispQLErrors($errors);
        }
        return ['language' => MispQLCompiler::LANGUAGE, 'statements' => $entries];
    }

    /**
     * Runs one statement. A search whose FORMAT is one of MISP's comes back
     * as kind `export`, with the scope and the backend's run, to be sent as
     * restSearch sends it.
     *
     * @param string $text
     * @return array
     * @throws MispQLErrors
     */
    public function run($text)
    {
        try {
            $statements = MispQLParser::parse($text);
        } catch (MispQLException $e) {
            throw new MispQLErrors([self::error($e, 0)]);
        }
        if (count($statements) !== 1) {
            $length = mb_strlen($text, 'UTF-8');
            $span = isset($statements[1])
                ? [$statements[1]['start'], $statements[1]['end']]
                : [$length, $length];
            throw new MispQLErrors([
                self::located(0, $span, MispQLException::SYNTAX, self::ONE_STATEMENT),
            ]);
        }
        try {
            $plan = $this->compiler->compile($statements[0]);
        } catch (MispQLException $e) {
            throw new MispQLErrors([self::error($e, 0)]);
        }
        switch ($plan['kind']) {
            case 'use':
            case 'show_databases':
                throw new MispQLErrors([self::located(
                    0,
                    [$plan['start'], $plan['end']],
                    MispQLException::CLIENT_STATEMENT,
                    self::CLIENT_STATEMENT
                )]);
            case 'show_tables':
                return self::reply('show_tables', ['tables' => $this->backend->tables()]);
            case 'whoami':
                $user = $this->backend->whoami();
                return self::reply('whoami', [
                    'email' => $user['email'],
                    'role' => $user['role'],
                    'org' => $user['org'],
                ]);
            case 'describe':
                return $this->describe($plan);
        }
        $errors = $this->check($plan, 0);
        if (!empty($errors)) {
            throw new MispQLErrors($errors);
        }
        return $plan['kind'] === 'count' ? $this->count($plan) : $this->search($plan);
    }

    private static function reply($kind, array $fields)
    {
        return ['language' => MispQLCompiler::LANGUAGE, 'kind' => $kind] + $fields;
    }

    /**
     * @return array[] the errors the backend finds in the plan's request,
     *   placed on the text
     */
    private function check(array $plan, $index)
    {
        if (!isset($plan['body'])) {
            return [];
        }
        try {
            $this->backend->validate($plan['table'], $plan['body']);
        } catch (ComplexQueryException $e) {
            return self::placed($plan, $e->errors, $index);
        }
        return [];
    }

    private function execute(array $plan, array $body)
    {
        try {
            return $this->backend->search($plan['table'], $body);
        } catch (ComplexQueryException $e) {
            throw new MispQLErrors(self::placed($plan, $e->errors, 0));
        }
    }

    private function describe(array $plan)
    {
        $found = $this->backend->describe($plan['table']);
        if (!isset($found['tables'][$plan['table']]['fields'], $found['limits'])) {
            throw new UnexpectedValueException('no fields in the description');
        }
        return self::reply('describe', [
            'table' => $plan['table'],
            'fields' => (object)$found['tables'][$plan['table']]['fields'],
            'order_by' => array_keys($this->tables->sortable($plan['table'])),
            'limits' => (object)$found['limits'],
        ]);
    }

    private function count(array $plan)
    {
        $run = $this->execute($plan, $plan['body']);
        if ($plan['source'] === 'header') {
            $count = (int)$run['count'];
        } else {
            $text = trim(self::text($run['result']));
            if (!preg_match('/^\d+$/', $text)) {
                throw new UnexpectedValueException('no count in the answer');
            }
            $count = (int)$text;
        }
        return self::reply('count', [
            'table' => $plan['table'],
            'count' => $count,
            'request' => self::request($plan['endpoint'], $plan['body']),
        ]);
    }

    private function search(array $plan)
    {
        if ($plan['output'] === 'verbatim') {
            return [
                'kind' => 'export',
                'scope' => $this->tables->scope($plan['table']),
                'run' => $this->execute($plan, $plan['body']),
            ];
        }
        $table = $this->tables->get($plan['table']);
        $run = $this->execute($plan, $plan['body']);
        $rows = self::rows($run, $table['rowKey']);
        $warnings = self::capped($plan, $run, count($rows));
        if ($plan['skip'] > 0) {
            $limit = $plan['body']['limit'];
            if (count($rows) === $limit) {
                $next = $this->execute($plan, self::nextPage($plan['body']));
                $rows = array_merge($rows, self::rows($next, $table['rowKey']));
            }
            $rows = array_slice($rows, $plan['skip'], $limit);
        }
        $columns = null;
        if ($plan['output'] !== 'default' || $plan['columns'] !== null) {
            $flat = array_map([MispQLRows::class, 'flatten'], $rows);
            list($columns, $cells, $missing) = MispQLRows::project($plan, $flat, $table['columns']);
            $rows = [];
            foreach ($cells as $values) {
                $row = new stdClass();
                foreach ($columns as $i => $column) {
                    $row->$column = $values[$i];
                }
                $rows[] = $row;
            }
            $warnings = array_merge($missing, $warnings);
        }
        return self::reply('search', [
            'table' => $plan['table'],
            'output' => $plan['output'],
            'columns' => $columns,
            'rows' => $rows,
            // Only events count every match; the other scopes count the page
            'total' => $table['count'] === 'header' ? (int)$run['count'] : null,
            'warnings' => $warnings,
            'request' => self::request($plan['endpoint'], $plan['body']),
        ]);
    }

    /**
     * @return string[] a warning when the role's restSearch limit, not the
     *   statement, ended the first page
     */
    private static function capped(array $plan, array $run, $found)
    {
        $allowed = (int)($run['filters']['limit'] ?? 0);
        $asked = $plan['body']['limit'] ?? null;
        if ($allowed > 0 && ($asked === null || $allowed < $asked) && $found >= $allowed) {
            return ["the role's restSearch limit stopped this search at $allowed rows"];
        }
        return [];
    }

    private static function rows(array $run, $rowKey)
    {
        $reply = json_decode(self::text($run['result']), false, 512, JSON_THROW_ON_ERROR);
        return MispQLRows::unwrap($reply, $rowKey);
    }

    private static function text($result)
    {
        return is_string($result) ? $result : $result->intoString();
    }

    private static function nextPage(array $body)
    {
        $body['page']++;
        return $body;
    }

    private static function request($endpoint, array $body)
    {
        return ['method' => 'POST', 'endpoint' => $endpoint, 'body' => $body];
    }

    /**
     * @return array a plan as explain returns it
     */
    private static function entry(array $plan, $validated)
    {
        $entry = [
            'kind' => $plan['kind'],
            'start' => $plan['start'],
            'end' => $plan['end'],
            'validated' => $validated,
        ];
        switch ($plan['kind']) {
            case 'search':
                $entry += [
                    'table' => $plan['table'],
                    'request' => self::request($plan['endpoint'], $plan['body']),
                ];
                if ($plan['skip'] > 0) {
                    // Sent when the first page is full
                    $entry['next_page'] = self::request($plan['endpoint'], self::nextPage($plan['body']));
                }
                return $entry + [
                    'output' => $plan['output'],
                    'columns' => $plan['columns'],
                    'skip' => $plan['skip'],
                ];
            case 'count':
                return $entry + [
                    'table' => $plan['table'],
                    'request' => self::request($plan['endpoint'], $plan['body']),
                ];
            case 'describe':
                return $entry + [
                    'table' => $plan['table'],
                    'request' => ['method' => 'GET', 'endpoint' => $plan['endpoint']],
                ];
            case 'use':
                return $entry + ['database' => $plan['database']];
            default:
                return $entry;
        }
    }

    /**
     * @param int|null $index the statement, null when the script could not
     *   be split into statements
     */
    private static function error(MispQLException $e, $index)
    {
        return self::located($index, [$e->getStart(), $e->getEnd()], $e->getErrorCode(), $e->getMessage());
    }

    private static function located($index, array $span, $code, $message)
    {
        return [
            'statement' => $index,
            'start' => $span[0],
            'end' => $span[1],
            'code' => $code,
            'message' => $message,
        ];
    }

    /**
     * Errors of the query tree, placed through the plan's spans: the longest
     * prefix of the path the plan knows, else the whole statement.
     */
    private static function placed(array $plan, array $errors, $index)
    {
        $placed = [];
        foreach ($errors as $error) {
            $path = (string)($error['path'] ?? '');
            $span = MispQLCompiler::locate($plan['spans'], $path) ?? [$plan['start'], $plan['end']];
            $placed[] = self::located(
                $index,
                $span,
                (string)($error['code'] ?? ''),
                (string)($error['message'] ?? '')
            ) + ['path' => $path];
        }
        return $placed;
    }
}
