<?php
require_once __DIR__ . '/MispQLBackend.php';
require_once __DIR__ . '/MispQLCompiler.php';
require_once __DIR__ . '/MispQLLexer.php';
require_once __DIR__ . '/MispQLParser.php';
require_once __DIR__ . '/MispQLTables.php';

/**
 * What the query console needs to colour and suggest statements for one
 * user: the keywords, the tables the user may query and, per table, its
 * fields, sort names, formats, default columns and aliases.
 */
class MispQLLanguagePack
{
    const CLIENT_STATEMENTS = ['USE', 'SHOW DATABASES'];

    /**
     * @param MispQLTables $tables
     * @param MispQLBackend $backend
     * @param callable $formats given a table, the returnFormat names its
     *   restSearch accepts
     * @return array
     */
    public static function build(MispQLTables $tables, MispQLBackend $backend, callable $formats)
    {
        $treeLimits = [];
        $packed = [];
        foreach ($backend->tables() as $name) {
            $found = $backend->describe($name);
            $table = $tables->get($name);
            $packed[$name] = [
                'endpoint' => $tables->search($name),
                'description' => self::description($name),
                'fields' => (object)$found['tables'][$name]['fields'],
                'order_by' => (object)$tables->sortable($name),
                'formats' => array_values($formats($name)),
                'default_columns' => $table['columns'],
                'aliases' => (object)$table['aliases'],
            ];
            $treeLimits = $found['limits'];
        }
        return [
            'language' => MispQLCompiler::LANGUAGE,
            'keywords' => array_keys(MispQLLexer::KEYWORDS),
            'client_statements' => self::CLIENT_STATEMENTS,
            'renderings' => MispQLCompiler::RENDERINGS,
            'limits' => (object)($treeLimits + [
                'max_length' => MispQLLexer::MAX_LENGTH,
                'max_nesting' => MispQLParser::MAX_DEPTH,
            ]),
            'tables' => (object)$packed,
        ];
    }

    /**
     * @param string $table
     * @return string
     */
    private static function description($table)
    {
        switch ($table) {
            case 'attributes':
                return __('Attributes, each with its event and its tags');
            case 'events':
                return __('Events; attribute and object fields select events holding a match');
            case 'objects':
                return __('Objects, each with the attributes of it you can see');
            case 'galaxy_clusters':
                return __('Galaxy clusters, with their galaxy');
            case 'event_reports':
                return __('Event reports, searched as children of their event');
            case 'notes':
                return __('Analyst notes');
            case 'opinions':
                return __('Analyst opinions');
            case 'relationships':
                return __('Analyst relationships');
            case 'collections':
                return __('Collections, each with its elements');
            case 'tags':
                return __('Every tag on the instance, with usage counts');
            case 'organisations':
                return __('Every organisation, local and external');
        }
        return '';
    }
}
