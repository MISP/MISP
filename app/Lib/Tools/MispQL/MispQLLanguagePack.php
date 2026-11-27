<?php
require_once __DIR__ . '/MispQLBackend.php';
require_once __DIR__ . '/MispQLCompiler.php';
require_once __DIR__ . '/MispQLFieldDocs.php';
require_once __DIR__ . '/MispQLLexer.php';
require_once __DIR__ . '/MispQLParser.php';
require_once __DIR__ . '/MispQLTables.php';

/**
 * What the query console needs to colour and suggest statements for one
 * user: the keywords, the tables the user may query and, per table, its
 * fields with what each means, sort names, formats, default columns, aliases
 * and linked columns;
 * the pages those links open; and the values it offers for a field, from
 * a list (`values`, shared by every field naming it) or looked up through
 * MISP's pickers (`sources`).
 */
class MispQLLanguagePack
{
    const CLIENT_STATEMENTS = ['USE', 'SHOW DATABASES'];

    /**
     * @param MispQLTables $tables
     * @param MispQLBackend $backend
     * @param callable $formats given a table, the returnFormat names its
     *   restSearch accepts
     * @param callable $values given a list's name, its rows:
     *   [{value, label?, description?}], or bare values
     * @return array
     */
    public static function build(MispQLTables $tables, MispQLBackend $backend, callable $formats, callable $values)
    {
        $treeLimits = [];
        $packed = [];
        $lists = [];
        $sources = [];
        $names = $backend->tables();
        foreach ($names as $name) {
            $found = $backend->describe($name);
            $table = $tables->get($name);
            $fields = MispQLFieldDocs::annotate($name, $found['tables'][$name]['fields']);
            foreach ($tables->values($name) as $field => $list) {
                if (!isset($fields[$field])) {
                    continue;
                }
                if (!array_key_exists($list, $lists)) {
                    $lists[$list] = array_values($values($list));
                }
                if (!empty($lists[$list])) {
                    $fields[$field]['values'] = $list;
                }
            }
            foreach ($tables->lookups($name) as $field => $source) {
                if (isset($fields[$field])) {
                    $fields[$field]['lookup'] = $source;
                    $sources[$source] = true;
                }
            }
            $packed[$name] = [
                'endpoint' => $tables->search($name),
                'description' => self::description($name),
                'fields' => (object)$fields,
                'order_by' => (object)$tables->sortable($name),
                'formats' => array_values($formats($name)),
                'default_columns' => $table['columns'],
                'aliases' => (object)$table['aliases'],
                'links' => (object)$tables->links($name),
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
            'pages' => (object)$tables->pages($names),
            'values' => (object)array_filter($lists),
            'sources' => (object)$tables->sources(array_keys($sources)),
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
