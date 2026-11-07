<?php
/**
 * Render shared templates without a database. These small helper doubles only
 * provide the Form/Paginator calls used here; this is not a Cake integration
 * test. Invoked by test_overmind_accessibility.py, never served over HTTP.
 */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

function h($text)
{
    return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8');
}

function __($text, ...$args)
{
    return $args ? vsprintf($text, $args) : $text;
}

class Hash
{
    public static function get($data, $path)
    {
        foreach (explode('.', $path) as $key) {
            $data = $data[$key] ?? null;
        }
        return $data;
    }
}

function fixtureAttributes($attributes)
{
    $result = '';
    foreach ($attributes as $key => $value) {
        $result .= ' ' . h($key) . '="' . h($value) . '"';
    }
    return $result;
}

class AccessibilityFixtureForm
{
    public function checkbox($name, $attributes)
    {
        return '<input name="' . h($name) . '"'
            . fixtureAttributes($attributes) . '>';
    }
}

class AccessibilityFixturePaginator
{
    public $page = 1;

    public function params()
    {
        return ['page' => $this->page, 'pageCount' => 12];
    }

    public function hasPrev()
    {
        return $this->page > 1;
    }

    public function hasNext()
    {
        return $this->page < 12;
    }

    public function link($label, $url, $attributes)
    {
        $escape = $attributes['escape'] ?? true;
        unset($attributes['escape']);
        return '<a href="?page=' . (int)$url['page'] . '"'
            . fixtureAttributes($attributes) . '>'
            . ($escape ? h($label) : $label) . '</a>';
    }

    public function prev($label, $attributes, $unused, $disabled)
    {
        return $this->link($label, ['page' => $this->page - 1], $attributes);
    }

    public function next($label, $attributes, $unused, $disabled)
    {
        return $this->link($label, ['page' => $this->page + 1], $attributes);
    }
}

class AccessibilityFixtureView
{
    public $Form;
    public $Paginator;
    private $elements;

    public function __construct($root)
    {
        $this->Form = new AccessibilityFixtureForm();
        $this->Paginator = new AccessibilityFixturePaginator();
        $this->elements = $root . '/app/View/Themed/Overmind/Elements/';
    }

    public function element($name, $vars = [])
    {
        $file = $this->elements . $name . '.ctp';
        if (!is_file($file)) {
            return '';
        }
        extract($vars);
        ob_start();
        include $file;
        return ob_get_clean();
    }
}

$root = $argv[1] ?? dirname(__DIR__, 2);
$view = new AccessibilityFixtureView($root);
$prefix = 'genericElementsBS5/IndexTable/';
$field = ['data_path' => 'id'];
$row = ['id' => '42 <tag> & "quoted"'];
$vars = ['row' => $row, 'field' => $field, 'isSiteAdmin' => true];
$fixtures = [
    'chrome' => $view->element('chrome_containers'),
    'legacyChrome' => $view->element('chrome_containers', ['legacy' => true]),
    'skip' => $view->element('skip_link'),
    'headers' => $view->element($prefix . 'headers', [
        'fields' => [['element' => 'checkbox'], ['name' => 'Item']],
        'paginator' => $view->Paginator,
    ]),
    'checkbox' => $view->element($prefix . 'Fields/checkbox', $vars),
    'selector' => $view->element($prefix . 'Fields/selector', $vars),
    'proposal' => $view->element($prefix . 'Fields/checkbox', [
        'row' => ['is_proposal' => true], 'field' => $field,
    ]),
];
foreach ([1, 6, 12] as $page) {
    $view->Paginator->page = $page;
    $fixtures['page' . $page] = $view->element($prefix . 'pagination_nav', [
        'maxPages' => 5,
    ]);
}
echo json_encode($fixtures, JSON_THROW_ON_ERROR);
