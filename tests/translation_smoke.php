<?php
/**
 * Real catalog lookup, plural dispatch and script encoding without app config/DB.
 * Run: php tests/translation_smoke.php [directory-for-rendered-navbar-scripts]
 */
define('DS', DIRECTORY_SEPARATOR);
define('ROOT', dirname(__DIR__));
define('APP_DIR', 'app');
define('WWW_ROOT', ROOT . DS . APP_DIR . DS . 'webroot' . DS);
$boot = false;
require ROOT . '/app/Lib/cakephp/lib/Cake/bootstrap.php';
Configure::write('Cache.disable', true);
Configure::write('App.encoding', 'UTF-8');
App::uses('I18n', 'I18n');
App::uses('MispLanguage', 'Tools');
App::build(['Locale' => [APP . 'Locale/']], App::RESET);
$coverage = json_decode(file_get_contents(ROOT . '/tools/i18n/overmind-core.json'), true);

// Expected integer-count grammar, independent of CakePHP's header heuristics.
$pluralIndex = function ($locale, $n) {
    if (in_array($locale, ['jpn', 'kor', 'th_TH', 'zh-s'], true)) {
        return 0;
    }
    if (in_array($locale, ['fra', 'pt_BR'], true)) {
        return $n > 1 ? 1 : 0;
    }
    if ($locale === 'ara') {
        return $n === 0 ? 0 : ($n === 1 ? 1 : ($n === 2 ? 2
            : ($n % 100 >= 3 && $n % 100 <= 10 ? 3 : ($n % 100 >= 11 ? 4 : 5))));
    }
    if ($locale === 'cze') {
        return $n === 1 ? 0 : ($n >= 2 && $n <= 4 ? 1 : 2);
    }
    if ($locale === 'pol') {
        return $n === 1 ? 0 : ($n % 10 >= 2 && $n % 10 <= 4
            && ($n % 100 < 12 || $n % 100 > 14) ? 1 : 2);
    }
    if (in_array($locale, ['rus', 'ukr'], true)) {
        return $n % 10 === 1 && $n % 100 !== 11 ? 0
            : ($n % 10 >= 2 && $n % 10 <= 4 && ($n % 100 < 12 || $n % 100 > 14) ? 1 : 2);
    }
    if ($locale === 'ro') {
        return $n === 1 ? 0 : ($n === 0 || ($n % 100 > 0 && $n % 100 < 20) ? 1 : 2);
    }
    return $n !== 1 ? 1 : 0;
};
$checks = 0;
$check = function ($actual, $expected, $label) use (&$checks) {
    $checks++;
    if ($actual !== $expected) {
        fwrite(STDERR, $label . ': expected ' . var_export($expected, true)
            . ', got ' . var_export($actual, true) . "\n");
        exit(1);
    }
};

// Render the actual layout preambles, stopping before assets and page chrome.
// Helper-only checks miss layouts that bypass the language mapping entirely.
$layoutView = new class {
    public $params = ['controller' => 'events', 'action' => 'index'];

    public function documentOpening($path)
    {
        $source = file_get_contents($path);
        $head = strpos($source, '<head>');
        if ($head === false) {
            throw new RuntimeException('Missing document head in ' . $path);
        }
        $file = tempnam(sys_get_temp_dir(), 'misp-language-');
        $level = ob_get_level();
        try {
            file_put_contents($file, substr($source, 0, $head));
            $baseurl = '/misp';
            $bootstrapTheme = [
                'mode' => 'dark', 'navbar' => 'rail', 'name' => 'language-test',
            ];
            ob_start();
            include $file;
            return ob_get_clean();
        } finally {
            while (ob_get_level() > $level) {
                ob_end_clean();
            }
            unlink($file);
        }
    }
};
$layoutLanguages = [
    'eng' => ['en', 'ltr'],
    'ara' => ['ar', 'rtl'],
    'zh-s' => ['zh-Hans', 'ltr'],
    'pt_BR' => ['pt-BR', 'ltr'],
    '' => ['en', 'ltr'],
];
foreach (['', 'Themed/UiBeta/', 'Themed/Overmind/'] as $theme) {
    foreach (['default', 'dashboard'] as $layout) {
        $path = APP . 'View/' . $theme . 'Layouts/' . $layout . '.ctp';
        foreach ($layoutLanguages as $locale => [$tag, $direction]) {
            Configure::write('Config.language', $locale);
            $document = new DOMDocument();
            $document->loadHTML($layoutView->documentOpening($path)
                . '<head><title>Language test</title></head><body></body></html>');
            $html = $document->documentElement;
            $label = $theme . $layout . ' (' . $locale . ')';
            $check($html->getAttribute('lang'), $tag, $label . ' lang');
            $check($html->getAttribute('dir'), $direction, $label . ' dir');
            if ($theme === 'Themed/Overmind/') {
                $check($html->getAttribute('class'), 'misp-railed', $label . ' rail');
                $check($html->getAttribute('data-misp-mode'), 'dark', $label . ' mode');
                $check($html->getAttribute('data-misp-theme'), 'language-test', $label . ' theme');
                if ($layout === 'dashboard') {
                    $check($html->getAttribute('data-theme'), 'midnight', $label . ' overlay');
                }
            }
        }
    }
}

$scriptDirectory = $argv[1] ?? null;
if ($scriptDirectory && !is_dir($scriptDirectory)) {
    mkdir($scriptDirectory, 0770, true);
}
$saveScript = function ($script, $locale) use ($scriptDirectory) {
    if ($scriptDirectory) {
        file_put_contents($scriptDirectory . '/navbar-' . $locale . '.js',
            preg_replace('/^<script>|<\/script>$/', '', trim($script)));
    }
};
$locales = ['eng'];
foreach (glob(APP . 'Locale/*/LC_MESSAGES/default.po') as $file) {
    if (!is_link(dirname($file, 2))) {
        $locales[] = basename(dirname($file, 2));
    }
}
$counts = array_merge(range(0, 202), [1000, 1001, 1011, 1022]);
foreach ($locales as $locale) {
    Configure::write('Config.language', $locale);
    I18n::clear();
    I18n::getInstance()->l10n = new L10n();
    $raw = $locale === 'eng' ? [] : I18n::loadPo(APP . 'Locale/' . $locale . '/LC_MESSAGES/default.po');
    $check(MispLanguage::direction($locale), $locale === 'ara' ? 'rtl' : 'ltr', $locale . ' direction');
    $check(preg_match('/^[a-z]{2,3}(?:-[A-Za-z0-9]+)*$/', MispLanguage::htmlLang($locale)),
        1, $locale . ' HTML language');
    $check(__('MISP translation fallback %s', 'OK'),
        'MISP translation fallback OK', $locale . ' English fallback');
    if ($locale === 'eng' || in_array($locale, $coverage['locales'], true)) {
        foreach ($coverage['messages'] as $message => $plural) {
            if (!$plural) {
                $expected = $locale === 'eng' ? $message : ($raw[$message][''] ?? null);
                $check(I18n::translate($message), $expected, $locale . ': ' . $message);
                continue;
            }
            foreach ($counts as $count) {
                $index = $pluralIndex($locale, $count);
                $expected = $locale === 'eng' ? ($count === 1 ? $message : $plural)
                    : ($raw[$message][''][$index] ?? null);
                $check(I18n::translate($message, $plural, null, I18n::LC_MESSAGES, $count),
                    $expected, $locale . ' plural ' . $count . ': ' . $message);
            }
        }
    }
    // Regression for the gettext review finding: literal percent, four args,
    // and reordered Chinese arguments must survive runtime formatting.
    $percentage = __('%s%% of the data of %s is contained in %s (%s matching values)',
        25, 'FEED_A', 'FEED_B', 4);
    foreach (['25%', 'FEED_A', 'FEED_B', '4'] as $part) {
        $check(strpos($percentage, $part) !== false, true, $locale . ' percentage ' . $part);
    }
    $check(strpos($percentage, '%%') === false, true, $locale . ' literal percent');
    $baseurl = '';
    ob_start();
    include APP . 'View/Themed/Overmind/Elements/navbar_actions.ctp';
    $script = ob_get_clean();
    $message = json_encode(__('Homepage saved!'),
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    $check(strpos($script, 'showToast(' . $message . ')') !== false,
        true, $locale . ' navbar encoding');
    $saveScript($script, $locale);
}
// Exercise the actual view with ASCII quotes, a newline and a closing script tag.
App::build(['Locale' => [ROOT . '/tests/fixtures/i18n/', APP . 'Locale/']], App::RESET);
Configure::write('Config.language', 'eng');
I18n::clear();
I18n::getInstance()->l10n = new L10n();
I18n::$defaultDomain = 'quotes';
ob_start();
include APP . 'View/Themed/Overmind/Elements/navbar_actions.ctp';
$script = ob_get_clean();
$check(substr_count($script, '</script>'), 1, 'script terminator is encoded');
$check(strpos($script, 'l\\u0027accueil') !== false, true, 'apostrophe is encoded');
$saveScript($script, 'quotes');
echo $checks . ' translation runtime checks passed for ' . count($locales) . " language choices.\n";
