<?php
/**
 * Exercise real catalog lookup and plural rules with the bundled framework.
 * Run: php tests/translation_smoke.php
 * No application config, database, cache files or Composer packages are needed.
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
App::build(['Locale' => [APP . 'Locale/']], App::RESET);

$expected = [
    'eng' => ['Log in', ['0 member organisations', '1 member organisation', '2 member organisations']],
    'zh-s' => ['登录', ['0 个成员组织', '1 个成员组织', '2 个成员组织']],
    'fra' => ['Se connecter', ['0 organisation membre', '1 organisation membre', '2 organisations membres']],
    'deu' => ['Anmelden', ['0 Mitgliedsorganisationen', '1 Mitgliedsorganisation', '2 Mitgliedsorganisationen']],
    'pt' => ['Iniciar sessão', ['0 organizações membros', '1 organização membro', '2 organizações membros']],
    'pt_BR' => ['Entrar', ['0 organização membro', '1 organização membro', '2 organizações membros']],
];
$checks = 0;
$check = function ($actual, $expected, $label) use (&$checks) {
    $checks++;
    if ($actual !== $expected) {
        fwrite(STDERR, $label . ': expected ' . var_export($expected, true)
            . ', got ' . var_export($actual, true) . "\n");
        exit(1);
    }
};
foreach ($expected as $locale => [$login, $members]) {
    // A fresh L10n matches a new request after AppController sets Config.language.
    Configure::write('Config.language', $locale);
    I18n::clear();
    I18n::getInstance()->l10n = new L10n();
    $check(__('Log in'), $login, $locale . ' login');
    foreach ([0, 1, 2] as $count) {
        $check(
            __n('%s member organisation', '%s member organisations', $count, $count),
            $members[$count],
            $locale . ' plural ' . $count
        );
    }
    $check(
        __('MISP translation fallback %s', 'OK'),
        'MISP translation fallback OK',
        $locale . ' English fallback'
    );
    // The navbar's inline JavaScript must remain valid with translated quotes.
    $baseurl = '';
    ob_start();
    include APP . 'View/Themed/Overmind/Elements/navbar_actions.ctp';
    $script = ob_get_clean();
    $message = json_encode(__('Homepage saved!'),
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    $check(strpos($script, 'showToast(' . $message . ')') !== false,
        true, $locale . ' navbar message encoding');
}
echo $checks . " translation runtime checks passed.\n";
