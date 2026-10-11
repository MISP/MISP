<?php
/** Exercise the real CakePHP PO loader without application/database bootstrap. */
$repository = dirname(__DIR__);
$scratch = sys_get_temp_dir() . '/misp-i18n-' . bin2hex(random_bytes(8));
mkdir($scratch . '/app/Config', 0700, true);
mkdir($scratch . '/app/tmp/cache', 0700, true);
file_put_contents($scratch . '/app/Config/core.php', '<?php
Configure::write("Config.language", "eng");
Configure::write("Cache.disable", true);
Configure::write("Error", array());
Configure::write("Exception", array());
');
file_put_contents($scratch . '/app/Config/bootstrap.php', '<?php App::build(array("locales" => array(' .
    var_export($scratch . '/app/Locale/', true) . ', ' .
    var_export($repository . '/app/Locale/', true) . ')));');

function translationCheck($actual, $expected)
{
    if ($actual !== $expected) {
        throw new RuntimeException(var_export($actual, true) . ' !== ' . var_export($expected, true));
    }
}

try {
    define('DS', DIRECTORY_SEPARATOR);
    define('ROOT', $scratch);
    define('APP_DIR', 'app');
    define('WEBROOT_DIR', 'webroot');
    define('APP', ROOT . DS . APP_DIR . DS);
    define('WWW_ROOT', APP . WEBROOT_DIR . DS);
    require $repository . '/app/Lib/cakephp/lib/Cake/bootstrap.php';
    App::uses('I18n', 'I18n');
    require $repository . '/app/Lib/Tools/MispL10n.php';
    I18n::getInstance()->l10n = new MispL10n();

    $catalogs = glob($repository . '/app/Locale/*/LC_MESSAGES/default.po');
    foreach ($catalogs as $catalog) {
        $language = basename(dirname(dirname($catalog)));
        $directory = $scratch . '/app/Locale/' . $language . '/LC_MESSAGES';
        mkdir($directory, 0700, true);
        file_put_contents($directory . '/locale_probe.po', 'msgid ""' . "\n" .
            'msgstr ""' . "\n" . '"Content-Type: text/plain; charset=UTF-8\n"' . "\n\n" .
            'msgid "catalog probe"' . "\n" . 'msgstr "' . $language . '"' . "\n");
    }
    // Interleave languages to catch accidental reuse of another locale's domain.
    foreach (array_merge($catalogs, array_reverse($catalogs)) as $catalog) {
        $language = basename(dirname(dirname($catalog)));
        Configure::write('Config.language', $language);
        translationCheck(I18n::translate('catalog probe', null, 'locale_probe'), $language);
        translationCheck(I18n::getInstance()->l10n->languagePath[0], $language);
    }
    foreach (array(
        'fra' => 'Vue en cartes', 'deu' => 'Kartenansicht',
        'spa' => 'Vista de tarjetas', 'ita' => 'Vista a schede',
        'pt' => 'Vista de cartões', 'pt_BR' => 'Vista de cartões',
    ) as $language => $expected) {
        Configure::write('Config.language', $language);
        translationCheck(I18n::translate('Card View'), $expected);
    }
    // A replacement resolver must be initialized even when I18n caches the language.
    Configure::write('Config.language', 'pt_BR');
    I18n::translate('Card View');
    I18n::getInstance()->l10n = new MispL10n();
    translationCheck(I18n::getInstance()->l10n->languagePath[0], 'pt_BR');
    translationCheck(I18n::translate('Card View'), 'Vista de cartões');
    Configure::write('Config.language', 'eng');
    translationCheck(I18n::translate('Card View'), 'Card View');
    Configure::write('Config.language', 'ara');
    I18n::translate('catalog probe', null, 'locale_probe');
    translationCheck(I18n::getInstance()->l10n->direction, 'rtl');
    echo count($catalogs) . " locale catalogs resolved; six new translations and English/RTL fallback passed.\n";
} finally {
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($scratch, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($files as $file) {
        $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
    }
    rmdir($scratch);
}
