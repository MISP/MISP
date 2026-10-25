<?php
App::uses('L10n', 'I18n');

/** Display metadata for catalog codes; directory names stay Crowdin-compatible. */
class MispLanguage
{
    const LANGUAGES = [
        'eng' => ['English', 'en'],
        'ara' => ['العربية', 'ar'],
        'cze' => ['Čeština', 'cs'],
        'dan' => ['Dansk', 'da'],
        'deu' => ['Deutsch', 'de'],
        'fra' => ['Français', 'fr'],
        'hun' => ['Magyar', 'hu'],
        'ita' => ['Italiano', 'it'],
        'jpn' => ['日本語', 'ja'],
        'kor' => ['한국어', 'ko'],
        'no' => ['Norsk', 'no'],
        'pol' => ['Polski', 'pl'],
        'pt' => ['Português (Portugal)', 'pt'],
        'pt_BR' => ['Português (Brasil)', 'pt-BR'],
        'ro' => ['Română', 'ro'],
        'rus' => ['Русский', 'ru'],
        'si-LK' => ['සිංහල', 'si-LK'],
        'sjn' => ['Sindarin', 'sjn'],
        'spa' => ['Español', 'es'],
        'swe' => ['Svenska', 'sv'],
        'th_TH' => ['ไทย', 'th-TH'],
        'ukr' => ['Українська', 'uk'],
        'zh-s' => ['简体中文', 'zh-Hans'],
    ];

    public static function label($language)
    {
        return self::LANGUAGES[$language][0] ?? $language;
    }

    public static function htmlLang($language)
    {
        if (isset(self::LANGUAGES[$language])) {
            return self::LANGUAGES[$language][1];
        }
        if ($language === '') {
            return 'en';
        }
        if (strlen($language) === 3) {
            return (new L10n())->map($language) ?: 'en';
        }
        return str_replace('_', '-', $language);
    }

    public static function direction($language)
    {
        return preg_match('/^ar(?:-|$)/', self::htmlLang($language))
            ? 'rtl' : 'ltr';
    }
}
