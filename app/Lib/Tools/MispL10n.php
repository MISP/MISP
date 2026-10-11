<?php
App::uses('L10n', 'I18n');

/** Resolve the catalog directory names offered by MISP's language setting. */
class MispL10n extends L10n
{
    private static $catalogLanguages = array(
        'ara' => 'ar', 'cze' => 'cs', 'dan' => 'da', 'deu' => 'de',
        'fra' => 'fr', 'hun' => 'hu', 'ita' => 'it', 'jpn' => 'ja',
        'kor' => 'ko', 'no' => 'no', 'pol' => 'pl', 'pt' => 'pt',
        'pt_BR' => 'pt-br', 'ro' => 'ro', 'rus' => 'ru',
        'si-LK' => 'eng', 'spa' => 'es', 'swe' => 'sv',
        'th_TH' => 'th-th', 'ukr' => 'uk', 'zh-s' => 'zh-cn',
    );

    public function __construct()
    {
        parent::__construct();
        if (isset(self::$catalogLanguages[$this->default])) {
            $this->default = self::$catalogLanguages[$this->default];
        }
        $language = Configure::read('Config.language');
        if ($language !== null) {
            $this->get($language);
        }
    }

    public function get($language = null)
    {
        if (!isset(self::$catalogLanguages[$language])) {
            return parent::get($language);
        }
        parent::get(self::$catalogLanguages[$language]);
        $this->languagePath = array_values(array_unique(array_merge(
            array($language), $this->languagePath
        )));
        $this->lang = $language;
        $this->charset = 'utf-8';
        if ($language === 'si-LK') {
            $this->language = 'Sinhala';
            $this->locale = 'si-LK';
        }
        return $language;
    }
}
