<?php
/*
 * Renders a country flag (best-effort) + the human-readable language name.
 * The flag is derived from the RFC5646 region subtag (e.g. en-US → US) or, when
 * absent, a common language→country fallback. Falls back to the raw code / no flag.
 *
 * Config:
 *   $field['data_path'] — Hash path to the RFC5646 code (e.g. 'Note.language')
 *   $field['empty']     — label shown when no language is set (default '—')
 */
$code = (string)Hash::get($row, $field['data_path'] ?? '');
if ($code === '') {
    echo '<span class="text-muted">' . h($field['empty'] ?? '—') . '</span>';
    return;
}

if (!function_exists('overmindLanguageInfo')) {
    function overmindLanguageInfo($code)
    {
        static $langs = null;
        if ($langs === null) {
            App::uses('LanguageRFC5646Tool', 'Tools');
            $langs = LanguageRFC5646Tool::getLanguages();
        }
        // Representative country for language codes without a region subtag.
        static $fallback = [
            'en' => 'GB', 'fr' => 'FR', 'de' => 'DE', 'es' => 'ES', 'it' => 'IT',
            'pt' => 'PT', 'nl' => 'NL', 'ru' => 'RU', 'zh' => 'CN', 'ja' => 'JP',
            'ko' => 'KR', 'ar' => 'SA', 'af' => 'ZA', 'pl' => 'PL', 'tr' => 'TR',
            'sv' => 'SE', 'da' => 'DK', 'fi' => 'FI', 'nb' => 'NO', 'nn' => 'NO',
            'cs' => 'CZ', 'el' => 'GR', 'he' => 'IL', 'hi' => 'IN', 'th' => 'TH',
            'uk' => 'UA', 'ro' => 'RO', 'hu' => 'HU', 'bg' => 'BG', 'hr' => 'HR',
            'sk' => 'SK', 'sl' => 'SI', 'et' => 'EE', 'lv' => 'LV', 'lt' => 'LT',
            'vi' => 'VN', 'id' => 'ID', 'fa' => 'IR', 'ca' => 'ES', 'sr' => 'RS',
            'eu' => 'ES', 'gl' => 'ES', 'is' => 'IS', 'ga' => 'IE', 'mt' => 'MT',
        ];
        $name = $langs[$code] ?? $code;
        $cc = null;
        $parts = explode('-', $code);
        $last = end($parts);
        if (count($parts) > 1 && strlen($last) === 2 && ctype_alpha($last)) {
            $cc = strtoupper($last); // region subtag
        } elseif (isset($fallback[strtolower($parts[0])])) {
            $cc = $fallback[strtolower($parts[0])];
        }
        return ['name' => $name, 'cc' => $cc];
    }
}

$info = overmindLanguageInfo($code);

$flag = '';
if (!empty($info['cc'])) {
    $cp = [];
    foreach (str_split(strtolower($info['cc'])) as $ltr) {
        $cp[] = '1f1' . dechex(0xe6 + (ord($ltr) - 97));
    }
    $flag = '<img src="' . h($baseurl . '/img/flags/' . implode('-', $cp) . '.svg')
        . '" alt="" loading="lazy" style="height:1.05em; width:auto; border-radius:2px;">';
}
?>
<span class="d-inline-flex align-items-center gap-2">
    <?= $flag ?>
    <span><?= h($info['name']) ?></span>
    <?php if (str_ends_with($info['cc'] , $code)): ?>
        <span class="text-muted small font-monospace"><?= h($code) ?></span>
    <?php endif; ?>
</span>
