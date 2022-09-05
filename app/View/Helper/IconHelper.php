<?php
App::uses('AppHelper', 'View/Helper');

class IconHelper extends AppHelper
{
    /**
     * @param string $countryCode ISO 3166-1 alpha-2 two-letter country code
     * @param string $countryName Full country name for title
     * @return string
     */
    public function countryFlag($countryCode, $countryName = null)
    {
        if (strlen($countryCode) !== 2) {
            return '';
        }

        $output = [];
        foreach (str_split(strtolower($countryCode)) as $letter) {
            $letterCode = ord($letter);
            if ($letterCode < 97 || $letterCode > 122) {
                return ''; // invalid letter
            }
            $output[] = "1f1" . dechex(0xe6 + ($letterCode - 97));
        }

        $baseurl = $this->_View->viewVars['baseurl'];
        $title = __('Flag of %s',  strtoupper($countryName ? h($countryName) : $countryCode));
        return '<img src="' . $baseurl . '/img/flags/' . implode('-', $output) . '.svg" title="' . $title .'" alt="' . $title . '" aria-label="' . $title . '"  style="height: 18px" />';
    }
}
