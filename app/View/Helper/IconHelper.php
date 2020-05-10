<?php
App::uses('AppHelper', 'View/Helper');

class IconHelper extends AppHelper {
    /**
     * @param string $countryCode  ISO 3166-1 alpha-2 two-letter country code
     * @return string
     */
    public function countryFlag($countryCode)
    {
        if (strlen($countryCode) !== 2) {
            return '';
        }

        $output = '';
        foreach (str_split(strtolower($countryCode)) as $letter) {
            $letterCode = ord($letter);
            if ($letterCode < 97 || $letterCode > 122) {
                return ''; // invalid letter
            }

            // UTF-8 representation
            $output .= "\xF0\x9F\x87" . chr(0xa6 + ($letterCode - 97));
        }

        return $output;
    }
}
