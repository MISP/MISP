<?php
class FinancialTool
{
    public $ibanLengths = array(
            'AD' => '24',
            'AE' => '23',
            'AL' => '28',
            'AO' => '25',
            'AT' => '20',
            'AZ' => '28',
            'BA' => '20',
            'BE' => '16',
            'BF' => '27',
            'BG' => '22',
            'BH' => '22',
            'BI' => '16',
            'BJ' => '28',
            'BR' => '29',
            'CG' => '27',
            'CH' => '21',
            'CI' => '28',
            'CM' => '27',
            'CR' => '21',
            'CV' => '25',
            'CY' => '28',
            'CZ' => '24',
            'DE' => '22',
            'DK' => '18',
            'DO' => '28',
            'DZ' => '24',
            'EE' => '20',
            'EG' => '27',
            'ES' => '24',
            'FI' => '18',
            'FO' => '18',
            'FR' => '27',
            'GA' => '27',
            'GB' => '22',
            'GE' => '22',
            'GI' => '23',
            'GL' => '18',
            'GR' => '27',
            'GT' => '28',
            'HR' => '21',
            'HU' => '28',
            'IE' => '22',
            'IL' => '23',
            'IR' => '26',
            'IS' => '26',
            'IT' => '27',
            'JO' => '30',
            'KW' => '30',
            'KZ' => '20',
            'LB' => '28',
            'LC' => '32',
            'LI' => '21',
            'LT' => '20',
            'LU' => '20',
            'LV' => '21',
            'MC' => '27',
            'MD' => '24',
            'ME' => '22',
            'MG' => '27',
            'MK' => '19',
            'ML' => '28',
            'MR' => '27',
            'MT' => '31',
            'MU' => '30',
            'MZ' => '25',
            'NL' => '18',
            'NO' => '15',
            'PK' => '24',
            'PL' => '28',
            'PS' => '29',
            'PT' => '25',
            'QA' => '29',
            'RO' => '24',
            'RS' => '22',
            'SA' => '24',
            'SE' => '24',
            'SI' => '19',
            'SK' => '24',
            'SM' => '27',
            'SN' => '28',
            'TN' => '24',
            'TR' => '26',
            'UA' => '29',
            'VG' => '24',
            'XK' => '20'
    );

    const BTC_BASE32_CONVERT_TABLE = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    ];

    /**
     * @param string $type
     * @param string $value
     * @return bool
     */
    public function validateRouter($type, $value)
    {
        $validationRoutes = array(
            'cc-number' => 'CC',
            'bin' => 'BIN',
            'bic' => 'BIC',
            'iban' => 'IBAN',
            'btc' => 'BTC',
            'xmr' => 'XMR'
        );
        if (isset($validationRoutes[$type])) {
            return $this->{'validate' . $validationRoutes[$type]}($value);
        }
        return true;
    }

    /**
        *
        * alternative to bcmod from: http://au2.php.net/manual/en/function.bcmod.php#38474
        *
        * my_bcmod - get modulus (substitute for bcmod)
        * string my_bcmod ( string left_operand, int modulus )
        * left_operand can be really big, but be careful with modulus :(
        * by Andrius Baranauskas and Laurynas Butkus :) Vilnius, Lithuania
    **/
    private function my_bcmod($x, $y)
    {
        // how many numbers to take at once? careful not to exceed (int)
        $take = 5;
        $mod = '';

        do {
            $a = (int)$mod.substr($x, 0, $take);
            $x = substr($x, $take);
            $mod = $a % $y;
        } while (strlen($x));

        return (int)$mod;
    }

    // validating using method described on wikipedia @ https://en.wikipedia.org/wiki/International_Bank_Account_Number#Algorithms
    public function validateIBAN($iban)
    {
        if (strlen($iban) < 15 || strlen($iban) > 32) {
            return false;
        }
        $temp = substr($iban, 4) . substr($iban, 0, 4);
        $temp2 = '';
        for ($i = 0; $i < strlen($temp); $i++) {
            if (is_numeric($temp[$i])) {
                $temp2 .= $temp[$i];
            } else {
                $temp2 .= ord(strtolower($temp[$i])) - 87;
            }
        }
        if (function_exists('bcmod')) {
            $temp = bcmod($temp2, 97);
        } else {
            $temp = $this->my_bcmod($temp2, 97);
        }
        return intval($temp)===1 ? true : false;
    }

    public function validateBIC($bic)
    {
        if (preg_match('/^([A-Z]{4})([A-Z]){2}([0-9A-Z]){2}([0-9A-Z]{3})?$/i', $bic)) {
            return true;
        }
        return false;
    }

    public function validateBIN($bin)
    {
        if (is_numeric($bin) && strlen($bin) == 6) {
            return true;
        }
        return false;
    }

    // based on the explanation at www.freeformatter.com/credit-card-number-generator-validator.html#validate
    public function validateCC($cc)
    {
        if (is_numeric($cc) && strlen($cc) > 12 && strlen($cc) < 20) {
            $numberArray = str_split($cc);
            $lastDigit = $numberArray[count($numberArray) - 1];
            unset($numberArray[count($numberArray) - 1]);
            $numberArray = array_reverse($numberArray);
            $sum = 0;
            foreach ($numberArray as $k => $number) {
                $number = intval($number);
                if ($k%2 == 0) {
                    $number *= 2;
                }
                if ($number > 9) {
                    $number -=9;
                }
                $sum += $number;
            }
            $sum += $lastDigit;
            if ($sum%10 == 0) {
                return true;
            }
            return false;
        }
        return false;
    }

    /**
     * Based on the php implementation of the BTC address validation example from
     * http://rosettacode.org/wiki/Bitcoin/address_validation
     * @param string $address
     * @return bool
     */
    public function validateBTC($address)
    {
        if ($this->validateBtcBech32($address)) {
            return true;
        }

        $strlen = strlen($address);
        if ($strlen < 26 || $strlen > 35) {
            return false;
        }
        $decoded = $this->__decodeBase58($address);
        if ($decoded === false) {
            return false;
        }

        $d1 = hash("sha256", substr($decoded, 0, 21), true);
        $d2 = hash("sha256", $d1, true);

        if (substr_compare($decoded, $d2, 21, 4)) {
            return false;
        }
        return true;
    }

    public function validateXMR($address)
    {
        if (!preg_match('/^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/', $address)) {
            return false;
        }
        return true;
    }

    private function validateBtcBech32($address)
    {
        if (!preg_match('/^(bc|tb)1([023456789acdefghjklmnpqrstuvwxyz]{11,71})$/i', $address, $match)) {
            return false;
        }

        $hrp = strtolower($match[1]);

        $expand1 = [];
        $expand2 = [];
        for ($i = 0; $i < strlen($hrp); $i++) {
            $o = ord($hrp[$i]);
            $expand1[] = $o >> 5;
            $expand2[] = $o & 31;
        }
        $data = array_merge($expand1, [0], $expand2);

        $chars = strtolower($match[2]);
        $chars = array_map('ord', str_split($chars));
        foreach ($chars as $char) {
            $data[] = ($char & 0x80) ? -1 : self::BTC_BASE32_CONVERT_TABLE[$char];
        }
        $generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        $chk = 1;
        foreach ($data as $char) {
            $top = $chk >> 25;
            $chk = ($chk & 0x1ffffff) << 5 ^ $char;
            for ($j = 0; $j < 5; $j++) {
                $value = (($top >> $j) & 1) ? $generator[$j] : 0;
                $chk ^= $value;
            }
        }

        return $chk === 1;
    }

    private function __decodeBase58($input)
    {
        $alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        $out = array_fill(0, 25, 0);
        for ($i = 0; $i < strlen($input); $i++) {
            $p = strpos($alphabet, $input[$i]);
            if ($p === false) {
                return false;
            }
            $c = $p;
            for ($j = 25; $j--;) {
                $c += (int)(58 * $out[$j]);
                $out[$j] = $c % 256;
                $c /= 256;
                $c = (int)$c;
            }
            if ($c != 0) {
                return false;
            }
        }

        $result = "";
        foreach ($out as $val) {
            $result .= chr($val);
        }

        return $result;
    }
}
