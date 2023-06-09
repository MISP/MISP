<?php
class OrganisationMapWidget
{
    public $title = 'Organisation world map';
    public $render = 'WorldMap';
    public $description = 'The countries represented via organisations on the current instance.';
    public $width = 3;
    public $height = 4;
    public $params = [
        'filter' => 'A list of filters by organisation meta information (sector, type, local (- expects a boolean or a list of boolean values)) to include. (dictionary, prepending values with ! uses them as a negation)',
        'limit' => 'Limits the number of displayed tags. Default: 10'
    ];
    public $cacheLifetime = null;
    public $autoRefreshDelay = false;
    private $validFilterKeys = [
        'sector',
        'type',
        'local'
    ];
    public $placeholder =
'{
    "filter": {
        "type": "Member",
        "local": [0,1]
    }
}';
    private $Organisation = null;

    public $countryCodes = array(
        'Afghanistan' => 'AF',
        'Albania' => 'AL',
        'Algeria' => 'DZ',
        'Angola' => 'AO',
        'Argentina' => 'AR',
        'Armenia' => 'AM',
        'Australia' => 'AU',
        'Austria' => 'AT',
        'Azerbaijan' => 'AZ',
        'Bahamas' => 'BS',
        'Bangladesh' => 'BD',
        'Belarus' => 'BY',
        'Belgium' => 'BE',
        'Belize' => 'BZ',
        'Benin' => 'BJ',
        'Bhutan' => 'BT',
        'Bolivia' => 'BO',
        'Bosnia and Herz.' => 'BA',
        'Botswana' => 'BW',
        'Brazil' => 'BR',
        'Brunei' => 'BN',
        'Bulgaria' => 'BG',
        'Burkina Faso' => 'BF',
        'Burundi' => 'BI',
        'Cambodia' => 'KH',
        'Cameroon' => 'CM',
        'Canada' => 'CA',
        'Central African Rep.' => 'CF',
        'Chad' => 'TD',
        'Chile' => 'CL',
        'China' => 'CN',
        'Colombia' => 'CO',
        'Congo' => 'CG',
        'Costa Rica' => 'CR',
        'Croatia' => 'HR',
        'Cuba' => 'CU',
        'Cyprus' => 'CY',
        'Czech Rep.' => 'CZ',
        'Czech Republic' => 'CZ',
        'Côte d\'Ivoire' => 'CI',
        'Dem. Rep. Congo' => 'CD',
        'Dem. Rep. Korea' => 'KP',
        'Denmark' => 'DK',
        'Djibouti' => 'DJ',
        'Dominican Rep.' => 'DO',
        'Ecuador' => 'EC',
        'Egypt' => 'EG',
        'El Salvador' => 'SV',
        'Eq. Guinea' => 'GQ',
        'Eritrea' => 'ER',
        'Estonia' => 'EE',
        'Ethiopia' => 'ET',
        'Falkland Is.' => 'FK',
        'Fiji' => 'FJ',
        'Finland' => 'FI',
        'Fr. S. Antarctic Lands' => 'TF',
        'France' => 'FR',
        'Gabon' => 'GA',
        'Gambia' => 'GM',
        'Georgia' => 'GE',
        'Germany' => 'DE',
        'Ghana' => 'GH',
        'Greece' => 'GR',
        'Greenland' => 'GL',
        'Guatemala' => 'GT',
        'Guinea' => 'GN',
        'Guinea-Bissau' => 'GW',
        'Guyana' => 'GY',
        'Haiti' => 'HT',
        'Honduras' => 'HN',
        'Hungary' => 'HU',
        'Iceland' => 'IS',
        'India' => 'IN',
        'Indonesia' => 'ID',
        'Iran' => 'IR',
        'Iraq' => 'IQ',
        'Ireland' => 'IE',
        'Ireland {Republic}' => 'IE',
        'Israel' => 'IL',
        'Italy' => 'IT',
        'Jamaica' => 'JM',
        'Japan' => 'JP',
        'Jordan' => 'JO',
        'Kazakhstan' => 'KZ',
        'Kenya' => 'KE',
        'Korea' => 'KR',
        'Kuwait' => 'KW',
        'Kyrgyzstan' => 'KG',
        'Lao PDR' => 'LA',
        'Latvia' => 'LV',
        'Lebanon' => 'LB',
        'Lesotho' => 'LS',
        'Liberia' => 'LR',
        'Libya' => 'LY',
        'Lithuania' => 'LT',
        'Luxembourg' => 'LU',
        'Macedonia' => 'MK',
        'Madagascar' => 'MG',
        'Mainland China' => 'CN',
        'Malawi' => 'MW',
        'Malaysia' => 'MY',
        'Mali' => 'ML',
        'Malta' => 'MT',
        'Mauritania' => 'MR',
        'Mexico' => 'MX',
        'Moldova' => 'MD',
        'Mongolia' => 'MN',
        'Montenegro' => 'ME',
        'Morocco' => 'MA',
        'Mozamb' => 'MZ',
        'Myanmar' => 'MM',
        'Namibia' => 'NA',
        'Nepal' => 'NP',
        'Netherlands' => 'NL',
        'New Caledonia' => 'NC',
        'New Zealand' => 'NZ',
        'Nicaragua' => 'NI',
        'Niger' => 'NE',
        'Nigeria' => 'NG',
        'Norway' => 'NO',
        'Oman' => 'OM',
        'Pakistan' => 'PK',
        'Palestine' => 'PS',
        'Panama' => 'PA',
        'Papua New Guinea' => 'PG',
        'Paraguay' => 'PY',
        'Peru' => 'PE',
        'Philippines' => 'PH',
        'Poland' => 'PL',
        'Portugal' => 'PT',
        'Puerto Rico' => 'PR',
        'Qatar' => 'QA',
        'Romania' => 'RO',
        'Russia' => 'RU',
        'Rwanda' => 'RW',
        'S. Sudan' => 'SS',
        'Saudi Arabia' => 'SA',
        'Senegal' => 'SN',
        'Serbia' => 'RS',
        'Sierra Leone' => 'SL',
        'Slovakia' => 'SK',
        'Slovenia' => 'SI',
        'Solomon Is.' => 'SB',
        'Somalia' => 'SO',
        'South Africa' => 'ZA',
        'Spain' => 'ES',
        'Sri Lanka' => 'LK',
        'Sudan' => 'SD',
        'Suriname' => 'SR',
        'Swaziland' => 'SZ',
        'Sweden' => 'SE',
        'Switzerland' => 'CH',
        'Syria' => 'SY',
        'Taiwan' => 'TW',
        'Tajikistan' => 'TJ',
        'Tanzania' => 'TZ',
        'Thailand' => 'TH',
        'Timor-Leste' => 'TL',
        'Togo' => 'TG',
        'Trinidad and Tobago' => 'TT',
        'Tunisia' => 'TN',
        'Turkey' => 'TR',
        'Turkmenistan' => 'TM',
        'Uganda' => 'UG',
        'Ukraine' => 'UA',
        'United Arab Emirates' => 'AE',
        'United Kingdom' => 'GB',
        'United States' => 'US',
        'Uruguay' => 'UY',
        'Uzbekistan' => 'UZ',
        'Vanuatu' => 'VU',
        'Venezuela' => 'VE',
        'Vietnam' => 'VN',
        'W. Sahara' => 'EH',
        'Yemen' => 'YE',
        'Zambia' => 'ZM',
        'Zimbabwe' => 'ZW'
    );

    public function handler($user, $options = array())
    {
        $params = [
            'conditions' => [
                'Nationality !=' => ''
            ]
        ];
        if (!empty($options['filter']) && is_array($options['filter'])) {
            foreach ($this->validFilterKeys as $filterKey) {
                if (!empty($options['filter'][$filterKey])) {
                    if (!is_array($options['filter'][$filterKey])) {
                        $options['filter'][$filterKey] = [$options['filter'][$filterKey]];
                    }
                    $tempConditionBucket = [];
                    foreach ($options['filter'][$filterKey] as $value) {
                        if ($value[0] === '!') {
                            $tempConditionBucket['Organisation.' . $filterKey . ' NOT IN'][] = mb_substr($value, 1);
                        } else {
                            $tempConditionBucket['Organisation.' . $filterKey . ' IN'][] = $value;
                        }
                    }
                    if (!empty($tempConditionBucket)) {
                        $params['conditions']['AND'][] = $tempConditionBucket;
                    }
                }
            }
        }
        $this->Organisation = ClassRegistry::init('Organisation');
        $orgs = $this->Organisation->find('all', [
            'recursive' => -1,
            'fields' => ['Organisation.nationality', 'COUNT(Organisation.nationality) AS frequency'],
            'conditions' => $params['conditions'],
            'group' => ['Organisation.nationality']
        ]);
        $results = ['data' => [], 'scope' => 'Organisations'];
        foreach($orgs as $org) {
            $country = $org['Organisation']['nationality'];
            $count = $org['0']['frequency'];
            if (isset($this->countryCodes[$country])) {
                $countryCode = $this->countryCodes[$country];
                $results['data'][$countryCode] = $count;
            }
        }
        return $results;
    }
}
?>
