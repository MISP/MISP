<?php

class CsseCovidMapWidget
{
    public $title = 'CSSE Covid-19 map';
    public $render = 'WorldMap';
    public $width = 3;
    public $height = 4;
    public $params = array(
        'event_info' => 'World map based on the countries with infections.',
        'type' => 'Type of data used for the widget (confirmed, death, recovered).',
        'logarithmic' => 'Use a log10 scale for the graph (set via 0/1).'
    );
    public $description = 'Widget mapping the countries showing confirmed cases of COVID-19.';
    public $placeholder =
'{
    "event_info": "%CSSE COVID-19 daily report%",
    "type": "confirmed",
    "logarithmic": 1
}';

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
    public $countryCodesReversed = array();

    public function handler($user, $options = array())
    {
        $this->countryCodesReversed = array_flip($this->countryCodes);
        $this->Event = ClassRegistry::init('Event');
        $event_info_condition = empty($options['event_info']) ? '%CSSE COVID-19 daily report%' : $options['event_info'];
        $params = array(
            'eventinfo' => $event_info_condition,
            'order' => 'date desc',
            'limit' => 1,
            'page' => 1
        );
        $eventIds = $this->Event->filterEventIds($user, $params);
        $params['eventid'] = $eventIds;
        $data = array();
        if (empty($options['type'])) {
            $options['type'] = 'confirmed';
        }
        if (!empty($eventIds)) {
            $events = $this->Event->fetchEvent($user, $params);
            $data = $this->__handleEvents($events, $options);
            arsort($data);
        }
        $data = array('data' => $data);
        if (!empty($options['type']) && $options['type'] === 'mortality') {
            $data['output_decorator'] = 'percentage';
        }
        if (!empty($options['logarithmic'])) {
            $data['logarithmic'] = array();
            foreach ($data['data'] as $k => $v) {
                if ($v == 0) {
                    $value = 0;
                } else if ($v <= 1) {
                    $value = 0.2;
                } else {
                    $value = log10($v);
                }
                $data['logarithmic'][$k] = $value;
            }
        }
        $data['scope'] = Inflector::humanize($options['type']);
        $data['colour_scale'] = json_encode(array('#F08080', '#8B0000'), true);
        return $data;
    }

    private function __handleEvents($events, $options)
    {
        $data = array();
        if (!empty($events)) {
            foreach ($events as $event) {
                if (!empty($event['Object'])) {
                    $data = $this->__handleObjects($data, $event['Object'], $options);
                }
            }
        }
        return $data;
    }

    private function __handleObjects($data, $objects, $options)
    {
        foreach ($objects as $object) {
            if ($object['name'] === 'covid19-csse-daily-report') {
                $temp = $this->__interpretObject($object);
                $data = $this->__rearrangeResults($data, $temp, $options);
            }
        }
        if ($options['type'] === 'mortality') {
            foreach ($data as $k => $v) {
                $data[$k] = round(100 * (empty($v['death']) ? 0 : $v['death']) / $v['confirmed'], 2);
            }
        }
        return $data;
    }

    private function __rearrangeResults($data, $temp, $options)
    {
        $country = $temp['country-region'];
        $type = $options['type'];
        if (!empty($temp[$type])) {
            $data[$country] = (empty($data[$country]) ? $temp[$type] : ($data[$country] + $temp[$type]));
        }
        return $data;
    }

    private function __interpretObject($object)
    {
        $temp = array();
        $validFields = array('country-region', 'confirmed', 'death', 'recovered');
        foreach ($object['Attribute'] as $attribute) {
            if (in_array($attribute['object_relation'], $validFields)) {
                if ($attribute['object_relation'] === 'country-region') {
                    if (!empty($this->countryCodes[$attribute['value']])) {
                        $temp[$attribute['object_relation']] = $this->countryCodes[$attribute['value']];
                    } elseif (isset($this->countryCodesReversed[$attribute['value']])) {
                        $temp[$attribute['object_relation']] = $attribute['value'];
                    } else {
                        $temp[$attribute['object_relation']] = 'XX';
                    }
                } else {
                    $attribute['value'] = intval($attribute['value']);
                    $temp[$attribute['object_relation']] = $attribute['value'];
                }
            }
        }
        return $temp;
    }
}
