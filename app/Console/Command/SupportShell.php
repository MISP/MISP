http://download.geonames.org/export/dump/countryInfo.txt

<?php
class SupportShell extends AppShell {

    public $uses = array();

    private $__fields = false;
    private $__countries = array();
    private $__whitelistedFields = array(
        'ISO',
        'ISO3',
        'Country',
        'Capital',
        'Area',
        'Population',
        'Continent',
        'tld',
        'CurrencyCode',
        'CurrencyName',
        'Languages'
    );

    public function getGeoNames()
    {
        $raw = file_get_contents('http://download.geonames.org/export/dump/countryInfo.txt');
        $raw = explode(PHP_EOL, $raw);
        $lastCommentLine = '';
        foreach ($raw as $line) {
            if (empty($line)) {
                continue;
            }
            if ($line[0] === '#') {
                $lastCommentLine = $line;
            } else {
                if (!$this->__fields) {
                    $this->__setHeaders($lastCommentLine);
                }
                $line = preg_split("/[\t]/", $line);
                $temp = array();
                foreach ($line as $pos => $value) {
                    $field = $this->__fields[$pos];
                    if (in_array($field, $this->__whitelistedFields)) {
                        $temp[$field] = $value;
                    }
                }
                $this->__countries[] = $temp;
            }
        }
        $clusters = array(
            'authors' => array('geonames.org'),
            'category' => 'country',
            'description' => 'Country meta information based on the database provided by geonames.org.',
            'name' => 'Country',
            'source' => 'MISP Project',
            'type' => 'country',
            'uuid' => '84668357-5a8c-4bdd-9f0f-6b50b2aee4c1',
            'version' => empty($this->args[0]) ? 1 : intval($this->args[0])
        );
        foreach ($this->__countries as $country) {
            $countryName = $country['Country'];
            unset($country['Country']);
            $clusters['values'][] = array(
                'description' => $countryName,
                'uuid' => '84668357-5a8c-4bdd-9f0f-6b50b2' . bin2hex($country['ISO3']),
                'value' => strtolower($countryName),
                'meta' => $country
            );
        }
        $galaxy = array(
            'description' => 'Country meta information based on the database provided by geonames.org.',
            'icon' => 'globe',
            'name' => 'Country',
            'namespace' => 'misp',
            'type' => 'country',
            'uuid' => '84668357-5a8c-4bdd-9f0f-6b50b2aee4c1',
            'version' => empty($this->args[0]) ? 1 : intval($this->args[0])
        );
        file_put_contents('cluster.json', json_encode($clusters, JSON_PRETTY_PRINT));
        file_put_contents('galaxy.json', json_encode($galaxy, JSON_PRETTY_PRINT));
        echo PHP_EOL . PHP_EOL . 'cluster.json and galaxy.json created.' . PHP_EOL . PHP_EOL;
    }

    private function __setHeaders($line)
    {
        $line = substr($line, 1);
        $this->__fields = preg_split("/[\t]/", $line);
        return true;
    }
}
