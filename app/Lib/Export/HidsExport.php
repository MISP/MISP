<?php

class HidsExport
{
    public $rules = array();

    public function explain($type)
    {
        // unshift add in reverse order
        array_unshift($this->rules, '# ');
        if ($type === 'MD5') {
            array_unshift($this->rules, '# Keep in mind MD5 is not collision resistant');
        } elseif ($type === 'SHA1') {
            array_unshift($this->rules, '# Keep in mind SHA-1 still has a theoretical collision possibility');
        }
        array_unshift($this->rules, '# These HIDS export contains ' . $type . ' checksums.');
    }

    public function export($items, $type = 'MD5', $continue = false)
    {
        if (!empty($items)) {
            foreach ($items as $item) {
                switch ($item['Attribute']['type']) {
                    case 'md5':
                    case 'sha1':
                    case 'sha256':
                        if (!in_array($item['Attribute']['value1'], $this->rules)) {
                            $this->rules[] = $item['Attribute']['value1'];
                        }
                        break;
                    case 'filename|md5':
                    case 'malware-sample':
                    case 'filename|sha1':
                    case 'filename|sha256':
                        if (!in_array($item['Attribute']['value2'], $this->rules)) {
                            $this->rules[] = $item['Attribute']['value2'];
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        if (!$continue) {
            $this->explain($type);
        }
        return $this->rules;
    }
}
