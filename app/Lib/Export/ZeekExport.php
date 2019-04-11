<?php

class ZeekExport
{
    public $rules = array();

    public $header = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.do_notice\tmeta.if_in";

    // mapping from misp attribute type to the zeek intel type
    // alternative mechanisms are:
    // - alternate: array containing a detection regex and a replacement zeek type
    // - composite: for composite misp attributes (domain|ip), use the provided zeek type if the second value is queried
    // - replace: run a replacement regex on the value before generating the zeek rule
    private $mapping = array(
        'ip-dst' => array('zeektype' => 'ADDR', 'alternate' => array('#/#', 'SUBNET')),
        'ip-src' => array('zeektype' => 'ADDR', 'alternate' => array('#/#', 'SUBNET')),
        'ip-dst|port' => array('zeektype' => 'ADDR', 'alternate' => array('#/#', 'SUBNET'), 'composite' => 'NONE'),
        'ip-src|port' => array('zeektype' => 'ADDR', 'alternate' => array('#/#', 'SUBNET'), 'composite' => 'NONE'),
        'email-src' => array('zeektype' => 'EMAIL'),
        'email-dst' => array('zeektype' => 'EMAIL'),
        'target-email' => array('zeektype' => 'EMAIL'),
        'email-attachment' => array('zeektype' => 'FILE_NAME'),
        'filename' => array('zeektype' => 'FILE_NAME'),
        'hostname' => array('zeektype' => 'DOMAIN'),
        'domain' => array('zeektype' => 'DOMAIN'),
        'domain|ip' => array('zeektype' => 'DOMAIN', 'composite' => 'ADDR'),
        'url' => array('zeektype' => 'URL', 'replace' => array('#^https?://#', '')),
        'user-agent' => array('zeektype' => 'SOFTWARE'),
        'md5' => array('zeektype' => 'FILE_HASH'),
        'malware-sample' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|md5' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'sha1' => array('zeektype' => 'FILE_HASH'),
        'filename|sha1' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'sha256' => array('zeektype' => 'FILE_HASH'),
        'filename|sha256' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'x509-fingerprint-sha1' => array('zeektype' => 'CERT_HASH'),
        'pdb' => array('zeektype' => 'FILE_NAME'),
        'authentihash' => array('zeektype' => 'FILE_HASH'),
        'ssdeep' => array('zeektype' => 'FILE_HASH'),
        'imphash' => array('zeektype' => 'FILE_HASH'),
        'pehash' => array('zeektype' => 'FILE_HASH'),
        'impfuzzy' => array('zeektype' => 'FILE_HASH'),
        'sha224' => array('zeektype' => 'FILE_HASH'),
        'sha384' => array('zeektype' => 'FILE_HASH'),
        'sha512' => array('zeektype' => 'FILE_HASH'),
        'sha512/224' => array('zeektype' => 'FILE_HASH'),
        'sha512/256' => array('zeektype' => 'FILE_HASH'),
        'tlsh' => array('zeektype' => 'FILE_HASH'),
        'cdhash' => array('zeektype' => 'FILE_HASH'),
        'filename|authentihash' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|ssdeep' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|imphash' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|pehash' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|impfuzzy' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|sha224' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|sha384' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|sha512' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|sha512/224' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|sha512/256' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH'),
        'filename|tlsh' => array('zeektype' => 'FILE_NAME', 'composite' => 'FILE_HASH')
    );

    // export group to misp type mapping
    // the mapped type is in an array format, first value being the misp type, second being the value field used
    public $mispTypes = array(
        'ip' => array(
            array('ip-src', 1),
            array('ip-dst', 1),
            array('ip-src|port', 1),
            array('ip-dst|port', 1),
            array('domain|ip', 2)
        ),
        'url' => array(
            array('url', 1)
        ),
        'domain' => array(
            array('hostname', 1),
            array('domain', 1),
            array('domain|ip', 1)
        ),
        'email' => array(
            array('email-src', 1),
            array('email-dst', 1),
            array('target-email', 1)
        ),
        'filename' => array(
            array('filename', 1),
            array('email-attachment', 1),
            array('attachment', 1),
            array('filename|md5', 1),
            array('filename|sha1', 1),
            array('filename|sha256', 1),
            array('malware-sample', 1),
            array('pdb', 1)
        ),
        'filehash' => array(
            array('md5', 1),
            array('sha1', 1),
            array('sha256', 1),
            array('authentihash', 1),
            array('ssdeep', 1),
            array('imphash', 1),
            array('pehash', 1),
            array('impfuzzy', 1),
            array('sha224', 1),
            array('sha384', 1),
            array('sha512', 1),
            array('sha512/224', 1),
            array('sha512/256', 1),
            array('tlsh', 1),
            array('filename|md5', 2),
            array('filename|sha1', 2),
            array('filename|sha256', 2),
            array('filename|authentihash', 2),
            array('filename|ssdeep', 2),
            array('filename|imphash', 2),
            array('filename|pehash', 2),
            array('filename|impfuzzy', 2),
            array('filename|sha224', 2),
            array('filename|sha384', 2),
            array('filename|sha512', 2),
            array('filename|sha512/224', 2),
            array('filename|sha512/256', 2),
            array('filename|tlsh', 2),
            array('malware-sample', 2)
        ),
        'certhash' => array(
            array('x509-fingerprint-sha1', 1)
        ),
        'software' => array(
            array('user-agent', 1)
        )
    );

    private $whitelist = null;

	public function handler($data, $options = array())
	{

	}

	public function footer()
	{
		return "\n";
	}

	public function separator()
	{
		return "\n";
	}

    public function export($items, $orgs, $valueField, $whitelist = array(), $instanceString)
    {
        $intel = array();
        //For zeek format organisation
        $orgsName = array();
        // generate the rules
        foreach ($items as $item) {
            if (!isset($orgs[$item['Event']['orgc_id']])) {
                continue;
            } else {
                $orgName = $instanceString . ' (' . $item['Event']['uuid'] . ')' . ' - ' . $orgs[$item['Event']['orgc_id']];
            }
            $ruleFormatReference = Configure::read('MISP.baseurl') . '/events/view/' . $item['Event']['id'];
            $ruleFormat = "%s\t%s\t" . $orgName . "\t%s. %s\t" . $ruleFormatReference . "\t%s\t%s";
            $rule = $this->__generateRule($item, $ruleFormat, $valueField, $whitelist);
            if (!empty($rule)) {
                $intel[] = $rule;
            }
        }
        return $intel;
    }

    private function __generateRule($item, $ruleFormat, $valueField, $whitelist = array())
    {
        if (isset($this->mapping[$item['Attribute']['type']])) {
            if (empty($whitelist) || !$this->checkWhitelist($item['Attribute']['value' . $valueField], $whitelist)) {
                $zeektype = $this->mapping[$item['Attribute']['type']]['zeektype'];
                if (isset($this->mapping[$item['Attribute']['type']]['alternate'])) {
                    if (preg_match($this->mapping[$item['Attribute']['type']]['alternate'][0], $item['Attribute']['value' . $valueField])) {
                        $zeektype = $this->mapping[$item['Attribute']['type']]['alternate'][1];
                    }
                }
                if ($valueField == 2 && isset($this->mapping[$item['Attribute']['type']]['composite'])) {
                    $zeektype = $this->mapping[$item['Attribute']['type']]['composite'];
                }
                $item['Attribute']['value' . $valueField] = $this->replaceIllegalChars($item['Attribute']['value' . $valueField]);  // substitute chars not allowed in rule
                if (isset($this->mapping[$item['Attribute']['type']]['replace'])) {
                    $item['Attribute']['value' . $valueField] = preg_replace(
                        $this->mapping[$item['Attribute']['type']]['replace'][0],
                        $this->mapping[$item['Attribute']['type']]['replace'][1],
                        $item['Attribute']['value' . $valueField]
                    );
                }
                return sprintf(
                    $ruleFormat,
                                $this->replaceIllegalChars($item['Attribute']['value' . $valueField]),    // value - for composite values only the relevant element is taken
                                'Intel::' . $zeektype,   // type
                                $this->replaceIllegalChars($item['Event']['info']),
                                $this->replaceIllegalChars($item['Attribute']['comment']),
                                'T',    // meta.do_notice
                                '-'  // meta.if_in
                                );
            }
        }
        return false;
    }

    /**
     * Replaces characters that are not allowed in a signature.
     * @param unknown_type $value
     */
    public static function replaceIllegalChars($value)
    {
        $replace_pairs = array(
                "\t" => ' ',
                "\x0B" => ' ',
                "\r" => ' ',
                "\r\n" => ' ',
                "\n" => ' '
        );
        return html_entity_decode(filter_var(strtr($value, $replace_pairs), FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_HIGH));
    }

    public function checkWhitelist($value, $whitelist)
    {
        foreach ($whitelist as $wlitem) {
            if (preg_match($wlitem, $value)) {
                return true;
            }
        }
        return false;
    }

    public function getMispTypes($type)
    {
        $mispTypes = array();
        if (isset($this->mispTypes[$type])) {
            $mispTypes = $this->mispTypes[$type];
        }
        return $mispTypes;
    }
}
