<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Event extends AppModel
{
    public const NO_PUSH_DISTRIBUTION = 'distribution',
        NO_PUSH_SERVER_RULES = 'push_rules';

    /**
     * @return array[]
     */
    public static function exportTypes()
    {
        return [
            'json' => [
                'extension' => '.json',
                'type' => 'JSON',
                'scope' => 'Event',
                'requiresPublished' => 0,
                'params' => ['includeAttachments' => 1, 'ignore' => 1, 'returnFormat' => 'json'],
                'description' => __('Click this to download all events and attributes that you have access to in MISP JSON format.'),
            ],
            'xml' => [
                'extension' => '.xml',
                'type' => 'XML',
                'scope' => 'Event',
                'params' => ['includeAttachments' => 1, 'ignore' => 1, 'returnFormat' => 'xml'],
                'requiresPublished' => 0,
                'description' => __('Click this to download all events and attributes that you have access to in MISP XML format.'),
            ],
            'csv_sig' => [
                'extension' => '.csv',
                'type' => 'CSV_Sig',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['published' => 1, 'to_ids' => 1, 'returnFormat' => 'csv'],
                'description' => __('Click this to download all attributes that are indicators and that you have access to (except file attachments) in CSV format.'),
            ],
            'csv_all' => [
                'extension' => '.csv',
                'type' => 'CSV_All',
                'scope' => 'Event',
                'requiresPublished' => 0,
                'params' => ['ignore' => 1, 'returnFormat' => 'csv'],
                'description' => __('Click this to download all attributes that you have access to (except file attachments) in CSV format.'),
            ],
            'suricata' => [
                'extension' => '.rules',
                'type' => 'Suricata',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'suricata'],
                'description' => __('Click this to download all network related attributes that you have access to under the Suricata rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ],
            'snort' => [
                'extension' => '.rules',
                'type' => 'Snort',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'snort'],
                'description' => __('Click this to download all network related attributes that you have access to under the Snort rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ],
            'bro' => [
                'extension' => '.intel',
                'type' => 'Bro',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'bro'],
                'description' => __('Click this to download all network related attributes that you have access to under the Bro rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ],
            'stix' => [
                'extension' => '.xml',
                'type' => 'STIX',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'stix', 'includeAttachments' => 1],
                'description' => __('Click this to download a STIX document containing the STIX version of all events and attributes that you have access to.')
            ],
            'stix2' => [
                'extension' => '.json',
                'type' => 'STIX2',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'stix2', 'includeAttachments' => 1],
                'description' => __('Click this to download a STIX2 document containing the STIX2 version of all events and attributes that you have access to.')
            ],
            'rpz' => [
                'extension' => '.txt',
                'type' => 'RPZ',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'rpz'],
                'description' => __('Click this to download an RPZ Zone file generated from all ip-src/ip-dst, hostname, domain attributes. This can be useful for DNS level firewalling. Only published events and attributes marked as IDS Signature are exported.')
            ],
            'text' => [
                'extension' => '.txt',
                'type' => 'TEXT',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'text', 'includeAttachments' => 1],
                'description' => __('Click on one of the buttons below to download all the attributes with the matching type. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.')
            ],
            'yara' => [
                'extension' => '.yara',
                'type' => 'Yara',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'yara'],
                'description' => __('Click this to download Yara rules generated from all relevant attributes.')
            ],
            'yara-json' => [
                'extension' => '.json',
                'type' => 'Yara',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => ['returnFormat' => 'yara-json'],
                'description' => __('Click this to download Yara rules generated from all relevant attributes. Rules are returned in a JSON format with information about origin (generated or parsed) and validity.')
            ],
        ];
    }
}
