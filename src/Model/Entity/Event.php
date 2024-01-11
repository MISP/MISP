<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Event extends AppModel
{
    public const NO_PUSH_DISTRIBUTION = 'distribution',
        NO_PUSH_SERVER_RULES = 'push_rules';

    public $displayField = 'id';

    public $fieldDescriptions = [
        'threat_level_id' => ['desc' => 'Risk levels: *low* means mass-malware, *medium* means APT malware, *high* means sophisticated APT malware or 0-day attack', 'formdesc' => 'Risk levels: low: mass-malware medium: APT malware high: sophisticated APT malware or 0-day attack'],
        'classification' => ['desc' => 'Set the Traffic Light Protocol classification. <ol><li><em>TLP:AMBER</em>- Share only within the organization on a need-to-know basis</li><li><em>TLP:GREEN:NeedToKnow</em>- Share within your constituency on the need-to-know basis.</li><li><em>TLP:GREEN</em>- Share within your constituency.</li></ol>'],
        'submittedioc' => ['desc' => '', 'formdesc' => ''],
        'analysis' => ['desc' => 'Analysis Levels: *Initial* means the event has just been created, *Ongoing* means that the event is being populated, *Complete* means that the event\'s creation is complete', 'formdesc' => 'Analysis levels: Initial: event has been started Ongoing: event population is in progress Complete: event creation has finished'],
        'distribution' => ['desc' => 'Describes who will have access to the event.']
    ];

    public $analysisDescriptions = [
        0 => ['desc' => '*Initial* means the event has just been created', 'formdesc' => 'Event has just been created and is in an initial state'],
        1 => ['desc' => '*Ongoing* means that the event is being populated', 'formdesc' => 'The analysis is still ongoing'],
        2 => ['desc' => '*Complete* means that the event\'s creation is complete', 'formdesc' => 'The event creator considers the analysis complete']
    ];

    public $distributionDescriptions = [
        Distribution::ORGANISATION_ONLY => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "This setting will only allow members of your organisation on this server to see it.",
        ],
        Distribution::COMMUNITY_ONLY => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "Organisations that are part of this MISP community will be able to see the event.",
        ],
        Distribution::CONNECTED_COMMUNITIES => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "Organisations that are either part of this MISP community or part of a directly connected MISP community will be able to see the event.",
        ],
        Distribution::ALL => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next.",
        ],
        Distribution::SHARING_GROUP => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "This distribution of this event will be handled by the selected sharing group.",
        ],
    ];

    public const ANALYSIS_LEVELS = [
        0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed'
    ];

    public $shortDist = [0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group'];

    public $validFormats = [
        'attack' => ['html', 'AttackExport', 'html'],
        'attack-sightings' => ['json', 'AttackSightingsExport', 'json'],
        'cache' => ['txt', 'CacheExport', 'cache'],
        'context' => ['html', 'ContextExport', 'html'],
        'context-markdown' => ['txt', 'ContextMarkdownExport', 'md'],
        'count' => ['txt', 'CountExport', 'txt'],
        'csv' => ['csv', 'CsvExport', 'csv'],
        'hashes' => ['txt', 'HashesExport', 'txt'],
        'hosts' => ['txt', 'HostsExport', 'txt'],
        'json' => ['json', 'JsonExport', 'json'],
        'netfilter' => ['txt', 'NetfilterExport', 'sh'],
        'opendata' => ['txt', 'OpendataExport', 'txt'],
        'openioc' => ['xml', 'OpeniocExport', 'ioc'],
        'rpz' => ['txt', 'RPZExport', 'rpz'],
        'snort' => ['txt', 'NidsSnortExport', 'rules'],
        'stix' => ['xml', 'Stix1Export', 'xml'],
        'stix-json' => ['json', 'Stix1Export', 'json'],
        'stix2' => ['json', 'Stix2Export', 'json'],
        'suricata' => ['txt', 'NidsSuricataExport', 'rules'],
        'text' => ['text', 'TextExport', 'txt'],
        'xml' => ['xml', 'XmlExport', 'xml'],
        'yara' => ['txt', 'YaraExport', 'yara'],
        'yara-json' => ['json', 'YaraExport', 'json']
    ];

    public $possibleOptions = [
        'eventid',
        'idList',
        'tags',
        'from',
        'to',
        'last',
        'to_ids',
        'includeAllTags', // include also non exportable tags, default `false`
        'includeAttachments',
        'event_uuid',
        'distribution',
        'sharing_group_id',
        'disableSiteAdmin',
        'metadata',
        'enforceWarninglist', // return just attributes that contains no warnings
        'sgReferenceOnly', // do not fetch additional information about sharing groups
        'flatten',
        'blockedAttributeTags',
        'eventsExtendingUuid',
        'extended',
        'extensionList',
        'excludeGalaxy',
        // 'includeCustomGalaxyCluster', // not used
        'includeRelatedTags',
        'excludeLocalTags',
        'includeDecayScore',
        'includeScoresOnEvent',
        'includeSightingdb',
        'includeFeedCorrelations',
        'includeServerCorrelations',
        'includeWarninglistHits',
        'includeGranularCorrelations',
        'noEventReports', // do not include event report in event data
        'noShadowAttributes', // do not fetch proposals,
        'limit',
        'page',
        'order',
        'protected',
        'published',
        'orgc_id',
    ];
}
