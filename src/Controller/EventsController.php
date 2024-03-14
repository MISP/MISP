<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Lib\Export\BroExport;
use App\Lib\Export\CsvExport;
use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\ClusterRelationsGraphTool;
use App\Lib\Tools\ColourGradientTool;
use App\Lib\Tools\ComplexTypeTool;
use App\Lib\Tools\CorrelationGraphTool;
use App\Lib\Tools\DistributionGraphTool;
use App\Lib\Tools\EventGraphTool;
use App\Lib\Tools\EventTimelineTool;
use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\IOCExportTool;
use App\Lib\Tools\JSONConverterTool;
use App\Lib\Tools\JsonTool;
use App\Lib\Tools\RequestRearrangeTool;
use App\Lib\Tools\TmpFileTool;
use App\Lib\Tools\XMLConverterTool;
use App\Model\Entity\Attribute;
use App\Model\Entity\Module;
use Cake\Chronos\Chronos;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\ForbiddenException;
use Cake\Http\Exception\InternalErrorException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\NotImplementedException;
use Cake\Http\Exception\UnauthorizedException;
use Cake\Http\Response;
use Cake\Utility\Hash;
use Cake\Utility\Inflector;
use Cake\Utility\Text;
use Cake\Validation\Validation;
use Exception;
use InvalidArgumentException;
use SplFileInfo;
use SplFileObject;

class EventsController extends AppController
{
    public $data1 = '{"Event":{"id":"46","orgc_id":"1","org_id":"1","date":"2023-02-07","threat_level_id":"2","info":"Spear-phishing attempt targeting telco sector","published":false,"uuid":"c516b000-740b-4e3b-8bb5-2f4562b1167e","attribute_count":"31","analysis":"1","timestamp":"1675774263","distribution":"1","proposal_email_lock":false,"locked":false,"publish_timestamp":"0","sharing_group_id":"0","disable_correlation":false,"extends_uuid":"","protected":null,"event_creator_email":"admin@admin.test","Feed": [{"id": "33","name": "VXvault - URL List","url": "http://vxvault.net/URL_List.php","provider": "VXvault","source_format": "freetext"}],"Org":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6","local":true},"Orgc":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6","local":true},"Attribute":[{"id":"1487","type":"vulnerability","category":"External analysis","to_ids":false,"uuid":"efa3a323-3696-4744-81d3-5cfa17fadd71","event_id":"46","distribution":"5","timestamp":"1675772084","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"0","object_relation":null,"first_seen":null,"last_seen":null,"value":"CVE-2015-5465","Galaxy":[],"ShadowAttribute":[]},{"id":"1499","type":"ip-dst","category":"Payload delivery","to_ids":false,"uuid":"1d64f99b-40c4-4785-8ce8-eb03b1e62655","event_id":"46","distribution":"5","timestamp":"1675774263","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"0","object_relation":null,"first_seen":null,"last_seen":null,"value":"8.8.8.8","Galaxy":[],"ShadowAttribute":[]}],"ShadowAttribute":[],"RelatedEvent":[{"Event":{"id":"42","date":"2022-12-15","threat_level_id":"1","info":"Test","published":false,"uuid":"389624c7-e5e5-41c2-88bf-79e7f122369e","analysis":"0","timestamp":"1671095982","distribution":"1","org_id":"1","orgc_id":"1","Org":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"},"Orgc":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"}}},{"Event":{"id":"39","date":"2022-11-01","threat_level_id":"1","info":"Test event ip|port -> ip-port","published":false,"uuid":"9bafd762-fe83-4868-899f-c649a5086bda","analysis":"0","timestamp":"1667755190","distribution":"1","org_id":"1","orgc_id":"1","Org":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"},"Orgc":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"}}},{"Event":{"id":"26","date":"2022-09-02","threat_level_id":"1","info":"Small event","published":true,"uuid":"627c2455-65fd-448e-ab33-b01e9297b5e3","analysis":"0","timestamp":"1663922158","distribution":"2","org_id":"1","orgc_id":"1","Org":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"},"Orgc":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"}}},{"Event":{"id":"20","date":"2022-05-17","threat_level_id":"2","info":"Analysis of a Flubot malware captured by a honeypot","published":false,"uuid":"2683b27f-c509-4458-84f9-8980f60548df","analysis":"1","timestamp":"1674145910","distribution":"0","org_id":"1","orgc_id":"1","Org":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"},"Orgc":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"}}},{"Event":{"id":"2","date":"2021-12-09","threat_level_id":"1","info":"Test PUSH filtering type","published":false,"uuid":"7907c4a9-a15c-4c60-a1b4-1d214cf8cf41","analysis":"0","timestamp":"1639378441","distribution":"2","org_id":"1","orgc_id":"1","Org":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"},"Orgc":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"}}},{"Event":{"id":"1","date":"2021-11-05","threat_level_id":"1","info":"Test","published":false,"uuid":"a904fc48-cc81-47c3-81b1-b15249dce141","analysis":"0","timestamp":"1662025524","distribution":"1","org_id":"1","orgc_id":"1","Org":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"},"Orgc":{"id":"1","name":"ORGNAME","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6"}}}],"Galaxy":[{"id":"6","uuid":"709ed29c-aa00-11e9-82cd-67ac1a6ee3bc","name":"Target Information","type":"target-information","description":"Description of targets of threat actors.","version":"1","icon":"bullseye","namespace":"misp","enabled":true,"local_only":false,"GalaxyCluster":[{"id":"1956","uuid":"f9a1d7f4-980a-11e9-a8b6-23162ddc4255","collection_uuid":"cc6feae0-968a-11e9-a29a-bf581ae8eee3","type":"target-information","value":"Luxembourg","tag_name":"misp-galaxy:target-information=\"Luxembourg\"","description":"","galaxy_id":"6","source":"Various","authors":["Unknown"],"version":"4","distribution":"3","sharing_group_id":null,"org_id":"0","orgc_id":"0","default":true,"locked":false,"extends_uuid":"","extends_version":"0","published":false,"deleted":false,"GalaxyClusterRelation":[],"Org":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"Orgc":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"meta":{"calling-code":["+352"],"capital":["Luxembourg"],"currency":["€","EUR","EURO"],"iso-code":["LU","LUX"],"member-of":["NATO"],"official-languages":["French","Luxembourgish","German"],"synomyms":["Grand Duchy of Luxembourg","Grand-Duché de Luxembourg","Lëtzebuerg","Groussherzogtum Lëtzebuerg","Luxemburg","Großherzogtum Luxemburg"],"territory-type":["Country"],"top-level-domain":["lu"]},"tag_id":251,"event_tag_id":"320","local":false,"relationship_type":false}]},{"id":"4","uuid":"84668357-5a8c-4bdd-9f0f-6b50b2aee4c1","name":"Country","type":"country","description":"Country meta information based on the database provided by geonames.org.","version":"1","icon":"globe","namespace":"misp","enabled":true,"local_only":false,"GalaxyCluster":[{"id":"1818","uuid":"84668357-5a8c-4bdd-9f0f-6b50b24c5558","collection_uuid":"84668357-5a8c-4bdd-9f0f-6b50b2aee4c1","type":"country","value":"luxembourg","tag_name":"misp-galaxy:country=\"luxembourg\"","description":"Luxembourg","galaxy_id":"4","source":"MISP Project","authors":["geonames.org"],"version":"1","distribution":"3","sharing_group_id":null,"org_id":"0","orgc_id":"0","default":true,"locked":false,"extends_uuid":"","extends_version":"0","published":false,"deleted":false,"GalaxyClusterRelation":[],"Org":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"Orgc":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"meta":{"Capital":["Luxembourg"],"Continent":["EU"],"CurrencyCode":["EUR"],"CurrencyName":["Euro"],"ISO":["LU"],"ISO3":["LUX"],"Languages":["lb,de-LU,fr-LU"],"Population":["497538"],"tld":[".lu"]},"tag_id":253,"event_tag_id":"321","local":false,"relationship_type":"targets"}]},{"id":"48","uuid":"c4e851fa-775f-11e7-8163-b774922098cd","name":"Attack Pattern","type":"mitre-attack-pattern","description":"ATT&CK Tactic","version":"9","icon":"map","namespace":"mitre-attack","enabled":true,"local_only":false,"kill_chain_order":{"mitre-attack":["reconnaissance","resource-development","initial-access","execution","persistence","privilege-escalation","defense-evasion","credential-access","discovery","lateral-movement","collection","command-and-control","exfiltration","impact"],"mitre-mobile-attack":["initial-access","execution","persistence","privilege-escalation","defense-evasion","credential-access","discovery","lateral-movement","collection","command-and-control","exfiltration","impact","network-effects","remote-service-effects"],"mitre-pre-attack":["priority-definition-planning","priority-definition-direction","target-selection","technical-information-gathering","people-information-gathering","organizational-information-gathering","technical-weakness-identification","people-weakness-identification","organizational-weakness-identification","adversary-opsec","establish-&-maintain-infrastructure","persona-development","build-capabilities","test-capabilities","stage-capabilities"]},"GalaxyCluster":[{"id":"8860","uuid":"e24a9f99-cb76-42a3-a50b-464668773e97","collection_uuid":"dcb864dc-775f-11e7-9fbb-1f41b4996683","type":"mitre-attack-pattern","value":"Spear phishing messages with malicious attachments - T1367","tag_name":"misp-galaxy:mitre-attack-pattern=\"Spear phishing messages with malicious attachments - T1367\"","description":"**This technique has been deprecated. Please use [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001).**\n\nEmails with malicious attachments are designed to get a user to open/execute the attachment in order to deliver malware payloads. (Citation: APT1)","galaxy_id":"48","source":"https://github.com/mitre/cti","authors":["MITRE"],"version":"16","distribution":"3","sharing_group_id":null,"org_id":"0","orgc_id":"0","default":true,"locked":false,"extends_uuid":"","extends_version":"0","published":false,"deleted":false,"GalaxyClusterRelation":[],"Org":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"Orgc":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"meta":{"external_id":["T1367"],"kill_chain":["mitre-pre-attack:launch"],"refs":["https://attack.mitre.org/techniques/T1367"]},"tag_id":145,"event_tag_id":"322","local":false,"relationship_type":false},{"id":"9475","uuid":"2e34237d-8574-43f6-aace-ae2915de8597","collection_uuid":"dcb864dc-775f-11e7-9fbb-1f41b4996683","type":"mitre-attack-pattern","value":"Spearphishing Attachment - T1566.001","tag_name":"misp-galaxy:mitre-attack-pattern=\"Spearphishing Attachment - T1566.001\"","description":"Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.\n\nThere are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary\'s payload exploits a vulnerability or directly executes on the user\'s system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one. ","galaxy_id":"48","source":"https://github.com/mitre/cti","authors":["MITRE"],"version":"16","distribution":"3","sharing_group_id":null,"org_id":"0","orgc_id":"0","default":true,"locked":false,"extends_uuid":"","extends_version":"0","published":false,"deleted":false,"GalaxyClusterRelation":[{"id":"14743","galaxy_cluster_id":"9475","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"subtechnique-of","galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","distribution":"3","sharing_group_id":null,"default":true}],"Org":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"Orgc":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"TargetingClusterRelation":[{"id":"1735","galaxy_cluster_id":"2906","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"e7a5229f-05eb-440e-b982-9a6d2b2b87c8","distribution":"3","sharing_group_id":null,"default":true},{"id":"2849","galaxy_cluster_id":"3001","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"01dbc71d-0ee8-420d-abb4-3dfb6a4bf725","distribution":"3","sharing_group_id":null,"default":true},{"id":"4686","galaxy_cluster_id":"3164","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"92ec0cbd-2c30-44a2-b270-73f4ec949841","distribution":"3","sharing_group_id":null,"default":true},{"id":"4984","galaxy_cluster_id":"3192","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"2a70812b-f1ef-44db-8578-a496a227aef2","distribution":"3","sharing_group_id":null,"default":true},{"id":"5590","galaxy_cluster_id":"3245","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"cc5497f7-a9e8-436f-94da-b2b4a9b9ad3c","distribution":"3","sharing_group_id":null,"default":true},{"id":"5812","galaxy_cluster_id":"3262","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"64122557-5940-4271-9123-25bfc0c693db","distribution":"3","sharing_group_id":null,"default":true},{"id":"5881","galaxy_cluster_id":"3266","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"00806466-754d-44ea-ad6f-0caf59cb8556","distribution":"3","sharing_group_id":null,"default":true},{"id":"6036","galaxy_cluster_id":"3281","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"44c75271-0e4d-496f-ae0a-a6d883a42a65","distribution":"3","sharing_group_id":null,"default":true},{"id":"6305","galaxy_cluster_id":"3296","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"222ba512-32d9-49ac-aefd-50ce981ce2ce","distribution":"3","sharing_group_id":null,"default":true},{"id":"6362","galaxy_cluster_id":"3301","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"288fa242-e894-4c7e-ac86-856deedf5cea","distribution":"3","sharing_group_id":null,"default":true},{"id":"6452","galaxy_cluster_id":"3307","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"5147ef15-1cae-4707-8ea1-bee8d98b7f1d","distribution":"3","sharing_group_id":null,"default":true},{"id":"6722","galaxy_cluster_id":"3323","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"32066e94-3112-48ca-b9eb-ba2b59d2f023","distribution":"3","sharing_group_id":null,"default":true},{"id":"7131","galaxy_cluster_id":"3347","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"81c57a96-fc8c-4f91-af8e-63e24c2927c2","distribution":"3","sharing_group_id":null,"default":true},{"id":"7280","galaxy_cluster_id":"3356","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"ba09b86c-1c40-4ff1-bda0-0d8c4ca35997","distribution":"3","sharing_group_id":null,"default":true},{"id":"7384","galaxy_cluster_id":"3362","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"ade37ada-14af-4b44-b36c-210eec255d53","distribution":"3","sharing_group_id":null,"default":true},{"id":"7459","galaxy_cluster_id":"3366","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"ac61f1f9-7bb1-465e-9b8a-c2ce8e88baf5","distribution":"3","sharing_group_id":null,"default":true},{"id":"7549","galaxy_cluster_id":"3373","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"ef2247bf-8062-404b-894f-d65d00564817","distribution":"3","sharing_group_id":null,"default":true},{"id":"7589","galaxy_cluster_id":"3377","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"8c1d01ff-fdc0-4586-99bd-c248e0761af5","distribution":"3","sharing_group_id":null,"default":true},{"id":"9371","galaxy_cluster_id":"7981","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"fa19de15-6169-428d-9cd6-3ca3d56075b7","distribution":"3","sharing_group_id":null,"default":true},{"id":"9383","galaxy_cluster_id":"7982","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"6688d679-ccdb-4f12-abf6-c7545dd767a4","distribution":"3","sharing_group_id":null,"default":true},{"id":"9486","galaxy_cluster_id":"7985","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"76d59913-1d24-4992-a8ac-05a3eb093f71","distribution":"3","sharing_group_id":null,"default":true},{"id":"9543","galaxy_cluster_id":"7987","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"93f52415-0fe4-4d3d-896c-fc9b8e88ab90","distribution":"3","sharing_group_id":null,"default":true},{"id":"9598","galaxy_cluster_id":"7989","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"dc6fe6ee-04c2-49be-ba3d-f38d2463c02a","distribution":"3","sharing_group_id":null,"default":true},{"id":"9646","galaxy_cluster_id":"7991","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"dd2d9ca6-505b-4860-a604-233685b802c7","distribution":"3","sharing_group_id":null,"default":true},{"id":"9761","galaxy_cluster_id":"7995","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"56319646-eb6e-41fc-ae53-aadfa7adb924","distribution":"3","sharing_group_id":null,"default":true},{"id":"9811","galaxy_cluster_id":"7996","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"c93fccb1-e8e8-42cf-ae33-2ad1d183913a","distribution":"3","sharing_group_id":null,"default":true},{"id":"9927","galaxy_cluster_id":"8000","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"381fcf73-60f6-4ab2-9991-6af3cbc35192","distribution":"3","sharing_group_id":null,"default":true},{"id":"10028","galaxy_cluster_id":"8003","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"2e290bfe-93b5-48ce-97d6-edcd6d32b7cf","distribution":"3","sharing_group_id":null,"default":true},{"id":"10100","galaxy_cluster_id":"8006","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"1f21da59-6a13-455b-afd0-d58d0a5a7d27","distribution":"3","sharing_group_id":null,"default":true},{"id":"10312","galaxy_cluster_id":"8014","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"420ac20b-f2b9-42b8-aa1a-6d4b72895ca4","distribution":"3","sharing_group_id":null,"default":true},{"id":"10318","galaxy_cluster_id":"8015","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"c4d50cdf-87ce-407d-86d8-862883485842","distribution":"3","sharing_group_id":null,"default":true},{"id":"10365","galaxy_cluster_id":"8018","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"c47f937f-1022-4f42-8525-e7a4779a14cb","distribution":"3","sharing_group_id":null,"default":true},{"id":"10378","galaxy_cluster_id":"8019","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"f047ee18-7985-4946-8bfb-4ed754d3a0dd","distribution":"3","sharing_group_id":null,"default":true},{"id":"10416","galaxy_cluster_id":"8020","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"6a2e693f-24e5-451a-9f88-b36a108e5662","distribution":"3","sharing_group_id":null,"default":true},{"id":"10436","galaxy_cluster_id":"8022","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"ead23196-d7b6-4ce6-a124-4ab4b67d81bd","distribution":"3","sharing_group_id":null,"default":true},{"id":"10582","galaxy_cluster_id":"8024","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"247cb30b-955f-42eb-97a5-a89fef69341e","distribution":"3","sharing_group_id":null,"default":true},{"id":"10640","galaxy_cluster_id":"8025","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"7eda3dd8-b09b-4705-8090-c2ad9fb8c14d","distribution":"3","sharing_group_id":null,"default":true},{"id":"10694","galaxy_cluster_id":"8026","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"bef4c620-0787-42a8-a96d-b7eb6e85917c","distribution":"3","sharing_group_id":null,"default":true},{"id":"10864","galaxy_cluster_id":"8031","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"17862c7d-9e60-48a0-b48e-da4dc4c3f6b0","distribution":"3","sharing_group_id":null,"default":true},{"id":"10906","galaxy_cluster_id":"8034","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"6b1b551c-d770-4f95-8cfc-3cd253c4c04e","distribution":"3","sharing_group_id":null,"default":true},{"id":"10984","galaxy_cluster_id":"8039","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"899ce53f-13a0-479b-a0e4-67d46e241542","distribution":"3","sharing_group_id":null,"default":true},{"id":"11093","galaxy_cluster_id":"8040","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"9e729a7e-0dd6-4097-95bf-db8d64911383","distribution":"3","sharing_group_id":null,"default":true},{"id":"11133","galaxy_cluster_id":"8042","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"df71bb3b-813c-45eb-a8bc-f2a419837411","distribution":"3","sharing_group_id":null,"default":true},{"id":"11164","galaxy_cluster_id":"8043","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"16ade1aa-0ea1-4bb7-88cc-9079df2ae756","distribution":"3","sharing_group_id":null,"default":true},{"id":"11180","galaxy_cluster_id":"8044","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"fe8796a4-2a02-41a0-9d27-7aa1e995feb6","distribution":"3","sharing_group_id":null,"default":true},{"id":"11189","galaxy_cluster_id":"8045","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"88489675-d216-4884-a98f-49a89fcc1643","distribution":"3","sharing_group_id":null,"default":true},{"id":"11204","galaxy_cluster_id":"8046","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"18854f55-ac7c-4634-bd9a-352dd07613b7","distribution":"3","sharing_group_id":null,"default":true},{"id":"11279","galaxy_cluster_id":"8047","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"5e78ae92-3ffd-4b16-bf62-e798529d73f1","distribution":"3","sharing_group_id":null,"default":true},{"id":"11301","galaxy_cluster_id":"8051","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"fd19bd82-1b14-49a1-a176-6cdc46b8a826","distribution":"3","sharing_group_id":null,"default":true},{"id":"11407","galaxy_cluster_id":"8056","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"2a158b0a-7ef8-43cb-9985-bf34d1e12050","distribution":"3","sharing_group_id":null,"default":true},{"id":"11420","galaxy_cluster_id":"8057","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"d13c8a7f-740b-4efa-a232-de7d6bb05321","distribution":"3","sharing_group_id":null,"default":true},{"id":"11512","galaxy_cluster_id":"8060","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"62a64fd3-aaf7-4d09-a375-d6f8bb118481","distribution":"3","sharing_group_id":null,"default":true},{"id":"11603","galaxy_cluster_id":"8064","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"fbd29c89-18ba-4c2d-b792-51c0adee049f","distribution":"3","sharing_group_id":null,"default":true},{"id":"11660","galaxy_cluster_id":"8069","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"4a2ce82e-1a74-468a-a6fb-bbead541383c","distribution":"3","sharing_group_id":null,"default":true},{"id":"11717","galaxy_cluster_id":"8070","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"2a7914cf-dff3-428d-ab0f-1014d1c28aeb","distribution":"3","sharing_group_id":null,"default":true},{"id":"11734","galaxy_cluster_id":"8073","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"44e43fad-ffcb-4210-abcf-eaaed9735f80","distribution":"3","sharing_group_id":null,"default":true},{"id":"11862","galaxy_cluster_id":"8077","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"d0b3393b-3bec-4ba3-bda9-199d30db47b6","distribution":"3","sharing_group_id":null,"default":true},{"id":"11894","galaxy_cluster_id":"8078","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"222fbd21-fc4f-4b7e-9f85-0e6e3a76c33f","distribution":"3","sharing_group_id":null,"default":true},{"id":"11956","galaxy_cluster_id":"8080","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"3753cc21-2dae-4dfb-8481-d004e74502cc","distribution":"3","sharing_group_id":null,"default":true},{"id":"11979","galaxy_cluster_id":"8081","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"2fd2be6a-d3a2-4a65-b499-05ea2693abee","distribution":"3","sharing_group_id":null,"default":true},{"id":"11988","galaxy_cluster_id":"8082","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"c416b28c-103b-4df1-909e-78089a7e0e5f","distribution":"3","sharing_group_id":null,"default":true},{"id":"11993","galaxy_cluster_id":"8083","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"0ec2f388-bf0f-4b5c-97b1-fc736d26c25f","distribution":"3","sharing_group_id":null,"default":true},{"id":"12074","galaxy_cluster_id":"8084","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"4ca1929c-7d64-4aab-b849-badbfc0c760d","distribution":"3","sharing_group_id":null,"default":true},{"id":"12159","galaxy_cluster_id":"8087","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"7113eaa5-ba79-4fb3-b68a-398ee9cd698e","distribution":"3","sharing_group_id":null,"default":true},{"id":"12177","galaxy_cluster_id":"8088","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"f40eb8ce-2a74-4e56-89a1-227021410142","distribution":"3","sharing_group_id":null,"default":true},{"id":"12189","galaxy_cluster_id":"8089","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"38863958-a201-4ce1-9dbe-539b0b6804e0","distribution":"3","sharing_group_id":null,"default":true},{"id":"12211","galaxy_cluster_id":"8090","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"03506554-5f37-4f8f-9ce4-0e9f01a1b484","distribution":"3","sharing_group_id":null,"default":true},{"id":"12240","galaxy_cluster_id":"8092","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"f9c06633-dcff-48a1-8588-759e7cec5694","distribution":"3","sharing_group_id":null,"default":true},{"id":"12247","galaxy_cluster_id":"8093","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"269e8108-68c6-4f99-b911-14b2e765dec2","distribution":"3","sharing_group_id":null,"default":true},{"id":"12331","galaxy_cluster_id":"8095","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"6b9ebeb5-20bf-48b0-afb7-988d769a2f01","distribution":"3","sharing_group_id":null,"default":true},{"id":"12344","galaxy_cluster_id":"8096","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"6fe8a2a1-a1b0-4af8-953d-4babd329f8f8","distribution":"3","sharing_group_id":null,"default":true},{"id":"12429","galaxy_cluster_id":"8098","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"94873029-f950-4268-9cfd-5032e15cb182","distribution":"3","sharing_group_id":null,"default":true},{"id":"12435","galaxy_cluster_id":"8099","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"3fc023b2-c5cc-481d-9c3e-70141ae1a87e","distribution":"3","sharing_group_id":null,"default":true},{"id":"12468","galaxy_cluster_id":"8100","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"afec6dc3-a18e-4b62-b1a4-5510e1a498d1","distribution":"3","sharing_group_id":null,"default":true},{"id":"12610","galaxy_cluster_id":"8104","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"54dfec3e-6464-4f74-9d69-b7c817b7e5a3","distribution":"3","sharing_group_id":null,"default":true},{"id":"13002","galaxy_cluster_id":"8230","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"21da4fd4-27ad-4e9c-b93d-0b9b14d02c96","distribution":"3","sharing_group_id":null,"default":true},{"id":"13082","galaxy_cluster_id":"8255","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"12241367-a8b7-49b4-b86e-2236901ba50c","distribution":"3","sharing_group_id":null,"default":true},{"id":"13902","galaxy_cluster_id":"8361","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"2a4f6c11-a4a7-4cb9-b0ef-6ae1bb3a718a","distribution":"3","sharing_group_id":null,"default":true},{"id":"14087","galaxy_cluster_id":"8371","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"b5dbb4c5-b0b1-40b1-80b6-e9e84ab90067","distribution":"3","sharing_group_id":null,"default":true},{"id":"14231","galaxy_cluster_id":"8391","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"a6a47a06-08fc-4ec4-bdc3-20373375ebb9","distribution":"3","sharing_group_id":null,"default":true},{"id":"14835","galaxy_cluster_id":"9625","referenced_galaxy_cluster_id":"9475","referenced_galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","referenced_galaxy_cluster_type":"revoked-by","galaxy_cluster_uuid":"6aac77c4-eaf2-4366-8c13-ce50ab951f38","distribution":"3","sharing_group_id":null,"default":true}],"meta":{"external_id":["CAPEC-163"],"kill_chain":["mitre-attack:initial-access"],"mitre_data_sources":["Application Log: Application Log Content","Network Traffic: Network Traffic Content","Network Traffic: Network Traffic Flow"],"mitre_platforms":["macOS","Windows","Linux"],"refs":["https://attack.mitre.org/techniques/T1566/001","https://capec.mitre.org/data/definitions/163.html","https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide","https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf","https://www.elastic.co/blog/embracing-offensive-tooling-building-detections-against-koadic-using-eql"]},"tag_id":254,"event_tag_id":"323","local":false,"relationship_type":false},{"id":"9771","uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","collection_uuid":"dcb864dc-775f-11e7-9fbb-1f41b4996683","type":"mitre-attack-pattern","value":"Phishing - T1566","tag_name":"misp-galaxy:mitre-attack-pattern=\"Phishing - T1566\"","description":"Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.\n\nAdversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems. Phishing may also be conducted via third-party services, like social media platforms. Phishing may also involve social engineering techniques, such as posing as a trusted source.","galaxy_id":"48","source":"https://github.com/mitre/cti","authors":["MITRE"],"version":"16","distribution":"3","sharing_group_id":null,"org_id":"0","orgc_id":"0","default":true,"locked":false,"extends_uuid":"","extends_version":"0","published":false,"deleted":false,"GalaxyClusterRelation":[],"Org":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"Orgc":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"TargetingClusterRelation":[{"id":"10127","galaxy_cluster_id":"8008","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"c77c5576-ca19-42ed-a36f-4b4486a84133","distribution":"3","sharing_group_id":null,"default":true},{"id":"11634","galaxy_cluster_id":"8068","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"1c63d4ec-0a75-4daa-b1df-0d11af3d3cc1","distribution":"3","sharing_group_id":null,"default":true},{"id":"13001","galaxy_cluster_id":"8230","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"21da4fd4-27ad-4e9c-b93d-0b9b14d02c96","distribution":"3","sharing_group_id":null,"default":true},{"id":"13081","galaxy_cluster_id":"8255","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"12241367-a8b7-49b4-b86e-2236901ba50c","distribution":"3","sharing_group_id":null,"default":true},{"id":"13901","galaxy_cluster_id":"8361","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"2a4f6c11-a4a7-4cb9-b0ef-6ae1bb3a718a","distribution":"3","sharing_group_id":null,"default":true},{"id":"14086","galaxy_cluster_id":"8371","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"b5dbb4c5-b0b1-40b1-80b6-e9e84ab90067","distribution":"3","sharing_group_id":null,"default":true},{"id":"14230","galaxy_cluster_id":"8391","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"a6a47a06-08fc-4ec4-bdc3-20373375ebb9","distribution":"3","sharing_group_id":null,"default":true},{"id":"14576","galaxy_cluster_id":"9180","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"subtechnique-of","galaxy_cluster_uuid":"f6ad61ee-65f3-4bd0-a3f5-2f0accb36317","distribution":"3","sharing_group_id":null,"default":true},{"id":"14743","galaxy_cluster_id":"9475","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"subtechnique-of","galaxy_cluster_uuid":"2e34237d-8574-43f6-aace-ae2915de8597","distribution":"3","sharing_group_id":null,"default":true},{"id":"14767","galaxy_cluster_id":"9499","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"subtechnique-of","galaxy_cluster_uuid":"2b742742-28c3-4e1b-bab7-8350d6300fa7","distribution":"3","sharing_group_id":null,"default":true},{"id":"14938","galaxy_cluster_id":"9855","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"similar","galaxy_cluster_uuid":"bae9e253-9515-4f1f-b34f-e8fc6747c2e0","distribution":"3","sharing_group_id":null,"default":true},{"id":"14939","galaxy_cluster_id":"9857","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"similar","galaxy_cluster_uuid":"15bd72f9-5ebc-4fef-8fbf-32c2d848f076","distribution":"3","sharing_group_id":null,"default":true},{"id":"14961","galaxy_cluster_id":"9885","referenced_galaxy_cluster_id":"9771","referenced_galaxy_cluster_uuid":"a62a8db3-f23a-4d8f-afd6-9dbc77e7813b","referenced_galaxy_cluster_type":"similar","galaxy_cluster_uuid":"d6ceeb8e-a17b-43b1-bad6-5a81192e2ebd","distribution":"3","sharing_group_id":null,"default":true}],"meta":{"external_id":["CAPEC-98"],"kill_chain":["mitre-attack:initial-access"],"mitre_data_sources":["Application Log: Application Log Content","Network Traffic: Network Traffic Flow","Network Traffic: Network Traffic Content"],"mitre_platforms":["Linux","macOS","Windows","SaaS","Office 365","Google Workspace"],"refs":["https://attack.mitre.org/techniques/T1566","https://capec.mitre.org/data/definitions/98.html","https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide","https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf"]},"tag_id":40,"event_tag_id":"324","local":false,"relationship_type":false}]}],"Object":[{"id":"83","name":"person","meta-category":"misc","description":"An object which describes a person or an identity.","template_uuid":"a15b0477-e9d1-4b9c-9546-abe78a4f4248","template_version":"11","event_id":"46","uuid":"a930eb56-97ec-400d-bb5f-e7250ea0b2ab","timestamp":"1675772508","distribution":"5","sharing_group_id":"0","comment":"Potential victim and teacher","deleted":false,"first_seen":null,"last_seen":null,"ObjectReference":[{"id":"53","uuid":"1e6efe6d-417f-4ae1-9848-f2115add79e0","timestamp":"1675772508","object_id":"83","referenced_uuid":"6bc81b4a-44e3-459d-9bd3-3cf38c92ca9a","referenced_id":"84","referenced_type":"1","relationship_type":"sends","comment":"","deleted":false,"event_id":"46","source_uuid":"a930eb56-97ec-400d-bb5f-e7250ea0b2ab","Object":{"distribution":"5","sharing_group_id":"0","uuid":"6bc81b4a-44e3-459d-9bd3-3cf38c92ca9a","name":"file","meta-category":"file"}}],"Attribute":[{"id":"1469","type":"last-name","category":"Person","to_ids":false,"uuid":"c4a6e23c-4f70-40a0-9a50-819182217eda","event_id":"46","distribution":"5","timestamp":"1675770545","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"83","object_relation":"last-name","first_seen":null,"last_seen":null,"value":"Doe","Galaxy":[],"ShadowAttribute":[]},{"id":"1470","type":"full-name","category":"Person","to_ids":false,"uuid":"f9c78751-302a-432c-8b5e-9467aeb9cd53","event_id":"46","distribution":"5","timestamp":"1675770545","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"83","object_relation":"full-name","first_seen":null,"last_seen":null,"value":"John Doe","Galaxy":[],"ShadowAttribute":[]},{"id":"1471","type":"first-name","category":"Person","to_ids":false,"uuid":"5ced596b-27c4-413c-9831-6ea8b99cdefd","event_id":"46","distribution":"5","timestamp":"1675770545","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":true,"object_id":"83","object_relation":"first-name","first_seen":null,"last_seen":null,"value":"John","Galaxy":[],"ShadowAttribute":[]},{"id":"1472","type":"email-src","category":"Payload delivery","to_ids":true,"uuid":"6df1f6de-cdfd-48c7-9a99-de0c3217b882","event_id":"46","distribution":"5","timestamp":"1675770545","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"83","object_relation":"e-mail","first_seen":null,"last_seen":null,"value":"john.doe@luxembourg.edu","Galaxy":[],"ShadowAttribute":[],"Sighting":[{"id":"32","attribute_id":"1412","event_id":"39","org_id":"1","date_sighting":"1682668454","uuid":"35a5096b-e747-4dbf-a0da-37926c454a26","source":"","type":"0","attribute_uuid":"e28b558b-c1f9-4556-9903-2c16dff76b4a","Organisation":{"id":"1","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6","name":"ORGNAME"}},{"id":"33","attribute_id":"1412","event_id":"39","org_id":"1","date_sighting":"1682668455","uuid":"2e4aeaaf-aeee-451b-8c8b-8df77a75e1ee","source":"","type":"0","attribute_uuid":"e28b558b-c1f9-4556-9903-2c16dff76b4a","Organisation":{"id":"1","uuid":"c5de83b4-36ba-49d6-9530-2a315caeece6","name":"ORGNAME"}}]},{"id":"1473","type":"gender","category":"Person","to_ids":false,"uuid":"ca4e1305-4524-44b7-b5ab-013147a3c908","event_id":"46","distribution":"0","timestamp":"1675770735","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"83","object_relation":"gender","first_seen":null,"last_seen":null,"value":"Male","Galaxy":[],"ShadowAttribute":[]}]},{"id":"84","name":"file","meta-category":"file","description":"File object describing a file with meta-information","template_uuid":"688c46fb-5edb-40a3-8273-1af7923e2215","template_version":"24","event_id":"46","uuid":"6bc81b4a-44e3-459d-9bd3-3cf38c92ca9a","timestamp":"1675772626","distribution":"5","sharing_group_id":"0","comment":"Initial payload","deleted":false,"first_seen":null,"last_seen":null,"ObjectReference":[{"id":"54","uuid":"1948de7d-f4a2-47db-8bd1-c9ef558f9b00","timestamp":"1675772596","object_id":"84","referenced_uuid":"3f8b039a-4864-4ca7-a301-f2322ab35e38","referenced_id":"85","referenced_type":"1","relationship_type":"received-from","comment":"","deleted":false,"event_id":"46","source_uuid":"6bc81b4a-44e3-459d-9bd3-3cf38c92ca9a","Object":{"distribution":"5","sharing_group_id":"0","uuid":"3f8b039a-4864-4ca7-a301-f2322ab35e38","name":"domain-ip","meta-category":"network"}},{"id":"55","uuid":"6f49e906-d81f-48bc-ad01-d84d44755c40","timestamp":"1675772626","object_id":"84","referenced_uuid":"824ce321-3c34-4f25-9b4f-67959d516a45","referenced_id":"87","referenced_type":"1","relationship_type":"downloads","comment":"","deleted":false,"event_id":"46","source_uuid":"6bc81b4a-44e3-459d-9bd3-3cf38c92ca9a","Object":{"distribution":"5","sharing_group_id":"0","uuid":"824ce321-3c34-4f25-9b4f-67959d516a45","name":"file","meta-category":"file"}}],"Attribute":[{"id":"1474","type":"malware-sample","category":"Payload delivery","to_ids":true,"uuid":"832c285e-8c7d-463a-90b1-0cf0b1bcbbc1","event_id":"46","distribution":"5","timestamp":"1675771936","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"84","object_relation":"malware-sample","first_seen":null,"last_seen":null,"value":"malicious.exe|f1a3e62de12faecee82bf4599cc1fdcd","Galaxy":[],"data":"dGVzdAo=","ShadowAttribute":[]},{"id":"1475","type":"filename","category":"Payload delivery","to_ids":false,"uuid":"85aa20c8-5837-4bb1-bd1e-9d99a4eeddc5","event_id":"46","distribution":"5","timestamp":"1675771936","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"84","object_relation":"filename","first_seen":null,"last_seen":null,"value":"malicious.exe","Galaxy":[],"ShadowAttribute":[]},{"id":"1476","type":"md5","category":"Payload delivery","to_ids":true,"uuid":"98cbe26a-16aa-4a38-b408-658322c79bc6","event_id":"46","distribution":"5","timestamp":"1675771936","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"84","object_relation":"md5","first_seen":null,"last_seen":null,"value":"f1a3e62de12faecee82bf4599cc1fdcd","Galaxy":[],"ShadowAttribute":[]},{"id":"1477","type":"sha1","category":"Payload delivery","to_ids":true,"uuid":"fbf3443f-20ca-4a94-bf95-9b2c503b9266","event_id":"46","distribution":"5","timestamp":"1675771936","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"84","object_relation":"sha1","first_seen":null,"last_seen":null,"value":"d836f2ee449b74913d1efc615eeb459b65e4f791","Galaxy":[],"ShadowAttribute":[]},{"id":"1478","type":"sha256","category":"Payload delivery","to_ids":true,"uuid":"19557f28-3d78-4557-8c3c-68bb2f338f4f","event_id":"46","distribution":"5","timestamp":"1675771936","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"84","object_relation":"sha256","first_seen":null,"last_seen":null,"value":"d90401420908dbb4b3488a306467e8fffc57577ce9d5eee016578ff6a3ada12e","Galaxy":[],"ShadowAttribute":[]},{"id":"1479","type":"size-in-bytes","category":"Other","to_ids":false,"uuid":"26c98525-5a56-4d39-8236-908c26810934","event_id":"46","distribution":"5","timestamp":"1675771936","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":true,"object_id":"84","object_relation":"size-in-bytes","first_seen":null,"last_seen":null,"value":"751328","Galaxy":[],"ShadowAttribute":[]}]},{"id":"85","name":"domain-ip","meta-category":"network","description":"A domain/hostname and IP address seen as a tuple in a specific time frame.","template_uuid":"43b3b146-77eb-4931-b4cc-b66c60f28734","template_version":"9","event_id":"46","uuid":"3f8b039a-4864-4ca7-a301-f2322ab35e38","timestamp":"1675771968","distribution":"5","sharing_group_id":"0","comment":"","deleted":false,"first_seen":null,"last_seen":null,"ObjectReference":[],"Attribute":[{"id":"1480","type":"domain","category":"Network activity","to_ids":true,"uuid":"871db045-31d5-4fb0-b62b-852bc773b19b","event_id":"46","distribution":"5","timestamp":"1675771968","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"85","object_relation":"domain","first_seen":null,"last_seen":null,"value":"throwaway-email-provider.com","Galaxy":[],"ShadowAttribute":[]},{"id":"1481","type":"ip-dst","category":"Network activity","to_ids":true,"uuid":"3b9f604e-a3c0-4ff1-a241-aca93cf89488","event_id":"46","distribution":"5","timestamp":"1675771968","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"85","object_relation":"ip","first_seen":null,"last_seen":null,"value":"137.221.106.104","Galaxy":[],"ShadowAttribute":[]}]},{"id":"86","name":"url","meta-category":"network","description":"url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.","template_uuid":"60efb77b-40b5-4c46-871b-ed1ed999fce5","template_version":"9","event_id":"46","uuid":"b09f5f8b-3f25-407e-ad1a-857c0710b378","timestamp":"1675772057","distribution":"5","sharing_group_id":"0","comment":"","deleted":false,"first_seen":null,"last_seen":null,"ObjectReference":[],"Attribute":[{"id":"1482","type":"url","category":"Network activity","to_ids":true,"uuid":"6af71aff-ee12-4fb9-a517-d05fe4f2ea67","event_id":"46","distribution":"5","timestamp":"1675772057","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"86","object_relation":"url","first_seen":null,"last_seen":null,"value":"https://evilprovider.com/this-is-not-malicious.exe","Galaxy":[],"ShadowAttribute":[]},{"id":"1483","type":"domain","category":"Network activity","to_ids":true,"uuid":"de068a83-d14a-44a1-99ec-bfdec9834177","event_id":"46","distribution":"5","timestamp":"1675772057","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"86","object_relation":"domain","first_seen":null,"last_seen":null,"value":"evilprovider.com","Galaxy":[],"ShadowAttribute":[]},{"id":"1484","type":"ip-dst","category":"Network activity","to_ids":true,"uuid":"a62d5a6b-d88d-4a80-9ccb-6e414d985846","event_id":"46","distribution":"5","timestamp":"1675772057","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"86","object_relation":"ip","first_seen":null,"last_seen":null,"value":"2607:5300:60:cd52:304b:760d:da7:d5","Galaxy":[],"ShadowAttribute":[]},{"id":"1485","type":"text","category":"Other","to_ids":false,"uuid":"6840e0e4-034f-46c8-a750-63b2462e0edb","event_id":"46","distribution":"5","timestamp":"1675772057","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"86","object_relation":"resource_path","first_seen":null,"last_seen":null,"value":"this-is-not-malicious.exe","Galaxy":[],"ShadowAttribute":[]},{"id":"1486","type":"text","category":"Other","to_ids":false,"uuid":"5267036a-132c-46c1-aa14-863f790e605e","event_id":"46","distribution":"5","timestamp":"1675772057","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":true,"object_id":"86","object_relation":"scheme","first_seen":null,"last_seen":null,"value":"https","Galaxy":[],"ShadowAttribute":[]}]},{"id":"87","name":"file","meta-category":"file","description":"File object describing a file with meta-information","template_uuid":"688c46fb-5edb-40a3-8273-1af7923e2215","template_version":"24","event_id":"46","uuid":"824ce321-3c34-4f25-9b4f-67959d516a45","timestamp":"1675773578","distribution":"5","sharing_group_id":"0","comment":"Secondary payload","deleted":false,"first_seen":null,"last_seen":null,"ObjectReference":[{"id":"56","uuid":"7243bbb4-9a13-4b89-bfa7-64a350eb357e","timestamp":"1675772648","object_id":"87","referenced_uuid":"b09f5f8b-3f25-407e-ad1a-857c0710b378","referenced_id":"86","referenced_type":"1","relationship_type":"downloaded-from","comment":"","deleted":false,"event_id":"46","source_uuid":"824ce321-3c34-4f25-9b4f-67959d516a45","Object":{"distribution":"5","sharing_group_id":"0","uuid":"b09f5f8b-3f25-407e-ad1a-857c0710b378","name":"url","meta-category":"network"}},{"id":"57","uuid":"13fd08b3-fda8-4202-b898-342764d37dfd","timestamp":"1675772668","object_id":"87","referenced_uuid":"add64cbb-96bb-40f8-9ee0-314ce2ed29e3","referenced_id":"88","referenced_type":"1","relationship_type":"exfiltrates-to","comment":"","deleted":false,"event_id":"46","source_uuid":"824ce321-3c34-4f25-9b4f-67959d516a45","Object":{"distribution":"5","sharing_group_id":"0","uuid":"add64cbb-96bb-40f8-9ee0-314ce2ed29e3","name":"url","meta-category":"network"}},{"id":"58","uuid":"4a71ae7e-5e02-44ad-a5f7-637550c4728c","timestamp":"1675772695","object_id":"87","referenced_uuid":"efa3a323-3696-4744-81d3-5cfa17fadd71","referenced_id":"1487","referenced_type":"0","relationship_type":"exploits","comment":"","deleted":false,"event_id":"46","source_uuid":"824ce321-3c34-4f25-9b4f-67959d516a45","Attribute":{"distribution":"5","sharing_group_id":"0","uuid":"efa3a323-3696-4744-81d3-5cfa17fadd71","value":"CVE-2015-5465","type":"vulnerability","category":"External analysis","to_ids":false}}],"Attribute":[{"id":"1488","type":"malware-sample","category":"Payload installation","to_ids":true,"uuid":"63b1c524-a38a-4bb7-a9ea-f60366fa47ba","event_id":"46","distribution":"5","timestamp":"1675773578","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"87","object_relation":"malware-sample","first_seen":null,"last_seen":null,"value":"this-is-not-malicious.exe|734b3fcc06d0a0eda6b83de9165636ac","Galaxy":[{"id":"48","uuid":"c4e851fa-775f-11e7-8163-b774922098cd","name":"Attack Pattern","type":"mitre-attack-pattern","description":"ATT&CK Tactic","version":"9","icon":"map","namespace":"mitre-attack","enabled":true,"local_only":false,"kill_chain_order":{"mitre-attack":["reconnaissance","resource-development","initial-access","execution","persistence","privilege-escalation","defense-evasion","credential-access","discovery","lateral-movement","collection","command-and-control","exfiltration","impact"],"mitre-mobile-attack":["initial-access","execution","persistence","privilege-escalation","defense-evasion","credential-access","discovery","lateral-movement","collection","command-and-control","exfiltration","impact","network-effects","remote-service-effects"],"mitre-pre-attack":["priority-definition-planning","priority-definition-direction","target-selection","technical-information-gathering","people-information-gathering","organizational-information-gathering","technical-weakness-identification","people-weakness-identification","organizational-weakness-identification","adversary-opsec","establish-&-maintain-infrastructure","persona-development","build-capabilities","test-capabilities","stage-capabilities"]},"GalaxyCluster":[{"id":"8984","uuid":"92d7da27-2d91-488e-a00c-059dc162766d","collection_uuid":"dcb864dc-775f-11e7-9fbb-1f41b4996683","type":"mitre-attack-pattern","value":"Exfiltration Over C2 Channel - T1041","tag_name":"misp-galaxy:mitre-attack-pattern=\"Exfiltration Over C2 Channel - T1041\"","description":"Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.","galaxy_id":"48","source":"https://github.com/mitre/cti","authors":["MITRE"],"version":"16","distribution":"3","sharing_group_id":null,"org_id":"0","orgc_id":"0","default":true,"locked":false,"extends_uuid":"","extends_version":"0","published":false,"deleted":false,"GalaxyClusterRelation":[],"Org":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"Orgc":{"id":"0","name":"MISP","date_created":"","date_modified":"","description":"Automatically generated MISP organisation","type":"","nationality":"Not specified","sector":"","created_by":"0","uuid":"0","contacts":"","local":true,"restricted_to_domain":[],"landingpage":null},"TargetingClusterRelation":[{"id":"879","galaxy_cluster_id":"2224","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"fb261c56-b80e-43a9-8351-c84081e7213d","distribution":"3","sharing_group_id":null,"default":true},{"id":"1902","galaxy_cluster_id":"2917","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"751b77e6-af1f-483b-93fe-eddf17f92a64","distribution":"3","sharing_group_id":null,"default":true},{"id":"1984","galaxy_cluster_id":"2923","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"56e6b6c2-e573-4969-8bab-783205cebbbf","distribution":"3","sharing_group_id":null,"default":true},{"id":"2291","galaxy_cluster_id":"2955","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"4f1c389e-a80e-4a3e-9b0e-9be8c91df64f","distribution":"3","sharing_group_id":null,"default":true},{"id":"2416","galaxy_cluster_id":"2966","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"fb261c56-b80e-43a9-8351-c84081e7213d","distribution":"3","sharing_group_id":null,"default":true},{"id":"2803","galaxy_cluster_id":"2996","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"60a9c2f0-b7a5-4e8e-959c-e1a3ff314a5f","distribution":"3","sharing_group_id":null,"default":true},{"id":"2838","galaxy_cluster_id":"2999","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"63c2a130-8a5b-452f-ad96-07cf0af12ffe","distribution":"3","sharing_group_id":null,"default":true},{"id":"2866","galaxy_cluster_id":"3001","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"01dbc71d-0ee8-420d-abb4-3dfb6a4bf725","distribution":"3","sharing_group_id":null,"default":true},{"id":"2883","galaxy_cluster_id":"3003","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"99164b38-1775-40bc-b77b-a2373b14540a","distribution":"3","sharing_group_id":null,"default":true},{"id":"2913","galaxy_cluster_id":"3007","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"687c23e4-4e25-4ee7-a870-c5e002511f54","distribution":"3","sharing_group_id":null,"default":true},{"id":"3080","galaxy_cluster_id":"3023","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"53cf6cc4-65aa-445a-bcf8-c3d296f8a7a2","distribution":"3","sharing_group_id":null,"default":true},{"id":"3300","galaxy_cluster_id":"3044","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"fb575479-14ef-41e9-bfab-0b7cf10bec73","distribution":"3","sharing_group_id":null,"default":true},{"id":"3482","galaxy_cluster_id":"3058","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"35cd1d01-1ede-44d2-b073-a264d727bc04","distribution":"3","sharing_group_id":null,"default":true},{"id":"3652","galaxy_cluster_id":"3074","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"cb7bcf6f-085f-41db-81ee-4b68481661b5","distribution":"3","sharing_group_id":null,"default":true},{"id":"3656","galaxy_cluster_id":"3075","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"dfb5fa9b-3051-4b97-8035-08f80aef945b","distribution":"3","sharing_group_id":null,"default":true},{"id":"3664","galaxy_cluster_id":"3076","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"463f68f1-5cde-4dc2-a831-68b73488f8f4","distribution":"3","sharing_group_id":null,"default":true},{"id":"4060","galaxy_cluster_id":"3111","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"a4f57468-fbd5-49e4-8476-52088220b92d","distribution":"3","sharing_group_id":null,"default":true},{"id":"4251","galaxy_cluster_id":"3127","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"aad11e34-02ca-4220-91cd-2ed420af4db3","distribution":"3","sharing_group_id":null,"default":true},{"id":"4304","galaxy_cluster_id":"3132","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"d20b397a-ea47-48a9-b503-2e2a3551e11d","distribution":"3","sharing_group_id":null,"default":true},{"id":"4352","galaxy_cluster_id":"3135","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"958b5d06-8bb0-4c5b-a2e7-0130fe654ac7","distribution":"3","sharing_group_id":null,"default":true},{"id":"4436","galaxy_cluster_id":"3145","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"12a7450d-b03e-4990-a5b8-b405ab9c803b","distribution":"3","sharing_group_id":null,"default":true},{"id":"4505","galaxy_cluster_id":"3150","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"53486bc7-7748-4716-8190-e4f1fde04c53","distribution":"3","sharing_group_id":null,"default":true},{"id":"4604","galaxy_cluster_id":"3160","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"5f9f7648-04ba-4a9f-bb4c-2a13e74572bd","distribution":"3","sharing_group_id":null,"default":true},{"id":"4731","galaxy_cluster_id":"3167","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"20945359-3b39-4542-85ef-08ecb4e1c174","distribution":"3","sharing_group_id":null,"default":true},{"id":"5384","galaxy_cluster_id":"3228","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"069af411-9b24-4e85-b26c-623d035bbe84","distribution":"3","sharing_group_id":null,"default":true},{"id":"5398","galaxy_cluster_id":"3230","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"1f6e3702-7ca1-4582-b2e7-4591297d05a8","distribution":"3","sharing_group_id":null,"default":true},{"id":"5516","galaxy_cluster_id":"3240","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"8e101fdd-9f7f-4916-bb04-6bd9e94c129c","distribution":"3","sharing_group_id":null,"default":true},{"id":"5598","galaxy_cluster_id":"3245","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"cc5497f7-a9e8-436f-94da-b2b4a9b9ad3c","distribution":"3","sharing_group_id":null,"default":true},{"id":"5696","galaxy_cluster_id":"3253","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"8bdfe255-e658-4ddd-a11c-b854762e451d","distribution":"3","sharing_group_id":null,"default":true},{"id":"5895","galaxy_cluster_id":"3266","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"00806466-754d-44ea-ad6f-0caf59cb8556","distribution":"3","sharing_group_id":null,"default":true},{"id":"6052","galaxy_cluster_id":"3282","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"feb2d7bb-aacb-48df-ad04-ccf41a30cd90","distribution":"3","sharing_group_id":null,"default":true},{"id":"6129","galaxy_cluster_id":"3286","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"edb24a93-1f7a-4bbf-a738-1397a14662c6","distribution":"3","sharing_group_id":null,"default":true},{"id":"6325","galaxy_cluster_id":"3298","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"03ea629c-517a-41e3-94f8-c7e5368cf8f4","distribution":"3","sharing_group_id":null,"default":true},{"id":"6421","galaxy_cluster_id":"3306","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"8f423bd7-6ca7-4303-9e85-008c7ad5fdaa","distribution":"3","sharing_group_id":null,"default":true},{"id":"6475","galaxy_cluster_id":"3309","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"b9704a7d-feef-4af9-8898-5280f1686326","distribution":"3","sharing_group_id":null,"default":true},{"id":"6515","galaxy_cluster_id":"3311","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"4b6ec280-7bbb-48ff-ae59-b189520ebe83","distribution":"3","sharing_group_id":null,"default":true},{"id":"6595","galaxy_cluster_id":"3316","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"ecc2f65a-b452-4eaf-9689-7e181f17f7a5","distribution":"3","sharing_group_id":null,"default":true},{"id":"6620","galaxy_cluster_id":"3317","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"d906e6f7-434c-44c0-b51a-ed50af8f7945","distribution":"3","sharing_group_id":null,"default":true},{"id":"6643","galaxy_cluster_id":"3318","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"925a6c52-5cf0-4fec-99de-b0d6917d8593","distribution":"3","sharing_group_id":null,"default":true},{"id":"6677","galaxy_cluster_id":"3321","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"6ba1d7ae-d60b-43e6-9f08-a8b787e9d9cb","distribution":"3","sharing_group_id":null,"default":true},{"id":"6705","galaxy_cluster_id":"3323","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"32066e94-3112-48ca-b9eb-ba2b59d2f023","distribution":"3","sharing_group_id":null,"default":true},{"id":"6753","galaxy_cluster_id":"3324","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"454fe82d-6fd2-4ac6-91ab-28a33fe01369","distribution":"3","sharing_group_id":null,"default":true},{"id":"6804","galaxy_cluster_id":"3326","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"1492d0f8-7e14-4af3-9239-bc3fe10d3407","distribution":"3","sharing_group_id":null,"default":true},{"id":"6845","galaxy_cluster_id":"3329","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"d6b3fcd0-1c86-4350-96f0-965ed02fcc51","distribution":"3","sharing_group_id":null,"default":true},{"id":"6989","galaxy_cluster_id":"3341","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"cb741463-f0fe-42e0-8d45-bc7e8335f5ae","distribution":"3","sharing_group_id":null,"default":true},{"id":"7018","galaxy_cluster_id":"3342","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"bbcd7a02-ef24-4171-ac94-a93540173b94","distribution":"3","sharing_group_id":null,"default":true},{"id":"7201","galaxy_cluster_id":"3354","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"e2d34c63-6f5a-41f5-86a2-e2380f27f858","distribution":"3","sharing_group_id":null,"default":true},{"id":"7286","galaxy_cluster_id":"3357","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"4b346d12-7f91-48d2-8f06-b26ffa0d825b","distribution":"3","sharing_group_id":null,"default":true},{"id":"7325","galaxy_cluster_id":"3359","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"dfa03c7d-79ed-4ce2-b9d1-ddc9dbf56ad2","distribution":"3","sharing_group_id":null,"default":true},{"id":"7359","galaxy_cluster_id":"3361","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"b51797f7-57da-4210-b8ac-b8632ee75d70","distribution":"3","sharing_group_id":null,"default":true},{"id":"7366","galaxy_cluster_id":"3362","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"ade37ada-14af-4b44-b36c-210eec255d53","distribution":"3","sharing_group_id":null,"default":true},{"id":"7455","galaxy_cluster_id":"3366","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"ac61f1f9-7bb1-465e-9b8a-c2ce8e88baf5","distribution":"3","sharing_group_id":null,"default":true},{"id":"7469","galaxy_cluster_id":"3367","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"eac3d77f-2b7b-4599-ba74-948dc16633ad","distribution":"3","sharing_group_id":null,"default":true},{"id":"7495","galaxy_cluster_id":"3369","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"c984b414-b766-44c5-814a-2fe96c913c12","distribution":"3","sharing_group_id":null,"default":true},{"id":"7630","galaxy_cluster_id":"3379","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"727afb95-3d0f-4451-b297-362a43909923","distribution":"3","sharing_group_id":null,"default":true},{"id":"7702","galaxy_cluster_id":"3383","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"7cdfccda-2950-4167-981a-60872ff5d0db","distribution":"3","sharing_group_id":null,"default":true},{"id":"7757","galaxy_cluster_id":"3388","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"d18cb958-f4ad-4fb3-bb4f-e8994d206550","distribution":"3","sharing_group_id":null,"default":true},{"id":"7790","galaxy_cluster_id":"3391","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"5c747acd-47f0-4c5a-b9e5-213541fc01e0","distribution":"3","sharing_group_id":null,"default":true},{"id":"7990","galaxy_cluster_id":"3946","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"8f8cd191-902c-4e83-bf20-b57c8c4640e9","distribution":"3","sharing_group_id":null,"default":true},{"id":"8175","galaxy_cluster_id":"3984","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"cb69b20d-56d0-41ab-8440-4a4b251614d4","distribution":"3","sharing_group_id":null,"default":true},{"id":"8385","galaxy_cluster_id":"4006","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"3433a9e8-1c47-4320-b9bf-ed449061d1c3","distribution":"3","sharing_group_id":null,"default":true},{"id":"8454","galaxy_cluster_id":"4012","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"115f88dd-0618-4389-83cb-98d33ae81848","distribution":"3","sharing_group_id":null,"default":true},{"id":"8609","galaxy_cluster_id":"4113","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"92c28497-2820-445e-9f3e-a03dd77dc0c8","distribution":"3","sharing_group_id":null,"default":true},{"id":"9656","galaxy_cluster_id":"7991","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"dd2d9ca6-505b-4860-a604-233685b802c7","distribution":"3","sharing_group_id":null,"default":true},{"id":"9817","galaxy_cluster_id":"7996","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"c93fccb1-e8e8-42cf-ae33-2ad1d183913a","distribution":"3","sharing_group_id":null,"default":true},{"id":"9934","galaxy_cluster_id":"8000","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"381fcf73-60f6-4ab2-9991-6af3cbc35192","distribution":"3","sharing_group_id":null,"default":true},{"id":"9993","galaxy_cluster_id":"8001","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"894aab42-3371-47b1-8859-a4a074c804c8","distribution":"3","sharing_group_id":null,"default":true},{"id":"10013","galaxy_cluster_id":"8003","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"2e290bfe-93b5-48ce-97d6-edcd6d32b7cf","distribution":"3","sharing_group_id":null,"default":true},{"id":"10148","galaxy_cluster_id":"8009","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"28f04ed3-8e91-4805-b1f6-869020517871","distribution":"3","sharing_group_id":null,"default":true},{"id":"10599","galaxy_cluster_id":"8024","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"247cb30b-955f-42eb-97a5-a89fef69341e","distribution":"3","sharing_group_id":null,"default":true},{"id":"10803","galaxy_cluster_id":"8029","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"6713ab67-e25b-49cc-808d-2b36d4fbc35c","distribution":"3","sharing_group_id":null,"default":true},{"id":"10923","galaxy_cluster_id":"8034","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"6b1b551c-d770-4f95-8cfc-3cd253c4c04e","distribution":"3","sharing_group_id":null,"default":true},{"id":"11464","galaxy_cluster_id":"8058","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"0bbdf25b-30ff-4894-a1cd-49260d0dd2d9","distribution":"3","sharing_group_id":null,"default":true},{"id":"11788","galaxy_cluster_id":"8073","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"44e43fad-ffcb-4210-abcf-eaaed9735f80","distribution":"3","sharing_group_id":null,"default":true},{"id":"11842","galaxy_cluster_id":"8075","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"06a11b7e-2a36-47fe-8d3e-82c265df3258","distribution":"3","sharing_group_id":null,"default":true},{"id":"12010","galaxy_cluster_id":"8083","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"0ec2f388-bf0f-4b5c-97b1-fc736d26c25f","distribution":"3","sharing_group_id":null,"default":true},{"id":"12288","galaxy_cluster_id":"8093","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"269e8108-68c6-4f99-b911-14b2e765dec2","distribution":"3","sharing_group_id":null,"default":true},{"id":"12525","galaxy_cluster_id":"8101","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"8c1f0187-0826-4320-bddc-5f326cfcfe2c","distribution":"3","sharing_group_id":null,"default":true},{"id":"12596","galaxy_cluster_id":"8104","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"54dfec3e-6464-4f74-9d69-b7c817b7e5a3","distribution":"3","sharing_group_id":null,"default":true},{"id":"12641","galaxy_cluster_id":"8105","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"uses","galaxy_cluster_uuid":"4283ae19-69c7-4347-a35e-b56f08eb660b","distribution":"3","sharing_group_id":null,"default":true},{"id":"12650","galaxy_cluster_id":"8117","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"92c28497-2820-445e-9f3e-a03dd77dc0c8","distribution":"3","sharing_group_id":null,"default":true},{"id":"13059","galaxy_cluster_id":"8255","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"mitigates","galaxy_cluster_uuid":"12241367-a8b7-49b4-b86e-2236901ba50c","distribution":"3","sharing_group_id":null,"default":true},{"id":"14940","galaxy_cluster_id":"9859","referenced_galaxy_cluster_id":"8984","referenced_galaxy_cluster_uuid":"92d7da27-2d91-488e-a00c-059dc162766d","referenced_galaxy_cluster_type":"similar","galaxy_cluster_uuid":"85b1f79e-49e7-4501-9b5c-a39ffce47428","distribution":"3","sharing_group_id":null,"default":true}],"meta":{"external_id":["T1041"],"kill_chain":["mitre-attack:exfiltration"],"mitre_data_sources":["Network Traffic: Network Connection Creation","Network Traffic: Network Traffic Flow","Network Traffic: Network Traffic Content","File: File Access","Command: Command Execution"],"mitre_platforms":["Linux","macOS","Windows"],"refs":["https://attack.mitre.org/techniques/T1041","https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf"]},"tag_id":255,"attribute_tag_id":"229","local":false,"relationship_type":false}]}],"data":"dGVzdDIK","ShadowAttribute":[],"Tag":[{"id":"255","name":"misp-galaxy:mitre-attack-pattern=\"Exfiltration Over C2 Channel - T1041\"","colour":"#0088cc","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":true,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null}]},{"id":"1489","type":"filename","category":"Payload installation","to_ids":false,"uuid":"ccea9c5f-b427-43ce-8fbe-2ff58546c2fc","event_id":"46","distribution":"5","timestamp":"1675772134","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"87","object_relation":"filename","first_seen":null,"last_seen":null,"value":"this-is-not-malicious.exe","Galaxy":[],"ShadowAttribute":[]},{"id":"1490","type":"md5","category":"Payload installation","to_ids":true,"uuid":"7e35b84e-623b-44fc-93da-e7ec79d16d1d","event_id":"46","distribution":"5","timestamp":"1675772134","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"87","object_relation":"md5","first_seen":null,"last_seen":null,"value":"734b3fcc06d0a0eda6b83de9165636ac","Galaxy":[],"ShadowAttribute":[]},{"id":"1491","type":"sha1","category":"Payload installation","to_ids":true,"uuid":"6146d7aa-f706-4458-802a-c4679168f789","event_id":"46","distribution":"5","timestamp":"1675772134","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"87","object_relation":"sha1","first_seen":null,"last_seen":null,"value":"5429e6a53d49aab342b1d0f82b1b627bf8666677","Galaxy":[],"ShadowAttribute":[]},{"id":"1492","type":"sha256","category":"Payload installation","to_ids":true,"uuid":"e243a93c-8732-4a84-9fcc-e14df2e02c9a","event_id":"46","distribution":"5","timestamp":"1675772134","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"87","object_relation":"sha256","first_seen":null,"last_seen":null,"value":"13d8429d500e20be8588f250449f70a6e8f8f34df9423b2897fd33bbb8712c5f","Galaxy":[],"ShadowAttribute":[]},{"id":"1493","type":"size-in-bytes","category":"Other","to_ids":false,"uuid":"29c3343d-65e6-4139-9999-98c2afed4cb4","event_id":"46","distribution":"5","timestamp":"1675772134","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":true,"object_id":"87","object_relation":"size-in-bytes","first_seen":null,"last_seen":null,"value":"1274088","Galaxy":[],"ShadowAttribute":[]}]},{"id":"88","name":"url","meta-category":"network","description":"url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.","template_uuid":"60efb77b-40b5-4c46-871b-ed1ed999fce5","template_version":"9","event_id":"46","uuid":"add64cbb-96bb-40f8-9ee0-314ce2ed29e3","timestamp":"1675773443","distribution":"5","sharing_group_id":"0","comment":"C2 server used for exfiltration","deleted":false,"first_seen":null,"last_seen":null,"ObjectReference":[],"Attribute":[{"id":"1494","type":"url","category":"Network activity","to_ids":true,"uuid":"3a85c40e-16dd-44d9-8eb3-89c95d042c7a","event_id":"46","distribution":"5","timestamp":"1675773443","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"88","object_relation":"url","first_seen":null,"last_seen":null,"value":"https://another.evil.provider.com:57666/","Galaxy":[],"ShadowAttribute":[],"Tag":[{"id":"122","name":"adversary:infrastructure-type=\"c2\"","colour":"#9e00ff","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":false,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null}]},{"id":"1495","type":"domain","category":"Network activity","to_ids":true,"uuid":"d3383359-4ef0-4596-9b11-8192a084e8c6","event_id":"46","distribution":"5","timestamp":"1675772371","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"88","object_relation":"domain","first_seen":null,"last_seen":null,"value":"another.evil.provider.com","Galaxy":[],"ShadowAttribute":[]},{"id":"1496","type":"ip-dst","category":"Network activity","to_ids":true,"uuid":"22c67a9d-2356-41b4-b5a8-eb61a16407af","event_id":"46","distribution":"5","timestamp":"1675772371","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"88","object_relation":"ip","first_seen":null,"last_seen":null,"value":"118.217.182.36","Galaxy":[],"ShadowAttribute":[]},{"id":"1497","type":"port","category":"Network activity","to_ids":false,"uuid":"a7ee2aa1-72e4-49f7-94bf-cc4c17d1aab2","event_id":"46","distribution":"5","timestamp":"1675772371","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":false,"object_id":"88","object_relation":"port","first_seen":null,"last_seen":null,"value":"57666","Galaxy":[],"ShadowAttribute":[]},{"id":"1498","type":"text","category":"Other","to_ids":false,"uuid":"dc4151bc-ee9a-4c1f-a919-5f688f043c17","event_id":"46","distribution":"5","timestamp":"1675772371","comment":"","sharing_group_id":"0","deleted":false,"disable_correlation":true,"object_id":"88","object_relation":"scheme","first_seen":null,"last_seen":null,"value":"https","Galaxy":[],"ShadowAttribute":[]}]}],"EventReport":[{"id":"25","uuid":"13b81ddb-2169-4f94-b71a-23048440ba18","event_id":"46","name":"Original mail received","content":"# Orginial email received from Fake-Company\n\n```\nFrom: \"Telecommunication CSIRT of Fake-Company\" <csirt@fake-company.lu>\nTo: \"Telecommunication CSIRT of Luxembourg\" <csirt@telco.lu>\nSubject: Attempted spearphishing attempt\n```\n\nDear xy,\n\nWe have had a failed spearphishing attempt targeting our CEO recently with the following details:\n\nOur CEO received an E-mail on 13/09/2022 15:56 containing a personalised message about a report card for their child. The attacker pretended to be working for the school of the CEO’s daughter, sending the mail from a spoofed address (@[attribute](6df1f6de-cdfd-48c7-9a99-de0c3217b882)). John Doe is a teacher of the student. The email was received from @[object](3f8b039a-4864-4ca7-a301-f2322ab35e38).\n\nThe e-mail contained a malicious file (find it attached) that would try to download a secondary payload from @[attribute](6840e0e4-034f-46c8-a750-63b2462e0edb) (also attached, resolves to 2607:5300:60:cd52:304b:760d:da7:d5). It looks like the sample is trying to exploit @[attribute](efa3a323-3696-4744-81d3-5cfa17fadd71). After a brief triage, the secondary payload has a hardcoded C2 at https://another.evil.provider.com:57666 (118.217.182.36) to which it tries to exfiltrate local credentials. This is how far we have gotten so far. Please be mindful that this is an ongoing investigation, we would like to avoid informing the attacker of the detection and kindly ask you to only use the contained information to protect your constituents.\n\nThis is @[attribute](1d64f99b-40c4-4785-8ce8-eb03b1e62655) !\n\n- @[tag](tlp:amber)\n- @[tag](misp-galaxy:mitre-attack-pattern=\"Exfiltration Over C2 Channel - T1041\")\n\nBest regards,","distribution":"5","sharing_group_id":"0","timestamp":"1675774158","deleted":false}],"CryptographicKey":[],"Tag":[{"id":"81","name":"tlp:amber","colour":"#FFC000","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":false,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"137","name":"PAP:AMBER","colour":"#ffa800","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":false,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"148","name":"phishing:techniques=\"email-spoofing\"","colour":"#002241","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":false,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"153","name":"phishing:distribution=\"spear-phishing\"","colour":"#003363","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":false,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"166","name":"phishing:state=\"active\"","colour":"#0061bb","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":"100","is_galaxy":false,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"170","name":"phishing:psychological-acceptability=\"medium\"","colour":"#006fd6","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":"50","is_galaxy":false,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"4","name":"estimative-language:likelihood-probability=\"very-likely\"","colour":"#001cad","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":"80","is_galaxy":false,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"251","name":"misp-galaxy:target-information=\"Luxembourg\"","colour":"#0088cc","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":true,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"253","name":"misp-galaxy:country=\"luxembourg\"","colour":"#0088cc","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":true,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":"targets"},{"id":"145","name":"misp-galaxy:mitre-attack-pattern=\"Spear phishing messages with malicious attachments - T1367\"","colour":"#0088cc","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":true,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"254","name":"misp-galaxy:mitre-attack-pattern=\"Spearphishing Attachment - T1566.001\"","colour":"#0088cc","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":true,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null},{"id":"40","name":"misp-galaxy:mitre-attack-pattern=\"Phishing - T1566\"","colour":"#0088cc","exportable":true,"user_id":"0","hide_tag":false,"numerical_value":null,"is_galaxy":true,"is_custom_galaxy":false,"local_only":false,"local":0,"relationship_type":null}]}}';


    private const ACCEPTED_FILTERING_NAMED_PARAMS = [
        'sort', 'direction', 'focus', 'extended', 'overrideLimit', 'filterColumnsOverwrite', 'attributeFilter', 'page',
        'searchFor', 'proposal', 'correlation', 'warning', 'deleted', 'includeRelatedTags', 'includeDecayScore', 'distribution',
        'taggedAttributes', 'galaxyAttachedAttributes', 'objectType', 'attributeType', 'feed', 'server', 'toIDS',
        'sighting', 'includeSightingdb', 'warninglistId', 'correlationId', 'email', 'eventid', 'datefrom', 'dateuntil'
    ];

    private const DEFAULT_FILTERING_RULE = [
        'searchFor' => '',
        'attributeFilter' => 'all',
        'proposal' => 0,
        'correlation' => 0,
        'warning' => 0,
        'deleted' => 0,
        'includeRelatedTags' => 0,
        'includeDecayScore' => 0,
        'toIDS' => 0,
        'feed' => 0,
        'server' => 0,
        'distribution' => [0, 1, 2, 3, 4, 5],
        'sighting' => 0,
        'taggedAttributes' => '',
        'galaxyAttachedAttributes' => '',
        'warninglistId' => '',
        'correlationId' => '',
    ];

    private const DEFAULT_HIDDEN_INDEX_COLUMNS = [
        'timestamp',
        'publish_timestamp'
    ];

    public $paginationFunctions = ['index', 'proposalEventIndex'];

    public $paginate = [
        'limit' => 60,
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
        'order' => [
            'Events.timestamp' => 'DESC'
        ],
        'contain' => [
            'Org' => ['fields' => ['id', 'name', 'uuid']],
            'Orgc' => ['fields' => ['id', 'name', 'uuid']],
            'SharingGroup' => ['fields' => ['id', 'name', 'uuid']]
        ]
    ];

    public function initialize(): void
    {
        $this->loadComponent('Toolbox');
        parent::initialize();
    }

    public function viewMock($id)
    {
        $data = json_decode($this->data1, true);
        $stats = $this->getStatisticsFromEvent($data);
        $warningslist_hits = [["value" => "8.8.8.8", "match" => "8.8.8.8/32", "warninglist_id" => 49, "warninglist_name" => "List of known IPv4 public DNS resolvers", "warninglist_category" => "false_positive"]];
        $recent_sightings = [["id" => "32", "attribute_id" => "1412", "event_id" => "39", "org_id" => "1", "date_sighting" => "1682668454", "uuid" => "35a5096b-e747-4dbf-a0da-37926c454a26", "source" => "", "type" => "0", "attribute_uuid" => "e28b558b-c1f9-4556-9903-2c16dff76b4a", "Organisation" => ["id" => "1", "uuid" => "c5de83b4-36ba-49d6-9530-2a315caeece6", "name" => "ORGNAME"]], ["id" => "33", "attribute_id" => "1412", "event_id" => "39", "org_id" => "1", "date_sighting" => "1682668455", "uuid" => "2e4aeaaf-aeee-451b-8c8b-8df77a75e1ee", "source" => "", "type" => "0", "attribute_uuid" => "e28b558b-c1f9-4556-9903-2c16dff76b4a", "Organisation" => ["id" => "1", "uuid" => "c5de83b4-36ba-49d6-9530-2a315caeece6", "name" => "ORGNAME"]]];
        $this->set('entity', $data);
        $this->set('stats', $stats);
        $this->set('warningslist_hits', $warningslist_hits);
        $this->set('recent_sightings', $recent_sightings);
    }

    public function getStatistics($id)
    {
        $data = json_decode($this->data1, true);
        $this->set('entity', $data);
    }

    private function getStatisticsFromEvent(array $event)
    {
        $stat_counts = [
            'attributes' => 0,
            'objects' => 0,
            'proposals' => 0,
            'eventreports' => 0,
            'attribute_deleted' => 0,
            'iocs' => 0,
            'observables' => 0,
            'relationships' => 0,
            'sightings' => 0,
            'correlations' => 0,
            'feed_correlations' => 0,
            'extensions' => 0,
            'discussions' => 0,
            'warninglists' => 0,
        ];
        $stat_distribution = [
            0 => 0,
            1 => 0,
            2 => 0,
            3 => 0,
            4 => 0,
        ];
        $stat_objects = [];
        $stat_attributes = [];

        $stat_counts['correlations'] = count($event['Event']['RelatedEvent'] ?? []);
        $stat_counts['feed_correlations'] = count($event['Event']['Feed'] ?? []);
        $stat_counts['attributes'] = count($event['Event']['Attribute'] ?? []);
        $stat_counts['objects'] = count($event['Event']['Object'] ?? []);
        $stat_counts['proposals'] = count($event['Event']['ShadowAttribute'] ?? []);
        $stat_counts['eventreports'] = count($event['Event']['EventReport'] ?? []);
        $stat_counts['discussions'] = count($event['Event']['Discussion'] ?? []);

        foreach ($event['Event']['Attribute'] as $attribute) {
            if ($attribute['to_ids']) {
                $stat_counts['iocs'] += 1;
            } else {
                $stat_counts['observables'] += 1;
            }
            if (!empty($attribute['deleted'])) {
                $stat_counts['proposals']['attribute_deleted'] += 1;
            }

            $attrDistribution = $attribute['distribution'] == '5' ? intval($event['Event']['distribution']) : intval($attribute['distribution']);
            if (!isset($stat_distribution[$attrDistribution])) {
                $stat_distribution[$attrDistribution] = 0;
            }
            $stat_distribution[$attrDistribution] += 1;

            if (!isset($stat_distribution[$attribute['type']])) {
                $stat_attributes[$attribute['type']] = 0;
            }
            $stat_attributes[$attribute['type']] += 1;
            if (!empty($attribute['warnings'])) {
                $stat_counts['warninglists'] += count($attribute['warnings']);
            }
            if (!empty($attribute['Sighting'])) {
                $stat_counts['sightings'] += count($attribute['Sighting']);
            }
        }

        foreach ($event['Event']['Object'] as $object) {
            if (!isset($stat_objects[$object['name']])) {
                $stat_objects[$object['name']] = 0;
            }
            $stat_objects[$object['name']] += 1;
            $stat_counts['relationships'] += count($object['ObjectReference'] ?? []);
            $stat_counts['attributes'] += count($object['Attribute']);
            foreach ($object['Attribute'] as $attribute) {
                if ($attribute['to_ids']) {
                    $stat_counts['iocs'] += 1;
                } else {
                    $stat_counts['observables'] += 1;
                }
                if (!empty($attribute['deleted'])) {
                    $stat_counts['proposals']['attribute_deleted'] += 1;
                }

                $attrDistribution = $attribute['distribution'] == '5' ? intval($event['Event']['distribution']) : intval($attribute['distribution']);
                if (!isset($stat_distribution[$attrDistribution])) {
                    $stat_distribution[$attrDistribution] = 0;
                }
                $stat_distribution[$attrDistribution] += 1;

                if (!isset($stat_distribution[$attribute['type']])) {
                    $stat_attributes[$attribute['type']] = 0;
                }
                $stat_attributes[$attribute['type']] += 1;
                if (!empty($attribute['warnings'])) {
                    $stat_counts['warninglists'] += count($attribute['warnings']);
                }
                if (!empty($attribute['Sighting'])) {
                    $stat_counts['sightings'] += count($attribute['Sighting']);
                }
            }
        }

        arsort($stat_objects);
        arsort($stat_attributes);

        $stat_objects_6 = array_slice($stat_objects, 0, 5);
        if (count($stat_objects) > 5) {
            $stat_objects_6['Others'] = array_sum(array_slice($stat_objects, 5));
        }
        $stat_attributes_6 = array_slice($stat_attributes, 0, 5);
        if (count($stat_attributes) > 5) {
            $stat_attributes_6['Others'] = array_sum(array_slice($stat_attributes, 5));
        }

        return [
            'stat_counts' => $stat_counts,
            'stat_distribution' => $stat_distribution,
            'distribution_levels' => ['Org. only', 'Community', 'Connected community', 'All community', 'Sharing group'],
            'stat_objects' => $stat_objects,
            'stat_objects_6' => $stat_objects_6,
            'stat_attributes' => $stat_attributes,
            'stat_attributes_6' => $stat_attributes_6,
        ];
    }

    public function beforeFilter(EventInterface $event)
    {
        parent::beforeFilter($event);

        // // what pages are allowed for non-logged-in users
        // TODO: [3.x-MIGRATION] is this still relevant?
        // $this->ACL->allow('xml');
        // $this->ACL->allow('csv');
        // $this->ACL->allow('nids');
        // $this->ACL->allow('hids_md5');
        // $this->ACL->allow('hids_sha1');
        // $this->ACL->allow('text');
        // $this->ACL->allow('restSearch');
        // $this->ACL->allow('stix');
        // $this->ACL->allow('stix2');

        $this->Security->setConfig('unlockedActions', ['viewEventAttributes']);

        // TODO: [3.x-MIGRATION] is this still relevant?
        // TODO Audit, activate logable in a Controller
        // if (count($this->uses) && $this->{$this->modelClass}->Behaviors->attached('SysLogLogable')) {
        //     $this->{$this->modelClass}->setUserData($this->activeUser);
        // }

        // convert uuid to id if present in the url, and overwrite id field
        if (isset($this->request->getQueryParams()['uuid'])) {
            $params = [
                'conditions' => ['Events.uuid' => $this->request->getQueryParams()['uuid']],
                'recursive' => 0,
                'fields' => 'id'
            ];
            $result = $this->Events->find('all', $params)->first();
            if (isset($result['Event']) && isset($result['Event']['id'])) {
                $id = $result['Event']['id'];
                $this->params->addParams(['pass' => [$id]]); // FIXME find better way to change id variable if uuid is found. params->url and params->here is not modified accordingly now
            }
        }

        // if not admin or own org, check private as well..
        if ($this->ACL->getUser() && !$this->isSiteAdmin() && in_array($this->request->getParam('action'), $this->paginationFunctions, true)) {
            $conditions = $this->Events->createEventConditions($this->ACL->getUser()->toArray());
            if ($this->ACL->getUser()['Role']['perm_sync'] && $this->ACL->getUser()['Server']['push_rules']) {
                $conditions['AND'][] = $this->Events->filterRulesToConditions($this->ACL->getUser()['Server']['push_rules']);
            }
            $this->paginate = Hash::merge($this->paginate, ['conditions' => $conditions]);
        }

        if (in_array($this->request->getParam('action'), ['checkLocks', 'getDistributionGraph'], true)) {
            $this->Security->doNotGenerateToken = true;
        }

        if (Configure::read('Plugin.CustomAuth_enable') && in_array($this->request->getParam('action'), ['saveFreeText'], true)) {
            $this->Security->csrfCheck = false;
        }
    }

    /**
     * @param string $value
     * @return array[]
     */
    private function __filterOnAttributeValue($value)
    {
        // dissect the value
        $include = [];
        $exclude = [];
        $includeIDs = [];
        $excludeIDs = [];
        if (!empty($value)) {
            if (!is_array($value)) {
                $pieces = explode('|', mb_strtolower($value));
            } else {
                $pieces = $value;
            }

            foreach ($pieces as $piece) {
                if ($piece[0] === '!') {
                    $exclude[] =  '%' . substr($piece, 1) . '%';
                } else {
                    $include[] = "%$piece%";
                }
            }

            if (!empty($include)) {
                $includeConditions = [];
                foreach ($include as $i) {
                    $includeConditions['OR'][] = ['Attribute.value1 LIKE' => $i];
                    $includeConditions['OR'][] = ['Attribute.value2 LIKE' => $i];
                }

                $includeIDs = $this->Events->Attributes->fetchAttributes(
                    $this->ACL->getUser()->toArray(),
                    [
                        'conditions' => $includeConditions,
                        'flatten' => true,
                        'event_ids' => true,
                        'list' => true,
                    ]
                );
            }

            if (!empty($exclude)) {
                $excludeConditions = [];
                foreach ($exclude as $e) {
                    $excludeConditions['OR'][] = ['Attribute.value1 LIKE' => $e];
                    $excludeConditions['OR'][] = ['Attribute.value2 LIKE' => $e];
                }

                $excludeIDs = $this->Events->Attributes->fetchAttributes(
                    $this->ACL->getUser()->toArray(),
                    [
                        'conditions' => $excludeConditions,
                        'flatten' => true,
                        'event_ids' => true,
                        'list' => true,
                    ]
                );
            }
        }
        // return -1 as the only value in includedIDs if both arrays are empty. This will mean that no events will be shown if there was no hit
        if (empty($includeIDs) && empty($excludeIDs)) {
            $includeIDs[] = -1;
        }
        return [$includeIDs, $excludeIDs];
    }

    /**
     * @param string|array $value
     * @return array Event ID that match filter
     */
    private function __quickFilter($value)
    {
        if (!is_array($value)) {
            $value = [$value];
        }
        $values = [];
        foreach ($value as $v) {
            $values[] = '%' . mb_strtolower($v) . '%';
        }

        // get all of the attributes that have a hit on the search term, in either the value or the comment field
        // This is not perfect, the search will be case insensitive, but value1 and value2 are searched separately. lower() doesn't seem to work on virtualfields
        $subconditions = [];
        foreach ($values as $v) {
            $subconditions[] = ['Attribute.value1 LIKE' => $v];
            $subconditions[] = ['Attribute.value2 LIKE' => $v];
            $subconditions[] = ['Attribute.comment LIKE' => $v];
        }
        $conditions = [
            'OR' => $subconditions,
        ];
        $result = $this->Events->Attributes->fetchAttributes(
            $this->ACL->getUser()->toArray(),
            [
                'conditions' => $conditions,
                'flatten' => 1,
                'event_ids' => true,
                'list' => true,
            ]
        );

        // we now have a list of event IDs that match on an attribute level, and the user can see it. Let's also find all of the events that match on other criteria!
        // What is interesting here is that we no longer have to worry about the event's releasability. With attributes this was a different case,
        // because we might run into a situation where a user can see an event but not a specific attribute
        // returning a hit on such an attribute would allow users to enumerate hidden attributes
        // For anything beyond this point the default pagination restrictions will apply!

        // First of all, there are tags that might be interesting for us
        $subconditions = [];
        foreach ($values as $v) {
            $subconditions[] = ['lower(name) LIKE' => $v];
        }
        $tags = $this->Events->EventTag->Tag->find(
            'all',
            [
                'conditions' => $subconditions,
                'fields' => ['id'],
                'contain' => ['EventTag' => ['fields' => 'event_id'], 'AttributeTag' => ['fields' => 'event_id']],
            ]
        );
        foreach ($tags as $tag) {
            foreach ($tag['EventTag'] as $eventTag) {
                if (!in_array($eventTag['event_id'], $result)) {
                    $result[] = $eventTag['event_id'];
                }
            }
            foreach ($tag['AttributeTag'] as $attributeTag) {
                if (!in_array($attributeTag['event_id'], $result)) {
                    $result[] = $attributeTag['event_id'];
                }
            }
        }

        // Finally, let's search on the event metadata!
        $subconditions = [];
        foreach ($values as $v) {
            $subconditions[] = ['lower(name) LIKE' => $v];
        }
        $orgs = $this->Events->Org->find(
            'column',
            [
                'conditions' => $subconditions,
                'fields' => ['Org.id']
            ]
        );

        $conditions = empty($result) ? [] : ['NOT' => ['id' => $result]]; // Do not include events that we already found
        foreach ($values as $v) {
            $conditions['OR'][] = ['lower(info) LIKE' => $v];
            $conditions['OR'][] = ['lower(uuid) LIKE' => $v];
        }
        if (!empty($orgs)) {
            $conditions['OR']['orgc_id'] = $orgs;
        }
        $otherEvents = $this->Events->find(
            'column',
            [
                'fields' => ['id'],
                'conditions' => $conditions,
            ]
        );
        foreach ($otherEvents as $eventId) {
            $result[] = $eventId;
        }
        return $result;
    }

    /**
     * @param array $passedArgs
     * @param string $urlparams
     * @param bool $nothing True when nothing should be fetched from database
     * @return array
     */
    private function __setIndexFilterConditions(array $passedArgs, &$urlparams, &$nothing = false)
    {
        $passedArgsArray = [];
        foreach ($passedArgs as $k => $v) {
            if (substr($k, 0, 6) !== 'search') {
                continue;
            }
            if (!is_array($v)) {
                if ($urlparams != "") {
                    $urlparams .= "/";
                }
                $urlparams .= $k . ":" . $v;
            }
            $searchTerm = strtolower(substr($k, 6));
            switch ($searchTerm) {
                case 'all':
                    if (!empty($v)) {
                        $this->paginate['conditions']['AND'][] = ['id' => $this->__quickFilter($v)];
                    }
                    break;
                case 'attribute':
                    $event_id_arrays = $this->__filterOnAttributeValue($v);
                    if (!empty($event_id_arrays[0])) {
                        $this->paginate['conditions']['AND'][] = ['id' => $event_id_arrays[0]];
                    }
                    if (!empty($event_id_arrays[1])) {
                        $this->paginate['conditions']['AND'][] = ['id !=' => $event_id_arrays[1]];
                    }
                    break;
                case 'published':
                    if ($v === 2 || $v === '2') { // both
                        continue 2;
                    }
                    if (is_array($v) && in_array(0, $v) && in_array(1, $v)) {
                        continue 2; // both
                    }
                    $this->paginate['conditions']['AND'][] = ['Events.published' => $v];
                    break;
                case 'hasproposal':
                    if ($v === 2 || $v === '2') { // both
                        continue 2;
                    }
                    $proposalQuery = "exists (select id, deleted from shadow_attributes where shadow_attributes.event_id = Events.id and shadow_attributes.deleted = 0)";
                    if ($v == 0) {
                        $proposalQuery = 'not ' . $proposalQuery;
                    }
                    $this->paginate['conditions']['AND'][] = $proposalQuery;
                    break;
                case 'eventid':
                    if ($v == "") {
                        continue 2;
                    }
                    $pieces = is_array($v) ? $v : explode('|', $v);
                    $eventidConditions = [];
                    foreach ($pieces as $piece) {
                        $piece = trim($piece);
                        if ($piece[0] === '!') {
                            if (strlen($piece) === 37) {
                                $eventidConditions['NOT']['uuid'][] = substr($piece, 1);
                            } else {
                                $eventidConditions['NOT']['id'][] = substr($piece, 1);
                            }
                        } else {
                            if (strlen($piece) === 36) {
                                $eventidConditions['OR']['uuid'][] = $piece;
                            } else {
                                $eventidConditions['OR']['id'][] = $piece;
                            }
                        }
                    }
                    foreach ($eventidConditions as $operator => $conditionForOperator) {
                        foreach ($conditionForOperator as $conditionKey => $conditionValue) {
                            $lookupKey = 'Events.' . $conditionKey;
                            if ($operator === 'NOT') {
                                $lookupKey = $lookupKey . ' !=';
                            }
                            $this->paginate['conditions']['AND'][] = [$lookupKey => $conditionValue];
                        }
                    }
                    break;
                case 'datefrom':
                    if ($v == "") {
                        continue 2;
                    }
                    $this->paginate['conditions']['AND'][] = ['Events.date >=' => $v];
                    break;
                case 'dateuntil':
                    if ($v == "") {
                        continue 2;
                    }
                    $this->paginate['conditions']['AND'][] = ['Events.date <=' => $v];
                    break;
                case 'timestamp':
                    if ($v == "") {
                        continue 2;
                    }
                    if (is_array($v) && isset($v[0]) && isset($v[1])) {
                        if (!is_int($v[0])) {
                            $v[0] = $this->Events->resolveTimeDelta($v[0]);
                        }
                        if (!is_int($v[1])) {
                            $v[1] = $this->Events->resolveTimeDelta($v[1]);
                        }
                        $this->paginate['conditions']['AND'][] = ['Events.timestamp >=' => $v[0]];
                        $this->paginate['conditions']['AND'][] = ['Events.timestamp <=' => $v[1]];
                    } else {
                        if (!is_int($v)) {
                            $v = $this->Events->resolveTimeDelta($v);
                        }
                        $this->paginate['conditions']['AND'][] = ['Events.timestamp >=' => $v];
                    }
                    break;
                case 'publish_timestamp':
                case 'publishtimestamp':
                    if ($v == "") {
                        continue 2;
                    }
                    if (is_array($v) && isset($v[0]) && isset($v[1])) {
                        if (!is_int($v[0])) {
                            $v[0] = $this->Events->resolveTimeDelta($v[0]);
                        }
                        if (!is_int($v[1])) {
                            $v[1] = $this->Events->resolveTimeDelta($v[1]);
                        }
                        $this->paginate['conditions']['AND'][] = ['Events.publish_timestamp >=' => $v[0]];
                        $this->paginate['conditions']['AND'][] = ['Events.publish_timestamp <=' => $v[1]];
                    } else {
                        if (!is_int($v)) {
                            $v = $this->Events->resolveTimeDelta($v);
                        }
                        $this->paginate['conditions']['AND'][] = ['Events.publish_timestamp >=' => $v];
                    }
                    break;
                case 'org':
                    if ($v == "" || !Configure::read('MISP.showorg')) {
                        continue 2;
                    }

                    $this->Events->Org->virtualFields = [
                        'upper_name' => 'UPPER(name)',
                        'lower_uuid' => 'LOWER(uuid)',
                    ];
                    $orgs = array_column(
                        $this->Events->Org->find(
                            'all',
                            [
                                'fields' => ['Org.id', 'Org.upper_name', 'Org.lower_uuid'],
                                'recursive' => -1,
                            ]
                        ),
                        'Org'
                    );
                    $this->Events->Org->virtualFields = [];
                    $orgByName = array_column($orgs, 'id', 'upper_name');
                    $orgByUuid = array_column($orgs, 'id', 'lower_uuid');
                    // if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
                    $pieces = is_array($v) ? $v : explode('|', $v);
                    $test = [];
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            $piece = substr($piece, 1); // remove `!` char
                            if (is_numeric($piece)) {
                                $orgId = $piece;
                            } else if (Validation::uuid($piece)) {
                                $orgId = isset($orgByUuid[$piece]) ? $orgByUuid[$piece] : null;
                            } else {
                                $orgName = mb_strtoupper($piece);
                                $orgId = isset($orgByName[$orgName]) ? $orgByName[$orgName] : null;
                            }
                            if ($orgId) {
                                $this->paginate['conditions']['AND'][] = ['Events.orgc_id !=' => $orgId];
                            }
                        } else {
                            if (is_numeric($piece)) {
                                $test['OR'][] = ['Events.orgc_id' => $piece];
                            } else {
                                if (Validation::uuid($piece)) {
                                    $orgId = isset($orgByUuid[$piece]) ? $orgByUuid[$piece] : null;
                                } else {
                                    $orgName = mb_strtoupper($piece);
                                    $orgId = isset($orgByName[$orgName]) ? $orgByName[$orgName] : null;
                                }
                                if ($orgId) {
                                    $test['OR'][] = ['Events.orgc_id' => $orgId];
                                } else {
                                    $nothing = true;
                                }
                            }
                        }
                    }
                    $this->paginate['conditions']['AND'][] = $test;
                    break;
                case 'sharinggroup':
                    $pieces = explode('|', $v);
                    $test = [];
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            $this->paginate['conditions']['AND'][] = ['Events.sharing_group_id !=' => substr($piece, 1)];
                        } else {
                            $test['OR'][] = ['Events.sharing_group_id' => $piece];
                        }
                    }
                    if (!empty($test)) {
                        $this->paginate['conditions']['AND'][] = $test;
                    }
                    break;
                case 'eventinfo':
                    if ($v == "") {
                        continue 2;
                    }
                    // if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
                    $pieces = explode('|', $v);
                    $test = [];
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            $this->paginate['conditions']['AND'][] = ['lower(Events.info) NOT LIKE' => '%' . mb_strtolower(substr($piece, 1)) . '%'];
                        } else {
                            $test['OR'][] = ['lower(Events.info) LIKE' => '%' . mb_strtolower($piece) . '%'];
                        }
                    }
                    $this->paginate['conditions']['AND'][] = $test;
                    break;
                case 'tag':
                case 'tags':
                    if (!$v || !Configure::read('MISP.tagging') || $v === 0) {
                        continue 2;
                    }
                    $pieces = is_array($v) ? $v : explode('|', $v);
                    $filterString = "";
                    $expectOR = false;
                    $tagRules = [];
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            if (is_numeric(substr($piece, 1))) {
                                $conditions = ['Tag.id' => substr($piece, 1)];
                            } else {
                                $conditions = ['Tag.name' => substr($piece, 1)];
                            }
                            $tagName = $this->Events->EventTag->Tag->find(
                                'all',
                                [
                                    'conditions' => $conditions,
                                    'fields' => ['id', 'name'],
                                    'recursive' => -1,
                                ]
                            )->first();

                            if (empty($tagName)) {
                                if ($filterString != "") {
                                    $filterString .= "|";
                                }
                                $filterString .= '!' . $piece;
                                continue;
                            }
                            $tagRules['block'][] = $tagName['Tag']['id'];
                            if ($filterString != "") {
                                $filterString .= "|";
                            }
                            $filterString .= '!' . $tagName['Tag']['name'];
                        } else {
                            $expectOR = true;
                            if (is_numeric($piece)) {
                                $conditions = ['Tag.id' => $piece];
                            } else {
                                $conditions = ['Tag.name' => $piece];
                            }
                            $tagName = $this->Events->EventTag->Tag->find(
                                'all',
                                [
                                    'conditions' => $conditions,
                                    'fields' => ['id', 'name'],
                                    'recursive' => -1,
                                ]
                            )->first();
                            if (empty($tagName)) {
                                if ($filterString != "") {
                                    $filterString .= "|";
                                }
                                $filterString .= $piece;
                                continue;
                            }
                            $tagRules['include'][] = $tagName['Tag']['id'];
                            if ($filterString != "") {
                                $filterString .= "|";
                            }
                            $filterString .= $tagName['Tag']['name'];
                        }
                    }

                    if (!empty($tagRules['block'])) {
                        $block = $this->Events->EventTag->find(
                            'column',
                            [
                                'conditions' => ['EventTag.tag_id' => $tagRules['block']],
                                'fields' => ['EventTag.event_id'],
                            ]
                        );
                        if (!empty($block)) {
                            $this->paginate['conditions']['AND'][] = 'id NOT IN (' . implode(",", $block) . ')';
                        }
                    }

                    if (!empty($tagRules['include'])) {
                        $include = $this->Events->EventTag->find(
                            'column',
                            [
                                'conditions' => ['EventTag.tag_id' => $tagRules['include']],
                                'fields' => ['EventTag.event_id'],
                            ]
                        );
                        if (!empty($include)) {
                            $this->paginate['conditions']['AND'][] = 'id IN (' . implode(",", $include) . ')';
                        } else {
                            $nothing = true;
                        }
                    } else if ($expectOR) {
                        // If we have a list of OR-d arguments, we expect to end up with a list of allowed event IDs
                        // If we don't however, it means that none of the tags was found. To prevent displaying the entire event index in this case:
                        $nothing = true;
                    }

                    $v = $filterString;
                    break;
                case 'email':
                    if ($v == "") {
                        continue 2;
                    }

                    if (!$this->isSiteAdmin()) {
                        // Special case to filter own events
                        if (strtolower($this->ACL->getUser()['email']) === strtolower(trim($v))) {
                            $this->paginate['conditions']['AND'][] = ['Events.user_id' => $this->ACL->getUser()['id']];
                            break;
                        } else {
                            $nothing = true;
                            continue 2;
                        }
                    }

                    // if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
                    $pieces = explode('|', $v);
                    $usersToMatch = [];
                    $positiveQuery = false;
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            $users = $this->Events->User->find(
                                'column',
                                [
                                    'fields' => ['User.id'],
                                    'conditions' => ['User.email LIKE' => '%' . strtolower(substr($piece, 1)) . '%']
                                ]
                            );
                            if (!empty($users)) {
                                $this->paginate['conditions']['AND'][] = ['Events.user_id !=' => $users];
                            }
                        } else {
                            $positiveQuery = true;
                            $users = $this->Events->User->find(
                                'column',
                                [
                                    'fields' => ['User.id'],
                                    'conditions' => ['User.email LIKE' => '%' . strtolower($piece) . '%']
                                ]
                            );
                            $usersToMatch = array_merge($usersToMatch, $users);
                        }
                    }

                    if ($positiveQuery) {
                        if (empty($usersToMatch)) {
                            $nothing = true;
                        } else {
                            $this->paginate['conditions']['AND'][] = ['Events.user_id' => array_unique($usersToMatch, SORT_REGULAR)];
                        }
                    }
                    break;
                case 'distribution':
                case 'analysis':
                case 'threatlevel':
                    if ($v == "") {
                        continue 2;
                    }
                    $filterString = "";
                    $searchTermInternal = $searchTerm;
                    if ($searchTerm === 'threatlevel') {
                        $searchTermInternal = 'threat_level_id';
                        $terms = $this->Events->ThreatLevel->listThreatLevels();
                    } elseif ($searchTerm === 'analysis') {
                        $terms = $this->Events->analysisLevels;
                    } else {
                        $terms = $this->Events->distributionLevels;
                    }
                    $pieces = is_array($v) ? $v : explode('|', $v);
                    $test = [];
                    foreach ($pieces as $piece) {
                        if ($filterString != "") {
                            $filterString .= '|';
                        }
                        if ($piece[0] === '!') {
                            $filterString .= $terms[substr($piece, 1)];
                            $this->paginate['conditions']['AND'][] = ['Events.' . $searchTermInternal . ' !=' => substr($piece, 1)];
                        } else {
                            $filterString .= $terms[$piece];
                            $test['OR'][] = ['Events.' . $searchTermInternal => $piece];
                        }
                    }
                    $this->paginate['conditions']['AND'][] = $test;
                    $v = $filterString;
                    break;
                case 'minimal':
                    $tableName = $this->Events->EventReport->table;
                    $eventReportQuery = sprintf('EXISTS (SELECT id FROM %s WHERE %s.event_id = Events.id AND %s.deleted = 0)', $tableName, $tableName, $tableName);
                    $this->paginate['conditions']['AND'][] = [
                        'OR' => [
                            ['Events.attribute_count >' => 0],
                            [$eventReportQuery]
                        ]
                    ];
                    break;
                case 'value':
                    if ($v == "") {
                        continue 2;
                    }
                    $conditions['OR'] = [
                        ['Attribute.value1' => $v],
                        ['Attribute.value2' => $v],
                    ];

                    $eventIds = $this->Events->Attributes->fetchAttributes(
                        $this->ACL->getUser()->toArray(),
                        [
                            'conditions' => $conditions,
                            'flatten' => true,
                            'event_ids' => true,
                            'list' => true,
                        ]
                    );

                    $this->paginate['conditions']['AND'][] = ['id' => $eventIds];

                    break;
                default:
                    continue 2;
            }
            $passedArgsArray[$searchTerm] = $v;
        }
        return $passedArgsArray;
    }

    public function index()
    {
        // list the events
        $urlparams = "";
        $overrideAbleParams = ['all', 'attribute', 'published', 'eventid', 'datefrom', 'dateuntil', 'org', 'eventinfo', 'tag', 'tags', 'distribution', 'sharinggroup', 'analysis', 'threatlevel', 'email', 'hasproposal', 'timestamp', 'publishtimestamp', 'publish_timestamp', 'minimal', 'value'];
        $paginationParams = ['limit', 'page', 'sort', 'direction', 'order'];
        $passedArgs = $this->request->getQueryParams();
        $data = $this->request->getData();
        if (!empty($data)) {
            if (isset($data['request'])) {
                $data = $data['request'];
            }
            foreach ($data as $k => $v) {
                if (substr($k, 0, 6) === 'search' && in_array(strtolower(substr($k, 6)), $overrideAbleParams, true)) {
                    unset($data[$k]);
                    $data[strtolower(substr($k, 6))] = $v;
                } else if (in_array(strtolower($k), $overrideAbleParams, true)) {
                    unset($data[$k]);
                    $data[strtolower($k)] = $v;
                }
            }
            foreach ($overrideAbleParams as $oap) {
                if (isset($data[$oap])) {
                    $passedArgs['search' . $oap] = $data[$oap];
                }
            }
            foreach ($paginationParams as $paginationParam) {
                if (isset($data[$paginationParam])) {
                    $passedArgs[$paginationParam] = $data[$paginationParam];
                }
            }
        }

        // check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
        $nothing = false;
        $passedArgsArray = $this->__setIndexFilterConditions($passedArgs, $urlparams, $nothing);

        // for REST, don't use the pagination. With this, we'll escape the limit of events shown on the index.
        if ($this->ParamHandler->isRest()) {
            if ($nothing) {
                return $this->RestResponse->viewData([], $this->response->getType(), false, false, false, ['X-Result-Count' => 0]);
            }
            return $this->__indexRestResponse($passedArgs);
        }

        $this->paginate['contain']['ThreatLevel'] = [
            'fields' => ['ThreatLevel.name']
        ];
        $this->paginate['contain']['EventTag'] = [
            'fields' => ['EventTag.event_id', 'EventTag.tag_id', 'EventTag.local', 'EventTag.relationship_type'],
        ];
        if ($this->isSiteAdmin()) {
            $this->paginate['contain'][] = 'User.email';
        }

        if ($nothing) {
            $this->paginate['conditions']['AND'][] = ['id' => -1]; // do not fetch any event
        }

        $events = $this->paginate();

        if (count($events) === 1 && isset($this->passedArgs['searchall'])) {
            $this->redirect(['controller' => 'events', 'action' => 'view', $events[0]['Event']['id']]);
        }

        list($possibleColumns, $enabledColumns) = $this->__indexColumns();
        $events = $this->__attachInfoToEvents($enabledColumns, $events->toArray());

        $this->__noKeyNotification();
        $this->set('events', $events);
        $this->set('possibleColumns', $possibleColumns);
        $this->set('columns', $enabledColumns);
        $this->set('eventDescriptions', $this->Events->fieldDescriptions);
        $this->set('analysisLevels', $this->Events->analysisLevels);
        $this->set('distributionLevels', $this->Events->distributionLevels);
        $this->set('shortDist', $this->Events->shortDist);
        $this->set('distributionData', $this->__genDistributionGraph(-1));
        $this->set('urlparams', $urlparams);
        $this->set('passedArgsArray', $passedArgsArray);
        $this->set('passedArgs', json_encode($passedArgs));

        if ($this->request->is('ajax')) {
            $this->autoRender = false;
            $this->layout = false;
            $this->render('ajax/index');
        }
    }

    /**
     * @param array $passedArgs
     * @return Response
     */
    private function __indexRestResponse(array $passedArgs)
    {
        // We do not want to allow instances to pull our data that can't make sense of protected mode events
        $skipProtected = (
            !empty($this->request->getHeaders()['misp-version']) &&
            version_compare($this->request->header('misp-version'), '2.4.156') < 0
        );

        $fieldNames = array_flip($this->Events->getSchema()->columns());
        $minimal = !empty($passedArgs['searchminimal']) || !empty($passedArgs['minimal']);
        if ($minimal) {
            $rules = [
                'recursive' => -1,
                'fields' => ['id', 'timestamp', 'sighting_timestamp', 'published', 'uuid', 'protected'],
                'contain' => ['Orgc.uuid'],
            ];
        } else {
            // Remove user ID from fetched fields
            unset($fieldNames['user_id']);
            $rules = [
                'contain' => ['EventTags'],
                'fields' => array_keys($fieldNames),
            ];
        }
        if (isset($passedArgs['sort']) && isset($fieldNames[$passedArgs['sort']])) {
            if (isset($passedArgs['direction']) && in_array(strtoupper($passedArgs['direction']), ['ASC', 'DESC'])) {
                $rules['order'] = ['Events.' . $passedArgs['sort'] => $passedArgs['direction']];
            } else {
                $rules['order'] = ['Events.' . $passedArgs['sort'] => 'ASC'];
            }
        }
        if (isset($this->paginate['conditions'])) {
            $rules['conditions'] = $this->paginate['conditions'];
        }
        if ($skipProtected) {
            $rules['conditions']['Events.protected'] = 0;
        }
        $paginationRules = ['page', 'limit', 'sort', 'direction', 'order'];
        foreach ($paginationRules as $paginationRule) {
            if (isset($passedArgs[$paginationRule])) {
                $rules[$paginationRule] = $passedArgs[$paginationRule];
            }
        }

        if (empty($rules['limit'])) {
            $events = [];
            $i = 1;
            $rules['limit'] = 20000;
            while (true) {
                $rules['page'] = $i++;
                $temp = $this->Events->find('all', $rules);
                $resultCount = $temp->count();
                if ($resultCount !== 0) {
                    array_push($events, ...$temp);
                }
                if ($resultCount < $rules['limit']) {
                    break;
                }
            }
            unset($temp);
            $absoluteTotal = count($events);
        } else {
            $counting_rules = $rules;
            unset($counting_rules['limit']);
            unset($counting_rules['page']);
            $absoluteTotal = $this->Events->find('count', $counting_rules);

            $events = $absoluteTotal === 0 ? [] : $this->Events->find('all', $rules);
        }

        $isCsvResponse = $this->response->getType() === 'text/csv';

        $protectedEventsByInstanceKey = $this->Events->CryptographicKeys->protectedEventsByInstanceKey($events);
        $protectedEventsByInstanceKey = array_flip($protectedEventsByInstanceKey);

        if (!$minimal) {
            // Collect all tag IDs that are events
            $tagIds = [];
            foreach (array_column($events, 'EventTag') as $eventTags) {
                foreach (array_column($eventTags, 'tag_id') as $tagId) {
                    $tagIds[$tagId] = true;
                }
            }

            if (!empty($tagIds)) {
                $tags = $this->Events->EventTags->Tags->find(
                    'all',
                    [
                        'conditions' => [
                            'Tag.id' => array_keys($tagIds),
                            'Tag.exportable' => 1,
                        ],
                        'recursive' => -1,
                        'fields' => ['Tag.id', 'Tag.name', 'Tag.colour', 'Tag.is_galaxy'],
                    ]
                );
                unset($tagIds);
                $tags = array_column(array_column($tags, 'Tag'), null, 'id');

                foreach ($events as $k => $event) {
                    if (empty($event['EventTag'])) {
                        continue;
                    }
                    foreach ($event['EventTag'] as $k2 => $et) {
                        if (!isset($tags[$et['tag_id']])) {
                            unset($events[$k]['EventTag'][$k2]); // tag not exists or is not exportable
                        } else {
                            $events[$k]['EventTag'][$k2]['Tag'] = $tags[$et['tag_id']];
                        }
                    }
                    $events[$k]['EventTag'] = array_values($events[$k]['EventTag']);
                }
                if (!$isCsvResponse) {
                    $events = $this->GalaxyCluster->attachClustersToEventIndex($this->ACL->getUser()->toArray(), $events, false);
                }
            }

            // Fetch all org and sharing groups that are in events
            $orgIds = [];
            $sharingGroupIds = [];
            foreach ($events as $k => $event) {
                $orgIds[$event['org_id']] = true;
                $orgIds[$event['orgc_id']] = true;
                $sharingGroupIds[$event['sharing_group_id']] = true;
                if ($event['protected'] && !isset($protectedEventsByInstanceKey[$event['id']])) {
                    unset($events[$k]);
                }
            }
            $events = array_values($events);
            if (!empty($orgIds)) {
                $orgs = $this->Events->Org->find(
                    'all',
                    [
                        'conditions' => ['Org.id IN' => array_keys($orgIds)],
                        'recursive' => -1,
                        'fields' => $this->paginate['contain']['Org']['fields'],
                    ]
                )->toArray();
                unset($orgIds);
                $orgs = array_column($orgs, null, 'id');
            } else {
                $orgs = [];
            }
            unset($sharingGroupIds[0]);
            if (!empty($sharingGroupIds)) {
                $sharingGroups = $this->Events->SharingGroup->find(
                    'all',
                    [
                        'conditions' => ['SharingGroup.id' => array_keys($sharingGroupIds)],
                        'recursive' => -1,
                        'fields' => $this->paginate['contain']['SharingGroup']['fields'],
                    ]
                );
                unset($sharingGroupIds);
                $sharingGroups = array_column(array_column($sharingGroups, 'SharingGroup'), null, 'id');
            }
            foreach ($events as $key => $event) {
                $temp = $event;
                $temp['Org'] = $orgs[$temp['org_id']];
                $temp['Orgc'] = $orgs[$temp['orgc_id']];
                if ($temp['sharing_group_id'] != 0) {
                    $temp['SharingGroup'] = $sharingGroups[$temp['sharing_group_id']];
                }
                $rearrangeObjects = ['GalaxyCluster', 'EventTag'];
                foreach ($rearrangeObjects as $ro) {
                    if (isset($event[$ro])) {
                        $temp[$ro] = $event[$ro];
                    }
                }
                $events[$key] = $temp;
            }
            unset($sharingGroups);
            unset($orgs);
            if ($this->response->getType() === 'application/xml') {
                $events = ['Event' => $events];
            }
        } else { // minimal
            foreach ($events as $key => $event) {
                if ($event['protected'] && !isset($protectedEventsByInstanceKey[$event['id']])) {
                    unset($events[$key]);
                    continue;
                }
                $event['orgc_uuid'] = $event['Orgc']['uuid'];
                unset($event['protected']);
                $events[$key] = $event;
            }
            $events = array_values($events);
        }

        if ($isCsvResponse) {
            $export = new CsvExport();
            $events = $export->eventIndex($events);
        }

        return $this->RestResponse->viewData($events, $this->response->getType(), false, false, false, ['X-Result-Count' => $absoluteTotal]);
    }

    private function __indexColumns()
    {
        $possibleColumns = [];

        if ($this->isSiteAdmin() && !Configure::read('MISP.showorgalternate')) {
            $possibleColumns[] = 'owner_org';
        }

        if (Configure::read('MISP.tagging')) {
            $possibleColumns[] = 'clusters';
            $possibleColumns[] = 'tags';
        }

        $possibleColumns[] = 'attribute_count';

        if (Configure::read('MISP.showCorrelationsOnIndex')) {
            $possibleColumns[] = 'correlations';
        }

        if (Configure::read('MISP.showEventReportCountOnIndex')) {
            $possibleColumns[] = 'report_count';
        }

        if (Configure::read('MISP.showSightingsCountOnIndex')) {
            $possibleColumns[] = 'sightings';
        }

        if (Configure::read('MISP.showProposalsCountOnIndex')) {
            $possibleColumns[] = 'proposals';
        }

        if (Configure::read('MISP.showDiscussionsCountOnIndex') && !Configure::read('MISP.discussion_disable')) {
            $possibleColumns[] = 'discussion';
        }

        if ($this->isSiteAdmin()) {
            $possibleColumns[] = 'creator_user';
        }

        $possibleColumns[] = 'timestamp';
        $possibleColumns[] = 'publish_timestamp';

        $userDisabledColumns = $this->User->UserSetting->getValueForUser($this->ACL->getUser()->toArray()['id'], 'event_index_hide_columns');
        if ($userDisabledColumns === null) {
            $userDisabledColumns = self::DEFAULT_HIDDEN_INDEX_COLUMNS;
        }

        $enabledColumns = array_diff($possibleColumns, $userDisabledColumns);

        return [$possibleColumns, $enabledColumns];
    }

    private function __attachInfoToEvents(array $columns, array $events)
    {
        if (empty($events)) {
            return [];
        }

        $user = $this->ACL->getUser()->toArray();

        if (in_array('tags', $columns, true) || in_array('clusters', $columns, true)) {
            $events = $this->Events->attachTagsToEvents($events);
            $events = $this->GalaxyCluster->attachClustersToEventIndex($user, $events, true);
            $events = $this->__attachHighlightedTagsToEvents($events);
        }

        if (in_array('correlations', $columns, true)) {
            $events = $this->Events->attachCorrelationCountToEvents($user, $events);
        }

        if (in_array('sightings', $columns, true)) {
            $events = $this->Events->attachSightingsCountToEvents($user, $events);
        }

        if (in_array('proposals', $columns, true)) {
            $events = $this->Events->attachProposalsCountToEvents($user, $events);
        }

        if (in_array('discussion', $columns, true) && !Configure::read('MISP.discussion_disable')) {
            $events = $this->Events->attachDiscussionsCountToEvents($user, $events);
        }

        if (in_array('report_count', $columns, true)) {
            $events = $this->Events->EventReport->attachReportCountsToEvents($user, $events);
        }

        return $events;
    }

    private function __noKeyNotification()
    {
        $onlyEncrypted = Configure::read('GnuPG.onlyencrypted');
        $bodyOnlyEncrypted = Configure::read('GnuPG.bodyonlyencrypted');
        if (!$onlyEncrypted && !$bodyOnlyEncrypted) {
            return;
        }

        $user = $this->Events->User->fillKeysToUser($this->ACL->getUser()->toArray());
        if (!empty($user['gpgkey'])) {
            return; // use has PGP key
        }

        if ($onlyEncrypted) {
            if (Configure::read('SMIME.enabled') && empty($user['certif_public'])) {
                $this->Flash->info(__('No X.509 certificate or PGP key set in your profile. To receive emails, submit your public certificate or PGP key in your profile.'));
            } elseif (!Configure::read('SMIME.enabled')) {
                $this->Flash->info(__('No PGP key set in your profile. To receive emails, submit your public key in your profile.'));
            }
        } elseif ($bodyOnlyEncrypted && $user['autoalert']) {
            if (Configure::read('SMIME.enabled') && empty($user['certif_public'])) {
                $this->Flash->info(__('No X.509 certificate or PGP key set in your profile. To receive attributes in emails, submit your public certificate or PGP key in your profile.'));
            } elseif (!Configure::read('SMIME.enabled')) {
                $this->Flash->info(__('No PGP key set in your profile. To receive attributes in emails, submit your public key in your profile.'));
            }
        }
    }

    public function filterEventIndex()
    {
        $passedArgsArray = [];
        $filtering = [
            'published' => 2,
            'org' => ['OR' => [], 'NOT' => []],
            'tag' => ['OR' => [], 'NOT' => []],
            'eventid' => ['OR' => [], 'NOT' => []],
            'date' => ['from' => "", 'until' => ""],
            'eventinfo' => ['OR' => [], 'NOT' => []],
            'all' => ['OR' => [], 'NOT' => []],
            'threatlevel' => ['OR' => [], 'NOT' => []],
            'distribution' => ['OR' => [], 'NOT' => []],
            'sharinggroup' => ['OR' => [], 'NOT' => []],
            'analysis' => ['OR' => [], 'NOT' => []],
            'attribute' => ['OR' => [], 'NOT' => []],
            'hasproposal' => 2,
            'timestamp' => ['from' => "", 'until' => ""],
            'publishtimestamp' => ['from' => "", 'until' => ""]
        ];

        if ($this->isSiteAdmin()) {
            $filtering['email'] = ['OR' => [], 'NOT' => []];
        }

        foreach ($this->passedArgs as $k => $v) {
            if (substr($k, 0, 6) === 'search') {
                $searchTerm = substr($k, 6);
                switch ($searchTerm) {
                    case 'published':
                    case 'hasproposal':
                        $filtering[$searchTerm] = $v;
                        break;
                    case 'Datefrom':
                        $filtering['date']['from'] = $v;
                        break;
                    case 'Dateuntil':
                        $filtering['date']['until'] = $v;
                        break;
                    case 'email':
                    case 'org':
                    case 'eventid':
                    case 'tag':
                    case 'eventinfo':
                    case 'attribute':
                    case 'threatlevel':
                    case 'distribution':
                    case 'sharinggroup':
                    case 'analysis':
                        if ($v == "" || ($searchTerm == 'email' && !$this->isSiteAdmin())) {
                            continue 2;
                        }
                        $pieces = explode('|', $v);
                        foreach ($pieces as $piece) {
                            if ($piece[0] == '!') {
                                $filtering[$searchTerm]['NOT'][] = substr($piece, 1);
                            } else {
                                $filtering[$searchTerm]['OR'][] = $piece;
                            }
                        }
                        break;
                }
                $passedArgsArray[$searchTerm] = $v;
            }
        }
        $this->set('filtering', json_encode($filtering));

        $tagNames = $this->Events->EventTag->Tag->find(
            'list',
            [
                'fields' => ['Tag.id', 'Tag.name'],
            ]
        );
        $tagJSON = [];
        foreach ($tagNames as $tagId => $tagName) {
            $tagJSON[] = ['id' => $tagId, 'value' => $tagName];
        }

        $rules = [
            'published' => __('Published'),
            'eventid' => __('Event ID'),
            'tag' => __('Tag'),
            'date' => __('Date'),
            'eventinfo' => __('Event info'),
            'threatlevel' => __('Threat level'),
            'distribution' => __('Distribution'),
            'sharinggroup' => __('Sharing group'),
            'analysis' => __('Analysis'),
            'attribute' => __('Attribute'),
            'hasproposal' => __('Has proposal'),
            'timestamp' => __('Last change at'),
            'publishtimestamp' => __('Published at'),
            'all' => __('Search in all fields'),
        ];

        if ($this->isSiteAdmin()) {
            $rules['email'] = __('Email');
        }
        if (Configure::read('MISP.showorg')) {
            $orgs = $this->Events->Orgc->find(
                'list',
                [
                    'fields' => ['Orgc.id', 'Orgc.name'],
                    'sort' => ['lower(Orgc.name) asc']
                ]
            );
            $this->set('showorg', true);
            $this->set('orgs', $orgs);
            $rules['org'] = __('Organisation');
        } else {
            $this->set('showorg', false);
        }
        $sharingGroups = $this->Events->SharingGroup->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'name', true);
        $this->set('sharingGroups', $sharingGroups);
        $this->set('tags', $tagNames);
        $this->set('tagJSON', json_encode($tagJSON));
        $this->set('rules', $rules);
        $this->layout = false;
    }

    public function viewEventAttributes($id, $all = false)
    {
        $filterData = [
            'paramArray' => self::ACCEPTED_FILTERING_NAMED_PARAMS,
            'named_params' => $this->params['named']
        ];
        $filters = $this->harvestParameters($filterData, $exception);
        if ($exception) {
            return $exception;
        }

        // Remove default filters
        foreach ($filters as $filterName => $filterValue) {
            if (isset(self::DEFAULT_FILTERING_RULE[$filterName]) && self::DEFAULT_FILTERING_RULE[$filterName] == $filterValue) {
                unset($filters[$filterName]);
            }
        }

        if (isset($filters['focus'])) {
            $this->set('focus', $filters['focus']);
        }
        $conditions = [
            'eventid' => $id,
            'includeFeedCorrelations' => true,
            'includeWarninglistHits' => true,
            'fetchFullClusters' => false,
            'includeAllTags' => true,
            'includeGranularCorrelations' => true,
            'includeEventCorrelations' => true, // event correlations are need for filtering
            'noEventReports' => true, // event reports for view are loaded dynamically
            'noSightings' => true,
            'includeServerCorrelations' => $filters['includeServerCorrelations'] ?? 1,
        ];
        if (isset($filters['extended'])) {
            $conditions['extended'] = 1;
            $this->set('extended', 1);
        } else {
            $this->set('extended', 0);
        }
        if (!empty($filters['overrideLimit'])) {
            $conditions['overrideLimit'] = 1;
        }
        if (isset($filters['deleted'])) {
            if ($filters['deleted'] == 1) { // both
                $conditions['deleted'] = [0, 1];
            } elseif ($filters['deleted'] == 0) { // not-deleted only (default)
                $conditions['deleted'] = 0;
            } else { // only deleted
                $conditions['deleted'] = 1;
            }
        }
        if (isset($filters['toIDS']) && $filters['toIDS'] != 0) {
            $conditions['to_ids'] = $filters['toIDS'] == 2 ? 0 : 1;
        }
        if (!empty($filters['includeRelatedTags'])) {
            $this->set('includeRelatedTags', 1);
            $conditions['includeRelatedTags'] = 1;
        } else {
            $this->set('includeRelatedTags', 0);
        }
        if (!empty($filters['includeDecayScore'])) {
            $this->set('includeDecayScore', 1);
            $conditions['includeDecayScore'] = 1;
        } else {
            $this->set('includeDecayScore', 0);
        }

        // Site admin can view event as different user
        if ($this->isSiteAdmin() && isset($this->params['named']['viewAs'])) {
            $user = $this->User->getAuthUser($this->params['named']['viewAs']);
            if (empty($user)) {
                throw new NotFoundException(__("User not found"));
            }
        } else {
            $user = $this->ACL->getUser()->toArray();
        }

        $results = $this->Events->fetchEvent($user, $conditions);
        if (empty($results)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $event = $results[0];

        $emptyEvent = empty($event['Object']) && empty($event['Attribute']);
        $this->set('emptyEvent', $emptyEvent);

        $attributeTagsName = $this->Events->Attributes->AttributeTag->extractAttributeTagsNameFromEvent($event);
        $this->set('attributeTags', array_values($attributeTagsName['tags']));
        $this->set('attributeClusters', array_values($attributeTagsName['clusters']));

        if (isset($filters['distribution'])) {
            if (!is_array($filters['distribution'])) {
                $filters['distribution'] = [$filters['distribution']];
            }
            $temp = implode('|', $filters['distribution']);
            $this->__applyQueryString($event, $temp, 'distribution');
        }
        if (isset($filters['searchFor']) && $filters['searchFor'] !== '') {
            if (isset($filters['filterColumnsOverwrite'])) {
                $this->__applyQueryString($event, $filters['searchFor'], $filters['filterColumnsOverwrite']);
            } else {
                $this->__applyQueryString($event, $filters['searchFor']);
            }
            $this->set('passedArgsArray', ['all' => $filters['searchFor']]);
        }
        if (isset($filters['taggedAttributes']) && $filters['taggedAttributes'] !== '') {
            $this->__applyQueryString($event, $filters['taggedAttributes'], 'Tag.name');
        }
        if (isset($filters['galaxyAttachedAttributes']) && $filters['galaxyAttachedAttributes'] !== '') {
            $this->__applyQueryString($event, $filters['galaxyAttachedAttributes'], 'Tag.name');
        }

        // remove galaxies tags
        $containsProposals = !empty($event['ShadowAttribute']);
        ;
        $TaxonomiesTable = $this->fetchTable('Taxonomies');
        foreach ($event['Object'] as $k => $object) {
            if (isset($object['Attribute'])) {
                foreach ($object['Attribute'] as $k2 => $attribute) {
                    if (!empty($attribute['AttributeTag'])) {
                        $this->Events->Attributes->removeGalaxyClusterTags($event['Object'][$k]['Attribute'][$k2]);

                        $tagConflicts = $TaxonomiesTable->checkIfTagInconsistencies($attribute['AttributeTag']);
                        $event['Object'][$k]['Attribute'][$k2]['tagConflicts'] = $tagConflicts;
                    }
                    if (!$containsProposals && !empty($attribute['ShadowAttribute'])) {
                        $containsProposals = true;
                    }
                }
            }
        }

        foreach ($event['Attribute'] as &$attribute) {
            if (!empty($attribute['AttributeTag'])) {
                $this->Events->Attributes->removeGalaxyClusterTags($attribute);

                $tagConflicts = $TaxonomiesTable->checkIfTagInconsistencies($attribute['AttributeTag']);
                $attribute['tagConflicts'] = $tagConflicts;
            }
            if (!$containsProposals && !empty($attribute['ShadowAttribute'])) {
                $containsProposals = true;
            }
        }
        if (empty($this->passedArgs['sort'])) {
            $filters['sort'] = 'timestamp';
            $filters['direction'] = 'desc';
        }
        $sightingsData = $this->Events->Sighting->eventsStatistic([$event], $user);
        $this->set('sightingsData', $sightingsData);
        $params = $this->Events->rearrangeEventForView($event, $filters, $all, $sightingsData);
        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $SightingsdbsTable = $this->fetchTable('Sightingsdbs');
            $event = $SightingsdbsTable->attachToEvent($event, $this->ACL->getUser()->toArray());
        }
        $this->params->params['paging'] = [$this->modelClass => $params];
        $this->set('event', $event);
        $this->set('includeOrgColumn', (isset($conditions['extended']) || $containsProposals));
        $this->set('includeSightingdb', (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')));
        $this->set('deleted', isset($filters['deleted']) && $filters['deleted'] != 0);
        $this->set('attributeFilter', isset($filters['attributeFilter']) ? $filters['attributeFilter'] : 'all');
        $this->set('filters', $filters);
        $advancedFiltering = $this->__checkIfAdvancedFiltering($filters);
        $this->set('advancedFilteringActive', $advancedFiltering['active'] ? 1 : 0);
        $this->set('advancedFilteringActiveRules', $advancedFiltering['activeRules']);
        $this->set('mayModify', $this->canModifyEvent($event, $user));
        $this->set('mayPublish', $this->canPublishEvent($event, $user));
        $this->response->withDisabledCache();

        // Remove `focus` attribute from URI
        $uriArray = explode('/', $this->request->getAttribute('here'));
        foreach ($uriArray as $k => $v) {
            if (strpos($v, 'focus:') === 0) {
                unset($uriArray[$k]);
            }
            $this->response->withLocation(implode('/', $uriArray));
        }

        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->set('sightingdbs', $SightingsdbsTable->getSightingdbList($user));
        }
        $this->set('currentUri', $this->request->getAttribute('here'));
        $this->layout = false;
        $this->__eventViewCommon($user);
        $this->render('/Elements/eventattribute');
    }

    /**
     * @param array $user
     * @param array $event
     * @param bool $continue
     * @param int $fromEvent
     */
    private function __viewUI(array $user, $event, $continue, $fromEvent)
    {
        $TaxonomiesTable = $this->fetchTable('Taxonomies');
        $filterData = [
            'request' => $this->request,
            'paramArray' => self::ACCEPTED_FILTERING_NAMED_PARAMS,
            'named_params' => $this->params['named']
        ];
        $exception = false;
        $warningTagConflicts = [];
        $filters = $this->harvestParameters($filterData, $exception);

        $emptyEvent = (empty($event['Object']) && empty($event['Attribute']));
        $this->set('emptyEvent', $emptyEvent);

        // set the data for the contributors / history field
        $contributors = $this->Events->ShadowAttribute->getEventContributors($event['Event']['id']);
        $this->set('contributors', $contributors);

        // set the pivot data
        $this->helpers[] = 'Pivot';
        if ($continue) {
            $this->__continuePivoting($event['Event']['id'], $event['Event']['info'], $event['Event']['date'], $fromEvent);
        } else {
            $this->__startPivoting($event['Event']['id'], $event['Event']['info'], $event['Event']['date']);
        }
        $pivot = $this->Session->read('pivot_thread');
        $this->__arrangePivotVertical($pivot);
        $this->__setDeletable($pivot, $event['Event']['id'], true);
        $this->set('allPivots', $this->Session->read('pivot_thread'));
        $this->set('pivot', $pivot);

        // workaround to get number of correlation per related event
        $relatedEventCorrelationCount = [];
        if (!empty($event['RelatedAttribute'])) {
            foreach ($event['RelatedAttribute'] as $relatedAttribute) {
                foreach ($relatedAttribute as $relation) {
                    $relatedEventCorrelationCount[$relation['id']][$relation['value']] = true;
                }
            }
        }
        foreach ($relatedEventCorrelationCount as $key => $relation) {
            $relatedEventCorrelationCount[$key] = count($relation);
        }

        $this->Events->removeGalaxyClusterTags($event);

        $tagConflicts = $TaxonomiesTable->checkIfTagInconsistencies($event['EventTag']);
        foreach ($tagConflicts['global'] as $tagConflict) {
            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
        }
        foreach ($tagConflicts['local'] as $tagConflict) {
            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
        }
        $this->set('tagConflicts', $tagConflicts);

        $attributeCount = isset($event['Attribute']) ? count($event['Attribute']) : 0;
        $objectCount = isset($event['Object']) ? count($event['Object']) : 0;
        $oldestTimestamp = PHP_INT_MAX;
        $containsProposals = !empty($event['ShadowAttribute']);
        $modDate = date("Y-m-d", $event['Event']['timestamp']);
        $modificationMap = [$modDate => 1];
        foreach ($event['Attribute'] as $k => $attribute) {
            if ($oldestTimestamp > $attribute['timestamp']) {
                $oldestTimestamp = $attribute['timestamp'];
            }
            $modDate = date("Y-m-d", $attribute['timestamp']);
            $modificationMap[$modDate] = !isset($modificationMap[$modDate]) ? 1 : $modificationMap[$modDate] + 1;

            $this->Events->Attributes->removeGalaxyClusterTags($event['Attribute'][$k]);

            if (!empty($attribute['AttributeTag'])) {
                $tagConflicts = $TaxonomiesTable->checkIfTagInconsistencies($attribute['AttributeTag']);
                foreach ($tagConflicts['global'] as $tagConflict) {
                    $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                }
                foreach ($tagConflicts['local'] as $tagConflict) {
                    $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                }
                $event['Attribute'][$k]['tagConflicts'] = $tagConflicts;
            }
            if (!$containsProposals && !empty($attribute['ShadowAttribute'])) {
                $containsProposals = true;
            }
        }

        foreach ($event['Object'] as $k => $object) {
            $modDate = date("Y-m-d", $object['timestamp']);
            $modificationMap[$modDate] = !isset($modificationMap[$modDate]) ? 1 : $modificationMap[$modDate] + 1;
            if (!empty($object['Attribute'])) {
                $attributeCount += count($object['Attribute']);
                foreach ($object['Attribute'] as $k2 => $attribute) {
                    if ($oldestTimestamp > $attribute['timestamp']) {
                        $oldestTimestamp = $attribute['timestamp'];
                    }

                    $modDate = date("Y-m-d", $attribute['timestamp']);
                    $modificationMap[$modDate] = !isset($modificationMap[$modDate]) ? 1 : $modificationMap[$modDate] + 1;

                    $this->Events->Attributes->removeGalaxyClusterTags($event['Object'][$k]['Attribute'][$k2]);

                    if (!empty($attribute['AttributeTag'])) {
                        $tagConflicts = $TaxonomiesTable->checkIfTagInconsistencies($attribute['AttributeTag']);
                        foreach ($tagConflicts['global'] as $tagConflict) {
                            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                        }
                        foreach ($tagConflicts['local'] as $tagConflict) {
                            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                        }
                        $event['Object'][$k]['Attribute'][$k2]['tagConflicts'] = $tagConflicts;
                    }
                    if (!$containsProposals && !empty($attribute['ShadowAttribute'])) {
                        $containsProposals = true;
                    }
                }
            }
        }

        if ($containsProposals && $this->canPublishEvent($event, $user)) {
            $mess = $this->Session->read('Message');
            if (empty($mess)) {
                $this->Flash->info(__('This event has active proposals for you to accept or discard.'));
            }
        }

        $attributeTagsName = $this->Events->Attributes->AttributeTag->extractAttributeTagsNameFromEvent($event);
        $this->set('attributeTags', array_values($attributeTagsName['tags']));
        $this->set('attributeClusters', array_values($attributeTagsName['clusters']));

        $this->set('warningTagConflicts', $warningTagConflicts);
        $filters['sort'] = 'timestamp';
        $filters['direction'] = 'desc';
        if (isset($filters['distribution'])) {
            if (!is_array($filters['distribution'])) {
                $filters['distribution'] = [$filters['distribution']];
            }
            $temp = implode('|', $filters['distribution']);
            $this->__applyQueryString($event, $temp, 'distribution');
        }
        $modificationMapCSV = 'Date,Close\n';
        $startDate = array_keys($modificationMap);
        sort($startDate);
        $startDate = $startDate[0];
        $this->set('startDate', $startDate);
        $today = strtotime(date('Y-m-d'));
        if (($today - 172800) > $startDate) {
            $startDate = date('Y-m-d', $today - 172800);
        }
        for ($date = $startDate; strtotime($date) <= $today; $date = date('Y-m-d', strtotime("+1 day", strtotime($date)))) {
            if (isset($modificationMap[$date])) {
                $modificationMapCSV .= $date . ',' . $modificationMap[$date] . '\n';
            } else {
                $modificationMapCSV .= $date . ',0\n';
            }
        }
        unset($modificationMap);
        $SightingsTable = $this->fetchTable('Sightings');
        $sightingsData = $SightingsTable->eventsStatistic([$event], $user);
        $this->set('sightingsData', $sightingsData);
        $params = $this->Events->rearrangeEventForView($event, $filters, false, $sightingsData);
        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $SightingdbsTable = $this->fetchTable('Sightingdbs');
            $event = $this->Sightingdb->attachToEvent($event, $user);
        }
        $this->params->params['paging'] = [$this->modelClass => $params];
        $this->set('event', $event);
        $extensionParams = [
            'conditions' => [
                'Events.extends_uuid' => $event['Event']['uuid']
            ]
        ];
        $extensions = $this->Events->fetchSimpleEvents($user, $extensionParams);
        $this->set('extensions', $extensions);
        if (!empty($event['Event']['extends_uuid'])) {
            $extendedEvent = $this->Events->fetchSimpleEvents($user, ['conditions' => ['Events.uuid' => $event['Event']['extends_uuid']]]);
            if (empty($extendedEvent)) {
                $extendedEvent = $event['Event']['extends_uuid'];
            }
            $this->set('extendedEvent', $extendedEvent);
        }
        if (Configure::read('MISP.delegation')) {
            $EventDelegationsTable = $this->fetchTable('EventDelegations');
            $delegationConditions = ['EventDelegation.event_id' => $event['Event']['id']];
            if (!$this->isSiteAdmin() && $this->ACL->getUser()['Role']['perm_publish']) {
                $delegationConditions['OR'] = [
                    'EventDelegation.org_id' => $user['org_id'],
                    'EventDelegation.requester_org_id' => $user['org_id']
                ];
            }
            $this->set(
                'delegationRequest',
                $this->EventDelegation->find(
                    'all',
                    [
                        'conditions' => $delegationConditions,
                        'recursive' => -1,
                        'contain' => ['Org', 'RequesterOrg']
                    ]
                )->first()
            );
        }

        $attributeUri = $this->baseurl . '/events/viewEventAttributes/' . $event['Event']['id'];
        foreach ($this->params->named as $k => $v) {
            if (!is_numeric($k)) {
                if (is_array($v)) {
                    foreach ($v as $value) {
                        $attributeUri .= sprintf('/%s[]:%s', $k, $value);
                    }
                } else {
                    $attributeUri .= sprintf('/%s:%s', $k, $v);
                }
            }
        }

        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->set('sightingdbs', $this->Sightingdb->getSightingdbList($user));
        }
        $this->set('includeOrgColumn', $this->viewVars['extended'] || $containsProposals);
        $this->set('includeSightingdb', !empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable'));
        $this->set('relatedEventCorrelationCount', $relatedEventCorrelationCount);
        $this->set('oldest_timestamp', $oldestTimestamp === PHP_INT_MAX ? false : $oldestTimestamp);
        $this->set('missingTaxonomies', $this->Events->missingTaxonomies($event));
        $this->set('currentUri', $attributeUri);
        $this->set('filters', $filters);
        $advancedFiltering = $this->__checkIfAdvancedFiltering($filters);
        $this->set('advancedFilteringActive', $advancedFiltering['active'] ? 1 : 0);
        $this->set('advancedFilteringActiveRules', $advancedFiltering['activeRules']);
        $this->set('modificationMapCSV', $modificationMapCSV);
        $this->set('title_for_layout', __('Event #%s', $event['Event']['id']));
        $this->set('attribute_count', $attributeCount);
        $this->set('object_count', $objectCount);
        $this->set('warnings', $this->Events->generateWarnings($event));
        $this->set('menuData', ['menuList' => 'event', 'menuItem' => 'viewEvent']);
        $this->set('mayModify', $this->canModifyEvent($event, $user));
        $this->set('mayPublish', $this->canPublishEvent($event, $user));
        try {
            $instanceKey = $event['Event']['protected'] ? $this->Events->CryptographicKeys->ingestInstanceKey() : null;
        } catch (Exception $e) {
            $instanceKey = null;
        }
        $this->set('instanceFingerprint', $instanceKey);
        $this->__eventViewCommon($user);
    }

    private function __eventViewCommon(array $user)
    {
        $this->set('defaultFilteringRules', self::DEFAULT_FILTERING_RULE);
        $this->set('typeGroups', array_keys(Attribute::TYPE_GROUPINGS));

        $orgTable = $this->Events->Orgc->find(
            'list',
            [
                'fields' => ['Orgc.id', 'Orgc.name']
            ]
        );
        $this->set('orgTable', $orgTable);

        $dataForView = [
            'Attribute' => ['attrDescriptions' => 'fieldDescriptions', 'distributionDescriptions' => 'distributionDescriptions', 'distributionLevels' => 'distributionLevels', 'shortDist' => 'shortDist'],
            'Event' => ['eventDescriptions' => 'fieldDescriptions', 'analysisDescriptions' => 'analysisDescriptions', 'analysisLevels' => 'analysisLevels']
        ];
        foreach ($dataForView as $m => $variables) {
            if ($m === 'Event') {
                $currentModel = $this->Event;
            } elseif ($m === 'Attribute') {
                $currentModel = $this->Events->Attribute;
            }
            foreach ($variables as $alias => $variable) {
                $this->set($alias, $currentModel->{$variable});
            }
        }

        if (Configure::read('Plugin.Enrichment_services_enable')) {
            $ModulesTable = $this->fetchTable('Modules');
            $modules = $ModulesTable->getEnabledModules($user);
            $this->set('modules', $modules);
        }
        if (Configure::read('Plugin.Cortex_services_enable')) {
            $ModulesTable = $this->fetchTable('Modules');
            $cortex_modules = $ModulesTable->getEnabledModules($user, false, 'Cortex');
            $this->set('cortex_modules', $cortex_modules);
        }
        $this->set('sightingsDbEnabled', (bool)Configure::read('Plugin.Sightings_sighting_db_enable'));
    }

    public function view($id = null, $continue = false, $fromEvent = null)
    {
        if ($this->request->is('head')) { // Just check if event exists
            $exists = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id, ['fields' => ['id']]);
            return new Response(['status' => $exists ? 200 : 404]);
        }

        if (is_numeric($id)) {
            $conditions = ['eventid' => $id];
        } else if (Validation::uuid($id)) {
            $conditions = ['event_uuid' => $id];
        } else {
            throw new NotFoundException(__('Invalid event'));
        }

        $namedParams = $this->request->getParam('named');

        if ($this->ParamHandler->isRest()) {
            $conditions['includeAttachments'] = isset($namedParams['includeAttachments']) ? $namedParams['includeAttachments'] : true;
        } else {
            $conditions['includeAllTags'] = true;
            $conditions['noEventReports'] = true; // event reports for view are loaded dynamically
            $conditions['noSightings'] = true;
            $conditions['fetchFullClusters'] = false;
        }
        $deleted = 0;
        if (isset($namedParams['deleted'])) {
            $deleted = $namedParams['deleted'];
        }
        if (isset($this->request->getData()['deleted'])) {
            $deleted = $this->request->getData()['deleted'];
        }
        // workaround for old instances trying to pull events with both deleted / non deleted data
        if (($this->ACL->getUser()['Role']['perm_sync'] && $this->ParamHandler->isRest() && !$this->ACL->getUser()['Role']['perm_site_admin']) && $deleted == 1) {
            $conditions['deleted'] = [0, 1];
        } else {
            if (is_array($deleted)) {
                $conditions['deleted'] = $deleted;
            } else if ($deleted == 1) { // both
                $conditions['deleted'] = [0, 1];
            } elseif ($deleted == 0) { // not-deleted only
                $conditions['deleted'] = 0;
            } else { // only deleted
                $conditions['deleted'] = 1;
            }
        }
        if (isset($namedParams['toIDS']) && $namedParams['toIDS'] != 0) {
            $conditions['to_ids'] = $namedParams['toIDS'] == 2 ? 0 : 1;
        }
        if (isset($namedParams['includeRelatedTags']) && $namedParams['includeRelatedTags']) {
            $conditions['includeRelatedTags'] = 1;
        }
        if (!empty($namedParams['includeDecayScore'])) {
            $conditions['includeDecayScore'] = 1;
        }
        if (isset($namedParams['public']) && $namedParams['public']) {
            $conditions['distribution'] = [3, 5];
        }
        if (!empty($namedParams['overrideLimit']) && !$this->ParamHandler->isRest()) {
            $conditions['overrideLimit'] = 1;
        }
        if (!empty($namedParams['excludeGalaxy'])) {
            $conditions['excludeGalaxy'] = 1;
            if (!empty($namedParams['includeCustomGalaxyCluster'])) {
                $conditions['includeCustomGalaxyCluster'] = 1;
            }
        }
        if (!empty($namedParams['extended']) || !empty($this->request->getData()['extended'])) {
            $conditions['extended'] = 1;
            $this->set('extended', 1);
        } else {
            $this->set('extended', 0);
        }
        $conditions['excludeLocalTags'] = false;
        $conditions['includeWarninglistHits'] = true;
        if (isset($namedParams['excludeLocalTags'])) {
            $conditions['excludeLocalTags'] = $namedParams['excludeLocalTags'];
        }
        $conditions['includeFeedCorrelations'] = 1;
        if (!$this->ParamHandler->isRest()) {
            $conditions['includeGranularCorrelations'] = 1;
        } else if (!empty($namedParams['includeGranularCorrelations'])) {
            $conditions['includeGranularCorrelations'] = 1;
        }
        if (!isset($namedParams['includeServerCorrelations'])) {
            $conditions['includeServerCorrelations'] = 1;
            if ($this->ParamHandler->isRest()) {
                $conditions['includeServerCorrelations'] = 0;
            }
        } else {
            $conditions['includeServerCorrelations'] = $namedParams['includeServerCorrelations'];
        }

        if ($this->ParamHandler->isRest()) {
            foreach (['includeEventCorrelations', 'includeFeedCorrelations', 'includeWarninglistHits', 'noEventReports', 'noShadowAttributes'] as $param) {
                if (isset($namedParams[$param])) {
                    $conditions[$param] = $namedParams[$param];
                }
            }
        }

        // Site admin can view event as different user
        if ($this->isSiteAdmin() && isset($namedParams['viewAs'])) {
            $user = $this->User->getAuthUser($namedParams['viewAs']);
            if (empty($user)) {
                throw new NotFoundException(__("User not found"));
            }
            $this->Flash->info(__('Viewing event as %s from %s', h($user['email']), h($user['Organisation']['name'])));
        } else {
            $user = $this->ACL->getUser()->toArray();
        }

        $results = $this->Events->fetchEvent($user, $conditions);
        if (empty($results)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $event = $results[0];
        // Attach related attributes to proper attribute
        if (!empty($namedParams['includeGranularCorrelations']) && !empty($event['RelatedAttribute'])) {
            foreach ($event['RelatedAttribute'] as $attribute_id => $relation) {
                foreach ($event['Attribute'] as $k2 => $attribute) {
                    if ((int)$attribute['id'] == $attribute_id) {
                        $event['Attribute'][$k2]['RelatedAttribute'][] = $relation;
                        break 2;
                    }
                }
                foreach ($event['Object'] as $k2 => $object) {
                    foreach ($object['Attribute'] as $k3 => $attribute) {
                        if ((int)$attribute['id'] == $attribute_id) {
                            $event['Object'][$k2]['Attribute'][$k3]['RelatedAttribute'][] = $relation;
                            break 3;
                        }
                    }
                }
            }
        }

        if (isset($namedParams['searchFor']) && $namedParams['searchFor'] !== '') {
            $this->__applyQueryString($event, $namedParams['searchFor']);
        }
        if (isset($namedParams['taggedAttributes']) && $namedParams['taggedAttributes'] !== '') {
            $this->__applyQueryString($event, $namedParams['taggedAttributes'], 'Tag.name');
        }
        if (isset($namedParams['galaxyAttachedAttributes']) && $namedParams['galaxyAttachedAttributes'] !== '') {
            $this->__applyQueryString($event, $namedParams['galaxyAttachedAttributes'], 'Tag.name');
        }
        if ($this->ParamHandler->isRest()) {
            if ($this->RestResponse->isAutomaticTool() && $event['Event']['protected']) {
                $this->RestResponse->signContents = true;
            }
            return $this->__restResponse($event);
        }

        $this->set('deleted', $deleted > 0);
        $this->set('includeRelatedTags', (!empty($namedParams['includeRelatedTags'])) ? 1 : 0);
        $this->set('includeDecayScore', (!empty($namedParams['includeDecayScore'])) ? 1 : 0);

        $this->__setHighlightedTags($event);

        if ($this->isSiteAdmin() && $event['Event']['orgc_id'] !== $this->ACL->getUser()['org_id']) {
            $this->Flash->info(__('You are currently logged in as a site administrator and about to edit an event not belonging to your organisation. This goes against the sharing model of MISP. Use a normal user account for day to day work.'));
        }
        $this->__viewUI($user, $event, $continue, $fromEvent);
    }

    /**
     * @param int $id
     * @param string $info
     * @param string $date
     */
    private function __startPivoting($id, $info, $date)
    {
        $initialPivot = [
            'id' => $id,
            'info' => $info,
            'date' => $date,
            'depth' => 0,
            'height' => 0,
            'children' => [],
            'deletable' => true,
        ];
        $this->Session->write('pivot_thread', $initialPivot);
    }

    /**
     * @param int $id
     * @param string $info
     * @param string $date
     * @param int $fromEvent
     */
    private function __continuePivoting($id, $info, $date, $fromEvent)
    {
        $pivot = $this->Session->read('pivot_thread');
        if (!is_array($pivot)) {
            $this->__startPivoting($id, $info, $date);
            return;
        }

        $newPivot = [
            'id' => $id,
            'info' => $info,
            'date' => $date,
            'depth' => null,
            'children' => [],
            'deletable' => true,
        ];
        if (!$this->__checkForPivot($pivot, $id)) {
            $pivot = $this->__insertPivot($pivot, $fromEvent, $newPivot, 0);
        }
        $this->Session->write('pivot_thread', $pivot);
    }

    /**
     * @param array $pivot
     * @param int $oldId
     * @param array $newPivot
     * @param int $depth
     * @return array
     */
    private function __insertPivot(array $pivot, $oldId, array $newPivot, $depth)
    {
        $depth++;
        if ($pivot['id'] == $oldId) {
            $newPivot['depth'] = $depth;
            $pivot['children'][] = $newPivot;
            return $pivot;
        }
        if (!empty($pivot['children'])) {
            foreach ($pivot['children'] as $k => $v) {
                $pivot['children'][$k] = $this->__insertPivot($v, $oldId, $newPivot, $depth);
            }
        }
        return $pivot;
    }

    /**
     * @param array $pivot
     * @param int $id
     * @return bool
     */
    private function __checkForPivot(array $pivot, $id)
    {
        if ($id == $pivot['id']) {
            return true;
        }
        foreach ($pivot['children'] as $k => $v) {
            if ($this->__checkForPivot($v, $id)) {
                return true;
            }
        }
        return false;
    }

    private function __arrangePivotVertical(&$pivot)
    {
        if (empty($pivot)) {
            return null;
        }
        $max = count($pivot['children']) - 1;
        if ($max < 0) {
            $max = 0;
        }
        $temp = 0;
        $pivot['children'] = array_values($pivot['children']);
        foreach ($pivot['children'] as $k => $v) {
            $pivot['children'][$k]['height'] = ($temp + $k) * 50;
            $temp += $this->__arrangePivotVertical($pivot['children'][$k]);
            if ($k == $max) {
                $temp = $pivot['children'][$k]['height'] / 50;
            }
        }
        return $temp;
    }

    public function removePivot($id, $eventId, $self = false)
    {
        $pivot = $this->Session->read('pivot_thread');
        if ($pivot['id'] == $id) {
            $pivot = null;
            $this->Session->write('pivot_thread', null);
            $this->redirect(['controller' => 'events', 'action' => 'view', $eventId]);
        } else {
            $pivot = $this->__doRemove($pivot, $id);
        }
        $this->Session->write('pivot_thread', $pivot);
        $pivot = $this->__arrangePivotVertical($pivot);
        $this->redirect(['controller' => 'events', 'action' => 'view', $eventId, true, $eventId]);
    }

    /**
     * @param array $event
     * @param string $searchFor
     * @param string|false $filterColumnsOverwrite
     */
    private function __applyQueryString(&$event, $searchFor, $filterColumnsOverwrite = false)
    {
        // filtering on specific columns is specified
        if ($filterColumnsOverwrite !== false) {
            $filterValue = array_map('trim', explode(",", $filterColumnsOverwrite));
        } else {
            $filterColumnsOverwrite = Configure::read('MISP.event_view_filter_fields') ?: 'id,uuid,value,comment,type,category,Tag.name';
            $filterValue = array_map('trim', explode(",", $filterColumnsOverwrite));
            $validFilters = ['id', 'uuid', 'value', 'comment', 'type', 'category', 'Tag.name'];
            foreach ($filterValue as $k => $v) {
                if (!in_array($v, $validFilters, true)) {
                    unset($filterValue[$k]);
                }
            }
        }

        $searchParts = explode('|', mb_strtolower($searchFor));

        // search in all attributes
        $foundAttributes = [];
        foreach ($event['Attribute'] as $attribute) {
            if ($this->__valueInFieldAttribute($attribute, $filterValue, $searchParts)) {
                $foundAttributes[] = $attribute;
            }
        }
        $event['Attribute'] = $foundAttributes;

        // search in all proposals
        $foundProposals = [];
        foreach ($event['ShadowAttribute'] as $proposals) {
            if ($this->__valueInFieldAttribute($proposals, $filterValue, $searchParts)) {
                $foundProposals[] = $proposals;
            }
        }
        $event['ShadowAttribute'] = $foundProposals;

        // search for all attributes in object
        foreach ($event['Object'] as $k => $object) {
            if ($this->__valueInFieldAttribute($object, ['id', 'uuid', 'name', 'comment'], $searchParts)) {
                continue;
            }
            $foundAttributes = [];
            foreach ($object['Attribute'] as $attribute) {
                if ($this->__valueInFieldAttribute($attribute, $filterValue, $searchParts)) {
                    $foundAttributes[] = $attribute;
                }
            }
            if (empty($foundAttributes)) {
                unset($event['Object'][$k]); // remove object if contains no attributes
            } else {
                $event['Object'][$k]['Attribute'] = $foundAttributes;
            }
        }
        $event['Object'] = array_values($event['Object']);
    }

    /**
     * Search for a value on an attribute level for a specific field.
     *
     * @param array $attribute An attribute
     * @param array $fields List of keys in attribute to search in
     * @param array $searchParts Values to search (OR)
     * @return bool Returns true on match
     */
    private function __valueInFieldAttribute($attribute, $fields, $searchParts)
    {
        foreach ($fields as $field) {
            if ($field === 'Tag.name') {
                if (empty($attribute['AttributeTag'])) {
                    continue;
                }
                foreach ($attribute['AttributeTag'] as $fieldValue) {
                    $fieldValue = mb_strtolower($fieldValue['Tag']['name']);
                    foreach ($searchParts as $s) {
                        if (strpos($fieldValue, $s) !== false) {
                            return true;
                        }
                    }
                }
            } else {
                if (!isset($attribute[$field])) {
                    continue;
                }
                $fieldValue = mb_strtolower($attribute[$field]);
                foreach ($searchParts as $s) {
                    if (strpos($fieldValue, $s) !== false) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // look in the parameters if we are doing advanced filtering or not
    private function __checkIfAdvancedFiltering($filters)
    {
        $advancedFilteringActive = array_diff_key($filters, ['sort' => 0, 'direction' => 0, 'focus' => 0, 'overrideLimit' => 0, 'filterColumnsOverwrite' => 0, 'attributeFilter' => 0, 'extended' => 0, 'page' => 0]);

        if (count($advancedFilteringActive) > 0) {
            if (count(array_diff_key($advancedFilteringActive, ['deleted', 'includeRelatedTags', 'includeDecayScore'])) > 0) {
                $res =  true;
            } else if (
                (isset($advancedFilteringActive['deleted']) && $advancedFilteringActive['deleted'] == 2) ||
                (isset($advancedFilteringActive['includeRelatedTags']) && $advancedFilteringActive['includeRelatedTags'] == 1) ||
                (isset($advancedFilteringActive['includeDecayScore']) && $advancedFilteringActive['includeDecayScore'] == 1)
            ) {
                $res =  true;
            } else {
                $res =  false;
            }
        } else {
            $res = false;
        }

        unset($filters['sort']);
        unset($filters['direction']);
        $activeRules = [];
        foreach ($filters as $k => $v) {
            if (isset(self::DEFAULT_FILTERING_RULE[$k]) && self::DEFAULT_FILTERING_RULE[$k] != $v) {
                $activeRules[$k] = $v;
            }
        }
        return ['active' => $activeRules > 0 ? $res : false, 'activeRules' => $activeRules];
    }

    private function __doRemove(&$pivot, $id)
    {
        foreach ($pivot['children'] as $k => $v) {
            if ($v['id'] == $id) {
                unset($pivot['children'][$k]);
                return $pivot;
            } else {
                $pivot['children'][$k] = $this->__doRemove($pivot['children'][$k], $id);
            }
        }
        return $pivot;
    }

    private function __setDeletable(&$pivot, $id, $root = false)
    {
        if ($pivot['id'] == $id && !$root) {
            $pivot['deletable'] = false;
            return true;
        }
        if (!empty($pivot['children'])) {
            foreach ($pivot['children'] as $k => $v) {
                $containsCurrent = $this->__setDeletable($pivot['children'][$k], $id);
                if ($containsCurrent && !$root) {
                    $pivot['deletable'] = false;
                }
            }
        }
        return !$pivot['deletable'];
    }

    public function add()
    {
        $sgs = $this->Events->SharingGroup->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'name', 1);
        if ($this->request->is('post')) {
            if ($this->ParamHandler->isRest()) {
                $data = $this->request->getData();
                if (empty($data)) {
                    throw new MethodNotAllowedException(__('No valid event data received.'));
                }
                // rearrange the response if the event came from an export
                if (isset($data['response'])) {
                    $data = $data['response'];
                }
                if (isset($data['request'])) {
                    $data = $data['request'];
                }
                if (!isset($data['Event'])) {
                    $data = ['Event' => $data];
                }

                // Distribution, reporter for the events pushed will be the owner of the authentication key
                $data['Event']['user_id'] = $this->ACL->getUser()['id'];
            }
            if (
                !empty($data['Event']['protected']) &&
                $this->ACL->getUser()['Role']['perm_sync'] &&
                !$this->ACL->getUser()['Role']['perm_site_admin']
            ) {
                $pgp_signature = $this->request->header('x-pgp-signature');
                if (empty($pgp_signature)) {
                    throw new MethodNotAllowedException(__('Protected event failed signature validation as no key was provided.'));
                }
                $raw_data = (string)$this->request->getBody();
                if (
                    !$this->Events->CryptographicKeys->validateProtectedEvent(
                        $raw_data,
                        $this->ACL->getUser()->toArray(),
                        $pgp_signature,
                        $data
                    )
                ) {
                    throw new MethodNotAllowedException(__('Protected event failed signature validation.'));
                }
            }
            if (!empty($this->request->getData())) {
                $data = $this->request->getData();
                if (!isset($data['Event']['distribution'])) {
                    $data['Event']['distribution'] = Configure::read('MISP.default_event_distribution') ?: 0;
                }
                if (!isset($data['Event']['analysis'])) {
                    $data['Event']['analysis'] = 0;
                }
                if (!isset($data['Event']['threat_level_id'])) {
                    $data['Event']['threat_level_id'] = Configure::read('MISP.default_event_threat_level') ?: 4;
                }
                if (!isset($data['Event']['date'])) {
                    $data['Event']['date'] = date('Y-m-d');
                }
                // If the distribution is set to sharing group, check if the id provided is really visible to the user, if not throw an error.
                if ($data['Event']['distribution'] == 4) {
                    if ($this->ACL->getUser()['Role']['perm_sync'] && $this->ParamHandler->isRest()) {
                        if (isset($data['Event']['SharingGroup'])) {
                            if (!isset($data['Event']['SharingGroup']['uuid'])) {
                                if (
                                    $this->Events->SharingGroup->checkIfExists($data['Event']['SharingGroup']['uuid']) &&
                                    $this->Events->SharingGroup->checkIfAuthorised($this->ACL->getUser()->toArray(), $data['Event']['SharingGroup']['uuid'])
                                ) {
                                    throw new MethodNotAllowedException(__('Invalid Sharing Group or not authorised (Sync user is not contained in the Sharing group).'));
                                }
                            }
                        } elseif (!isset($sgs[$data['Event']['sharing_group_id']])) {
                            throw new MethodNotAllowedException(__('Invalid Sharing Group or not authorised.'));
                        }
                    } else {
                        if (!isset($sgs[$data['Event']['sharing_group_id']])) {
                            throw new MethodNotAllowedException(__('Invalid Sharing Group or not authorised.'));
                        }
                    }
                } else {
                    // If the distribution is set to something "traditional", set the SG id to 0.
                    $data['Event']['sharing_group_id'] = 0;
                }
                // If we are not sync users / site admins, we only allow events to be created for our own org
                // Set the orgc ID as our own orgc ID and unset both the 2.4 and 2.3 style creator orgs
                if ($this->ParamHandler->isRest() && !$this->ACL->getUser()['Role']['perm_sync']) {
                    $data['Event']['orgc_id'] = $this->ACL->getUser()['org_id'];
                    if (isset($data['Event']['Orgc'])) {
                        unset($data['Event']['Orgc']);
                    }
                    if (isset($data['Event']['orgc'])) {
                        unset($data['Event']['orgc']);
                    }
                }
                $validationErrors = [];
                $created_id = 0;
                $add = $this->Events->_add($data, $this->ParamHandler->isRest(), $this->ACL->getUser()->toArray(), '', null, false, null, $created_id, $validationErrors);
                if ($add === true) {
                    if ($this->ParamHandler->isRest()) {
                        // REST users want to see the newly created event
                        $namedParams = $this->request->getParam('named');
                        $metadata = $namedParams['metadata'] ?? [];
                        $results = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), ['eventid' => $created_id, 'metadata' => $metadata]);
                        $event = $results[0];
                        if (!empty($validationErrors)) {
                            $event['errors'] = $validationErrors;
                        }
                        return $this->__restResponse($event);
                    } else {
                        // redirect to the view of the newly created event
                        $this->Flash->success(__('The event has been saved'));
                        $this->redirect(['action' => 'view', $this->Events->getID()]);
                    }
                } else {
                    if ($this->ParamHandler->isRest()) { // TODO return error if REST
                        if (is_numeric($add)) {
                            $this->response->withHeader('Location', $this->baseurl . '/events/' . $add);
                            throw new NotFoundException(__('Event already exists, if you would like to edit it, use the url in the location header.'));
                        }

                        if ($add === 'blocked') {
                            throw new ForbiddenException(__('Event blocked by organisation blocklist.'));
                        } else if ($add === 'Blocked by blocklist') {
                            throw new ForbiddenException(__('Event blocked by event blocklist.'));
                        } else if ($add === 'Blocked by event block rules') {
                            throw new ForbiddenException(__('Blocked by event block rules.'));
                        }

                        // # TODO i18n?
                        return $this->RestResponse->saveFailResponse('Events', 'add', false, $validationErrors, $this->response->getType());
                    } else {
                        if ($add === 'blocked') {
                            $this->Flash->error(__('A blocklist entry is blocking you from creating any events. Please contact the administration team of this instance') . (Configure::read('MISP.contact') ? ' at ' . Configure::read('MISP.contact') : '') . '.');
                        } else {
                            $this->Flash->error(__('The event could not be saved. Please, try again.'), 'default', [], 'error');
                        }
                    }
                }
            }
        } elseif ($this->ParamHandler->isRest()) {
            return $this->RestResponse->describe('Events', 'add', false, $this->response->getType());
        }

        $data['Event']['date'] = date('Y-m-d');
        if (isset($data['Event']['distribution'])) {
            $initialDistribution = $data['Event']['distribution'];
        } else {
            $initialDistribution = 3;
            if (Configure::read('MISP.default_event_distribution') != null) {
                $initialDistribution = Configure::read('MISP.default_event_distribution');
            }
        }
        $this->set('initialDistribution', $initialDistribution);

        // combobox for distribution
        $distributions = array_keys($this->Events->distributionDescriptions);
        $distributions = $this->_arrayToValuesIndexArray($distributions);
        $this->set('distributions', $distributions);
        // tooltip for distribution
        $fieldDesc = [];
        $distributionLevels = $this->Events->distributionLevels;
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        $this->set('distributionLevels', $distributionLevels);
        foreach ($distributionLevels as $key => $value) {
            $fieldDesc['distribution'][$key] = $this->Events->distributionDescriptions[$key]['formdesc'];
        }

        // combobox for risks
        $threat_levels = array_column($this->Events->ThreatLevel->find('all'), 'ThreatLevel');
        $this->set('threatLevels', array_column($threat_levels, 'name', 'id'));
        $fieldDesc['threat_level_id'] = array_column($threat_levels, 'description', 'id');

        // combobox for analysis
        $this->set('sharingGroups', $sgs);
        // tooltip for analysis
        $analysisLevels = $this->Events->analysisLevels;
        $this->set('analysisLevels', $analysisLevels);
        foreach ($analysisLevels as $key => $value) {
            $fieldDesc['analysis'][$key] = $this->Events->analysisDescriptions[$key]['formdesc'];
        }

        if (Configure::read('MISP.unpublishedprivate')) {
            $this->Flash->info(__('The event created will be visible only to your organisation until it is published.'));
        } else {
            $this->Flash->info(__('The event created will be visible to the organisations having an account on this platform, but not synchronised to other MISP instances until it is published.'));
        }
        $this->set('fieldDesc', $fieldDesc);
        if (isset($this->params['named']['extends'])) {
            $this->set('extends_uuid', $this->params['named']['extends']);
        }
    }

    public function addIOC($id)
    {
        $this->Events->recursive = -1;
        $this->Events->read(null, $id);
        if (!$this->ACL->canModifyEvent($this->Events->data)) {
            throw new UnauthorizedException(__('You do not have permission to do that.'));
        }
        if ($this->request->is('post')) {
            $data = $this->request->getData();
            if (!empty($data)) {
                if (isset($data['Event']['submittedioc'])) {
                    $this->_addIOCFile($id);
                }

                // redirect to the view of the newly created event
                $this->Flash->success(__('The event has been saved'));
            }
        }
        // set the id
        $this->set('id', $id);
        // set whether it is published or notPyongyang
        $this->set('published', $this->Events->data['Event']['published'] ?? false);
    }

    public function add_misp_export()
    {
        if ($this->request->is('post')) {
            $results = [];
            $data = $this->request->getData();
            if (!empty($data)) {
                if (empty($data['Event'])) {
                    $data['Event'] = $data;
                }
                if (!empty($data['Event']['filecontent'])) {
                    $data = $data['Event']['filecontent'];
                    $isXml = $data[0] === '<';
                } elseif (isset($data['Event']['submittedfile'])) {
                    $file = $data['Event']['submittedfile'];
                    if ($file['error'] === UPLOAD_ERR_NO_FILE) {
                        $this->Flash->error(__('No file was uploaded.'));
                        $this->redirect(['controller' => 'events', 'action' => 'add_misp_export']);
                    }

                    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                    if (($ext !== 'xml' && $ext !== 'json') && $file['size'] > 0 && is_uploaded_file($file['tmp_name'])) {
                        $LogsTable = $this->fetchTable('Logs');
                        $LogsTable->createLogEntry($this->ACL->getUser()->toArray(), 'file_upload', 'Event', 0, 'MISP export file upload failed', 'File details: ' . json_encode($file));
                        $this->Flash->error(__('You may only upload MISP XML or MISP JSON files.'));
                        throw new MethodNotAllowedException(__('File upload failed or file does not have the expected extension (.xml / .json).'));
                    }

                    $isXml = $ext === 'xml';
                    $data = FileAccessTool::readFromFile($file['tmp_name'], $file['size']);
                } else {
                    throw new MethodNotAllowedException(__('No file uploaded.'));
                }

                $takeOwnership = Configure::read('MISP.take_ownership_xml_import')
                    && (isset($data['Event']['takeownership']) && $data['Event']['takeownership'] == 1);

                $publish = $data['Event']['publish'] ?? false;

                try {
                    $results = $this->Events->addMISPExportFile($this->ACL->getUser()->toArray(), $data, $isXml, $takeOwnership, $publish);
                } catch (Exception $e) {
                    $this->log("Exception during processing MISP file import: {$e->getMessage()}");
                    $this->Flash->error(__('Could not process MISP export file. %s', $e->getMessage()));
                    $this->redirect(['controller' => 'events', 'action' => 'add_misp_export']);
                }
            }
            $this->set('results', $results);
            $this->render('add_misp_export_result');
        }
        $this->set('title_for_layout', __('Import from MISP Export File'));
    }

    public function upload_stix($stix_version = '1', $publish = false, $galaxies_as_tags = true, $debug = false)
    {
        $sgs = $this->Events->SharingGroup->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'name', 1);
        $initialDistribution = 0;
        if (Configure::read('MISP.default_event_distribution') != null) {
            $initialDistribution = Configure::read('MISP.default_event_distribution');
        }
        $distributionLevels = $this->Events->distributionLevels;
        if ($this->request->is('post')) {
            if ($this->ParamHandler->isRest()) {
                if (isset($this->params['named']['publish'])) {
                    $publish = $this->params['named']['publish'];
                }
                if (isset($this->params['named']['distribution'])) {
                    $distribution = intval($this->params['named']['distribution']);
                    if (array_key_exists($distribution, $distributionLevels)) {
                        $initialDistribution = $distribution;
                    } else {
                        throw new MethodNotAllowedException(__('Wrong distribution level'));
                    }
                }
                $sharingGroupId = null;
                if ($initialDistribution == 4) {
                    if (!isset($this->params['named']['sharing_group_id'])) {
                        throw new MethodNotAllowedException(__('The sharing group id is needed when the distribution is set to 4 ("Sharing group").'));
                    }
                    $sharingGroupId = intval($this->params['named']['sharing_group_id']);
                    if (!array_key_exists($sharingGroupId, $sgs)) {
                        throw new MethodNotAllowedException(__('Please select a valid sharing group id.'));
                    }
                }
                if (isset($this->params['named']['galaxies_as_tags'])) {
                    $galaxies_as_tags = $this->params['named']['galaxies_as_tags'];
                }
                if (isset($this->params['named']['debugging'])) {
                    $debug = $this->params['named']['debugging'];
                }
                $filePath = FileAccessTool::writeToTempFile((string)$this->request->getBody());
                $result = $this->Events->upload_stix(
                    $this->ACL->getUser()->toArray(),
                    $filePath,
                    $stix_version,
                    'uploaded_stix_file.' . ($stix_version == '1' ? 'xml' : 'json'),
                    $publish,
                    $initialDistribution,
                    $sharingGroupId,
                    $galaxies_as_tags,
                    $debug
                );
                if (is_numeric($result)) {
                    $event = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), ['eventid' => $result]);
                    if (!empty($event)) {
                        return $this->RestResponse->viewData($event[0], 'json');
                    } else {
                        return $this->RestResponse->saveFailResponse('Events', 'upload_stix', false, 'Could not read saved Events.', $this->response->getType());
                    }
                } else {
                    return $this->RestResponse->saveFailResponse('Events', 'upload_stix', false, $result, $this->response->getType());
                }
            } else {
                $original_file = !empty($this->data['Event']['original_file']) ? $this->data['Event']['stix']['name'] : '';
                if (isset($this->data['Event']['stix']) && $this->data['Event']['stix']['size'] > 0 && is_uploaded_file($this->data['Event']['stix']['tmp_name'])) {
                    $filePath = FileAccessTool::createTempFile();
                    if (!move_uploaded_file($this->data['Event']['stix']['tmp_name'], $filePath)) {
                        throw new Exception("Could not move uploaded STIX file.");
                    }
                    if (isset($this->data['Event']['debug'])) {
                        $debug = $this->data['Event']['debug'];
                    }
                    $result = $this->Events->upload_stix(
                        $this->ACL->getUser()->toArray(),
                        $filePath,
                        $stix_version,
                        $original_file,
                        $this->data['Event']['publish'],
                        $this->data['Event']['distribution'],
                        $this->data['Event']['sharing_group_id'] ?? null,
                        $this->data['Event']['galaxies_handling'],
                        $debug
                    );
                    if (is_numeric($result)) {
                        $this->Flash->success(__('STIX document imported.'));
                        $this->redirect(['action' => 'view', $result]);
                    } else {
                        $this->Flash->error(__('Could not import STIX document: %s', $result));
                    }
                } else {
                    $maxUploadSize = intval(ini_get('post_max_size'));
                    if (intval(ini_get('upload_max_filesize')) < $maxUploadSize) {
                        $maxUploadSize = intval(ini_get('upload_max_filesize'));
                    }
                    $this->Flash->error(__('File upload failed. Make sure that you select a STIX file to be uploaded and that the file doesn\'t exceed the maximum file size of %s MB.', $maxUploadSize));
                }
            }
        }
        $this->set('stix_version', $stix_version == 2 ? '2.x JSON' : '1.x XML');
        $this->set('initialDistribution', $initialDistribution);
        $distributions = array_keys($this->Events->distributionDescriptions);
        $distributions = $this->_arrayToValuesIndexArray($distributions);
        $this->set('distributions', $distributions);
        $fieldDesc = [];
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        $this->set('distributionLevels', $distributionLevels);
        foreach ($distributionLevels as $key => $value) {
            $fieldDesc['distribution'][$key] = $this->Events->distributionDescriptions[$key]['formdesc'];
        }

        $debugOptions = [
            0 => __('Standard debugging'),
            1 => __('Advanced debugging'),
        ];
        $debugDescriptions = [
            0 => __('The critical errors are logged in the usual log file.'),
            1 => __('All the errors and warnings are logged in the usual log file.'),
        ];
        $galaxiesOptions = [
            0 => __('As MISP standard format'),
            1 => __('As tag names'),
        ];
        $galaxiesOptionsDescriptions = [
            0 => __('Galaxies and Clusters are passed as MISP standard format. New generic Galaxies and Clusters are created when there is no match with existing ones.'),
            1 => __('Galaxies are passed as tags and there is only a simple search with existing galaxy tag names.'),
        ];

        $this->set('debugOptions', $debugOptions);
        foreach ($debugOptions as $key => $value) {
            $fieldDesc['debug'][$key] = $debugDescriptions[$key];
        }
        $this->set('galaxiesOptions', $galaxiesOptions);
        foreach ($galaxiesOptions as $key => $value) {
            $fieldDesc['galaxies_handling'][$key] = $galaxiesOptionsDescriptions[$key];
        }
        $this->set('sharingGroups', $sgs);
        $this->set('fieldDesc', $fieldDesc);
    }

    public function merge($target_id = null, $source_id = null)
    {
        if ($this->request->is('post')) {
            $data = $this->request->getData();
            if (empty($data['Event'])) {
                $data = ['Event' => $data];
            }
        }
        $extractedParams = ['target_id', 'source_id'];
        foreach ($extractedParams as $param) {
            if (empty(${$param})) {
                if (!empty($data['Event'][$param])) {
                    ${$param} = $data['Event'][$param];
                } else {
                    if ($param === 'target_id' || $this->request->is('post')) {
                        throw new InvalidArgumentException(__('This action requires a target_id for GET requests and both a target_id and a source_id for POST requests.'));
                    }
                }
            }
        }
        $target_event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $target_id, ['contain' => ['Orgc']]);
        if (empty($target_event)) {
            throw new NotFoundException(__('Invalid target Events.'));
        }
        if (!$this->ACL->canModifyEvent($target_event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        if ($this->request->is('post')) {
            $source_id = $this->Toolbox->findIdByUuid($this->Events, $source_id);
            $source_event = $this->Events->fetchEvent(
                $this->ACL->getUser()->toArray(),
                [
                    'eventid' => $source_id,
                    'includeAllTags' => 1,
                    'includeAttachments' => 1
                ]
            );
            if (empty($source_event)) {
                throw new NotFoundException(__('Invalid source Events.'));
            }
            $recovered_uuids = [];
            foreach ($source_event[0]['Attribute'] as &$attribute) {
                unset($attribute['id']);
                $originalUUID = $attribute['uuid'];
                $attribute['uuid'] = Text::uuid();
                $recovered_uuids[$originalUUID] = $attribute['uuid'];
                unset($attribute['ShadowAttribute']);
                $attribute['Tag'] = [];
                foreach ($attribute['AttributeTag'] as $aT) {
                    $attribute['Tag'][] = $aT['Tag'];
                    $aT['Tag']['local'] = $aT['local'];
                }
                unset($attribute['AttributeTag']);
            }
            foreach ($source_event[0]['Object'] as &$object) {
                unset($object['id']);
                $originalUUID = $object['uuid'];
                $object['uuid'] = Text::uuid();
                $recovered_uuids[$originalUUID] = $object['uuid'];
                foreach ($object['Attribute'] as &$attribute) {
                    unset($attribute['id']);
                    $originalUUID = $attribute['uuid'];
                    $attribute['uuid'] = Text::uuid();
                    $recovered_uuids[$originalUUID] = $attribute['uuid'];
                    unset($attribute['ShadowAttribute']);
                    $attribute['Tag'] = [];
                    foreach ($attribute['AttributeTag'] as $aT) {
                        $attribute['Tag'][] = $aT['Tag'];
                        $aT['Tag']['local'] = $aT['local'];
                    }
                    unset($attribute['AttributeTag']);
                }
            }
            foreach ($source_event[0]['Object'] as &$object) {
                foreach ($object['ObjectReference'] as &$reference) {
                    if (isset($recovered_uuids[$object['uuid']])) {
                        $reference['object_uuid'] = $recovered_uuids[$object['uuid']];
                    }
                    if (isset($recovered_uuids[$reference['referenced_uuid']])) {
                        $reference['referenced_uuid'] = $recovered_uuids[$reference['referenced_uuid']];
                    }
                }
            }
            foreach ($source_event[0]['EventReport'] as &$report) {
                unset($report['id'], $report['event_id']);
                $report['uuid'] = Text::uuid();
            }
            $results = [
                'results' => [
                    'Object' => $source_event[0]['Object'],
                    'Attribute' => $source_event[0]['Attribute'],
                    'EventReport' => $source_event[0]['EventReport']
                ]
            ];
            if ($this->ParamHandler->isRest()) {
                $LogsTable = $this->fetchTable('Logs');
                $save_results = ['attributes' => 0, 'objects' => 0, 'eventReports' => 0];
                foreach ($results['results']['Attribute'] as $attribute) {
                    $this->Events->Attributes->captureAttribute($attribute, $target_id, $this->ACL->getUser()->toArray());
                }
                foreach ($results['results']['Object'] as $object) {
                    $this->Events->Object->captureObject($object, $target_id, $this->ACL->getUser()->toArray());
                }
                foreach ($results['results']['EventReport'] as $report) {
                    $this->Events->EventReport->captureReport($this->ACL->getUser()->toArray(), $report, $target_id);
                }
                $event = $this->Events->fetchEvent(
                    $this->ACL->getUser()->toArray(),
                    [
                        'eventid' => $target_id
                    ]
                );
                return $this->RestResponse->viewData($event, $this->response->getType());
            }
            $event = $this->Events->handleMispFormatFromModuleResult($results);
            $event['Event'] = $target_event['Event'];
            $distributions = $this->Events->Attributes->distributionLevels;
            $sgs = $this->Events->SharingGroup->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'name', 1);
            if (empty($sgs)) {
                unset($distributions[4]);
            }
            $this->set('distributions', $distributions);
            $this->set('sgs', $sgs);
            $this->set('event', $event);
            $this->set('title_for_layout', __('Event merge results'));
            $this->set('title', __('Event merge results'));
            $this->set('importComment', 'Merged from event ' . $source_id);
            $this->render('resolved_misp_format');
        } else {
            $this->set('target_event', $target_event);
            $this->set('title_for_layout', __('Merge data from event'));
        }
    }

    public function populate($id, $regenerateUUIDs = false)
    {
        if ($this->request->is('get') && $this->ParamHandler->isRest()) {
            return $this->RestResponse->describe('Events', 'populate', false, $this->response->getType());
        }
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id, ['contain' => ['Orgc']]);
        if (!$event) {
            throw new NotFoundException(__('Invalid event'));
        }
        $id = $event['Event']['id']; // change possible event UUID with real ID
        // check if private and user not authorised to edit
        if (!$this->ACL->canModifyEvent($event) && !($this->ACL->getUser()['Role']['perm_sync'] && $this->ParamHandler->isRest())) {
            $message = __('You are not authorised to do that.');
            if ($this->ParamHandler->isRest()) {
                throw new ForbiddenException($message);
            } else {
                $this->Flash->error($message);
                $this->redirect(['controller' => 'events', 'action' => 'index']);
            }
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $data = $this->request->getData();
            if (isset($data['Event'])) {
                $regenerateUUIDs = $data['Event']['regenerate_uuids'] ?? false;
                $data = $data['Event'];
            }
            if (isset($data['json'])) {
                $data = $this->_jsonDecode($data['json']);
            }
            if (isset($data['Event'])) {
                $data = $data['Event'];
            }
            $eventToSave = $event;
            $capturedObjects = ['Attribute', 'Object', 'Tag', 'Galaxy', 'EventReport'];
            foreach ($capturedObjects as $objectType) {
                if (!empty($data[$objectType])) {
                    if (!empty($regenerateUUIDs)) {
                        foreach ($data[$objectType] as $i => $obj) {
                            unset($data[$objectType][$i]['id']);
                            unset($data[$objectType][$i]['uuid']);
                            if ($objectType === 'Object' && !empty($data[$objectType][$i]['Attribute'])) {
                                foreach ($data[$objectType][$i]['Attribute'] as $j => $attr) {
                                    unset($data[$objectType][$i]['Attribute'][$j]['id']);
                                    unset($data[$objectType][$i]['Attribute'][$j]['uuid']);
                                }
                            }
                        }
                    }
                    $eventToSave['Event'][$objectType] = $data[$objectType];
                }
            }
            $eventToSave['Event']['published'] = 0;
            $eventToSave['Event']['timestamp'] = time();
            $result = $this->Events->_edit($eventToSave, $this->ACL->getUser()->toArray(), $id);
            if ($this->ParamHandler->isRest()) {
                if ($result === true) {
                    // REST users want to see the newly created event
                    $metadata = $this->request->param('named.metadata');
                    $results = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), ['eventid' => $id, 'metadata' => $metadata]);
                    $event = $results[0];
                    return $this->__restResponse($event);
                } else {
                    $message = 'Error';
                    if ($this->ParamHandler->isRest()) {
                        if (isset($result['error'])) {
                            $errors = $result['error'];
                        } else {
                            $errors = $result;
                        }
                        return $this->RestResponse->saveFailResponse('Events', 'populate', $id, $errors, $this->response->getType());
                    } else {
                        $this->set(['message' => $message, '_serialize' => ['message']]);  // $this->Events->validationErrors
                        $this->render('populate');
                    }
                    return false;
                }
            }
            if ($result) {
                $this->Flash->success(__('The event has been saved'));
                $this->redirect(['action' => 'view', $id]);
            } else {
                $this->Flash->error(__('The event could not be saved. Please, try again.'));
            }
        }
        $this->set('event', $event);
    }

    public function edit($id = null)
    {
        if ($this->request->is('get') && $this->ParamHandler->isRest()) {
            return $this->RestResponse->describe('Events', 'edit', false, $this->response->getType());
        }
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id, ['contain' => ['Orgc', 'CryptographicKeys']]);
        if (!$event) {
            throw new NotFoundException(__('Invalid event'));
        }
        $id = $event['id']; // change possible event UUID with real ID
        // check if private and user not authorised to edit
        if (!$this->canModifyEvent($event) && !($this->ACL->getUser()['Role']['perm_sync'] && $this->ParamHandler->isRest())) {
            $message = __('You are not authorised to do that.');
            if ($this->ParamHandler->isRest()) {
                throw new ForbiddenException($message);
            } else {
                $this->Flash->error($message);
                $this->redirect(['controller' => 'events', 'action' => 'index']);
            }
        }
        if (
            !empty($event['protected']) &&
            $this->ACL->getUser()['Role']['perm_sync'] &&
            !$this->ACL->getUser()['Role']['perm_site_admin']
        ) {
            $pgp_signature = $this->request->header('x-pgp-signature');
            if (empty($pgp_signature)) {
                throw new MethodNotAllowedException(__('Protected event failed signature validation as no key was provided.'));
            }
            $raw_data = (string)$this->request->getBody();
            if (
                !$this->Events->CryptographicKeys->validateProtectedEvent(
                    $raw_data,
                    $this->ACL->getUser()->toArray(),
                    $pgp_signature,
                    $event
                )
            ) {
                throw new MethodNotAllowedException(__('Protected event failed signature validation.'));
            }
        }
        if (!$this->ParamHandler->isRest()) {
            $this->Events->insertLock($this->ACL->getUser()->toArray(), $id);
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if ($this->ParamHandler->isRest()) {
                $data = $this->request->getData();
                if (isset($data['response'])) {
                    $data = $this->Events->updateXMLArray($data, true);
                } else {
                    $data = $this->Events->updateXMLArray($data, false);
                }
                // Workaround for different structure in XML/array than what CakePHP expects
                if (isset($data['response'])) {
                    $data = $data['response'];
                }
                if (!isset($data)) {
                    $data = ['Event' => $data];
                }
                $fast_update = $this->request->getParam('named')['fast_update'] ?? false;
                if (!empty($data['fast_update'])) {
                    $fast_update = (bool)$data['fast_update'];
                }
                if ($fast_update) {
                    $this->Events->fast_update = true;
                    $this->Events->Attributes->fast_update = true;
                }
                $result = $this->Events->_edit($data, $this->ACL->getUser()->toArray(), $id, null, null, false);
                if ($result === true) {
                    // REST users want to see the newly created event
                    $metadata = $this->request->getParam('named')['metadata'] ?? [];
                    $results = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), ['eventid' => $id, 'metadata' => $metadata]);
                    $event = $results[0];
                    return $this->__restResponse($event);
                } else {
                    $message = 'Error';
                    if ($this->ParamHandler->isRest()) {
                        if (isset($result['error'])) {
                            $errors = $result['error'];
                        } else {
                            $errors = $result;
                        }
                        return $this->RestResponse->saveFailResponse('Events', 'edit', $id, $errors, $this->response->getType());
                    } else {
                        $this->set(['message' => $message, '_serialize' => ['message']]);  // $this->Events->validationErrors
                        $this->render('edit');
                    }
                    return false;
                }
            }
            // say what fields are to be updated
            $fieldList = ['date', 'threat_level_id', 'analysis', 'info', 'published', 'distribution', 'timestamp', 'sharing_group_id', 'extends_uuid'];

            // always force the org, but do not force it for admins
            if (!$this->isSiteAdmin()) {
                // set the same org as existed before
                $data['org_id'] = $event['org_id'];
            }
            // we probably also want to remove the published flag
            $data['published'] = 0;
            $data['timestamp'] = time();
            if ($this->Events->save($data, true, $fieldList)) {
                $this->Flash->success(__('The event has been saved'));
                $this->redirect(['action' => 'view', $id]);
            } else {
                $this->Flash->error(__('The event could not be saved. Please, try again.'));
            }
        } else {
            $data = $event;
        }

        // combobox for distribution
        $distributions = array_keys($this->Events->distributionDescriptions);
        $distributions = $this->_arrayToValuesIndexArray($distributions);
        $this->set('distributions', $distributions);

        // even if the SG is not local, we still want the option to select the currently assigned SG
        $sgs = $this->Events->SharingGroup->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'name', 1);
        $this->set('sharingGroups', $sgs);

        // tooltip for distribution
        $fieldDesc = [];
        $distributionLevels = $this->Events->distributionLevels;
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        $this->set('distributionLevels', $distributionLevels);
        foreach ($distributionLevels as $key => $value) {
            $fieldDesc['distribution'][$key] = $this->Events->distributionDescriptions[$key]['formdesc'];
        }

        // combobox for risks
        $threat_levels = $this->Events->ThreatLevel->find('all');
        $this->set('threatLevels', Hash::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
        $fieldDesc['threat_level_id'] = Hash::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.description');

        // combobox for analysis
        $this->set('sharingGroups', $sgs);
        // tooltip for analysis
        $analysisLevels = $this->Events->analysisLevels;
        foreach ($analysisLevels as $key => $value) {
            $fieldDesc['analysis'][$key] = $this->Events->analysisDescriptions[$key]['formdesc'];
        }
        $this->set('analysisLevels', $analysisLevels);
        $this->set('fieldDesc', $fieldDesc);
        $this->set('eventDescriptions', $this->Events->fieldDescriptions);
        $this->set('event', $event);
        $this->render('add');
    }

    public function delete($id = null)
    {
        if ($this->request->is(['post', 'put', 'delete'])) {
            $data = $this->request->getData();
            if (isset($data['id'])) {
                $data['Event'] = $data;
            }
            if (!isset($id) && isset($data['Event']['id'])) {
                $idList = $data['Event']['id'];
                if (!is_array($idList)) {
                    if (is_numeric($idList) || Validation::uuid($idList)) {
                        $idList = [$idList];
                    } else {
                        $idList = $this->_jsonDecode($idList);
                    }
                }
                if (empty($idList)) {
                    throw new NotFoundException(__('Invalid input.'));
                }
            } else {
                $idList = [$id];
            }

            $fails = [];
            $successes = [];
            foreach ($idList as $eid) {
                $event = $this->Events->find(
                    'all',
                    [
                        'conditions' => Validation::uuid($eid) ? ['Events.uuid' => $eid] : ['id' => $eid],
                        'recursive' => -1,
                    ]
                )->first();
                if (empty($event)) {
                    $fails[] = $eid; // event not found
                    continue;
                }
                if (!$this->ACL->canModifyEvent($event)) {
                    $fails[] = $eid; // user don't have permission to delete this event
                    continue;
                }
                $this->Events->insertLock($this->ACL->getUser()->toArray(), $event['Event']['id']);
                if ($this->Events->quickDelete($event)) {
                    $successes[] = $eid;
                } else {
                    $fails[] = $eid;
                }
            }
            if (count($idList) === 1) {
                $message = empty($successes) ?  __('Event was not deleted.') : __('Event deleted.');
            } else {
                $message = '';
                if (!empty($successes)) {
                    $message .= __n('%s event deleted.', '%s events deleted.', count($successes), count($successes));
                }
                if (!empty($fails)) {
                    $message .= count($fails) . ' event(s) could not be deleted due to insufficient privileges or the event not being found.';
                }
            }
            if ($this->ParamHandler->isRest()) {
                if (!empty($successes)) {
                    return $this->RestResponse->saveSuccessResponse('Events', 'delete', $id, $this->response->getType(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('Events', 'delete', false, $message, $this->response->getType());
                }
            } else {
                if (!empty($successes)) {
                    $this->Flash->success($message);
                } else {
                    $this->Flash->error($message);
                }
                $this->redirect(['action' => 'index']);
            }
        } else {
            $eventList = is_numeric($id) ? [$id] : $this->_jsonDecode($id);
            $data['Event']['id'] = json_encode($eventList);
            $this->set('idArray', $eventList);
            $this->render('ajax/eventDeleteConfirmationForm');
        }
    }

    public function unpublish($id = null)
    {
        $id = $this->Toolbox->findIdByUuid($this->Events, $id);
        $event = $this->Events->get($id);
        if (!$this->canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have the permission to do that.'));
        }
        $this->Events->insertLock($this->ACL->getUser()->toArray(), $id);
        if ($this->request->is('post') || $this->request->is('put')) {
            $fieldList = ['published', 'id', 'info'];
            $event['published'] = 0;
            $result = $this->Events->save($event, ['fieldList' => $fieldList]);
            if ($result) {
                $message = __('Event unpublished.');
                $kafkaTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
                if (Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_event_publish_notifications_enable') && !empty($kafkaTopic)) {
                    $kafkaPubTool = $this->Events->getKafkaPubTool();
                    $params = ['eventid' => $id];
                    if (Configure::read('Plugin.Kafka_include_attachments')) {
                        $params['includeAttachments'] = 1;
                    }
                    $pubEvent = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), $params);
                    if (!empty($pubEvent)) {
                        $kafkaPubTool->publishJson($kafkaTopic, $pubEvent[0], 'unpublish');
                    }
                }
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('events', 'unpublish', $id, false, $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(['action' => 'view', $id]);
                }
            } else {
                throw new MethodNotAllowedException('Could not unpublish Events.');
            }
        } else {
            $this->set('id', $id);
            $this->set('type', 'unpublish');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    public function publishSightings($id = null)
    {
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $result = $this->Events->publishSightingsRouter($event['Event']['id'], $this->ACL->getUser()->toArray());
            if (!Configure::read('MISP.background_jobs')) {
                if (!is_array($result)) {
                    // redirect to the view event page
                    $message = 'Sightings published';
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $message = sprintf('Sightings published but not pushed to %s, re-try later. If the issue persists, make sure that the correct sync user credentials are used for the server link and that the sync user on the remote server has authentication privileges.', $resultString);
                }
            } else {
                // update the DB to set the published flag
                // for background jobs, this should be done already
                $fieldList = ['id', 'info', 'sighting_timestamp'];
                $event['Event']['sighting_timestamp'] = time();
                $this->Events->save($event, ['fieldList' => $fieldList]);
                $message = 'Job queued';
            }
            if ($this->ParamHandler->isRest()) {
                $this->set('name', 'Publish Sightings');
                $this->set('message', $message);
                if (!empty($errors)) {
                    $this->set('errors', $errors);
                }
                $this->set('url', $this->baseurl . '/events/publishSightings/' . $event['Event']['id']);
                $this->set('id', $event['Event']['id']);
                $this->set('_serialize', ['name', 'message', 'url', 'id', 'errors']);
            } else {
                $this->Flash->success($message);
                $this->redirect(['action' => 'view', $event['Event']['id']]);
            }
        } else {
            $this->set('id', $id);
            $this->set('type', 'publishSightings');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    // Publishes the event without sending an alert email
    public function publish($id = null)
    {
        $event = $this->__prepareForPublish($id);

        // only allow form submit CSRF protection.
        if ($this->request->is('post') || $this->request->is('put')) {
            $errors = [];
            // Performs all the actions required to publish an event
            $result = $this->Events->publishRouter($event['id'], null, $this->ACL->getUser()->toArray());
            if (!Configure::read('MISP.background_jobs')) {
                if (!is_array($result)) {
                    if ($result === true) {
                        $message = __('Event published without alerts');
                    } else {
                        $message = __('Event publishing failed due to a blocking module failing. The reason for the failure: %s', $result);
                        $errors['Module'] = 'Module failure.';
                    }
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $message = __('Event published but not pushed to %s, re-try later. If the issue persists, make sure that the correct sync user credentials are used for the server link and that the sync user on the remote server has authentication privileges.', $resultString);
                }
            } else {
                $message = 'Job queued';
            }
            if ($this->ParamHandler->isRest()) {
                if (!empty($errors)) {
                    return $this->RestResponse->saveFailResponse('Events', 'publish', $event['id'], $errors);
                } else {
                    return $this->RestResponse->saveSuccessResponse('Events', 'publish', $event['id'], false, $message);
                }
            } else {
                if (!empty($errors)) {
                    $this->Flash->error($message);
                } else {
                    $this->Flash->success($message);
                }
                $this->redirect(['action' => 'view', $event['id']]);
            }
        } else {
            $servers = $this->Events->listServerToPush($event);
            $this->set('id', $event['id']);
            $this->set('servers', $servers);
            $this->set('type', 'publish');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    // Send out an alert email to all the users that wanted to be notified.
    // Users with a GnuPG key will get the mail encrypted, other users will get the mail unencrypted
    public function alert($id = null)
    {
        $event = $this->__prepareForPublish($id);

        // only allow form submit CSRF protection
        if ($this->request->is('post') || $this->request->is('put')) {
            $errors = [];
            // send out the email
            $emailResult = $this->Events->sendAlertEmailRouter($event['Event']['id'], $this->ACL->getUser()->toArray(), $event['Event']['publish_timestamp']);
            if (is_bool($emailResult) && $emailResult == true) {
                // Performs all the actions required to publish an event
                $result = $this->Events->publishRouter($event['Event']['id'], null, $this->ACL->getUser()->toArray());
                if (!is_array($result)) {
                    // redirect to the view event page
                    if (Configure::read('MISP.background_jobs')) {
                        $message = 'Job queued.';
                    } else {
                        $message = 'Email sent to all participants.';
                    }
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $message = __('Not published given no connection to %s but email sent to all participants.', $resultString);
                }
            } elseif (!is_bool($emailResult)) {
                // Performs all the actions required to publish an event
                $result = $this->Events->publishRouter($event['Event']['id'], null, $this->ACL->getUser()->toArray());
                if (!is_array($result)) {
                    if ($result === true) {
                        $message = __('Published but no email sent given GnuPG is not configured.');
                        $errors['GnuPG'] = 'GnuPG not set up.';
                    } else {
                        $message = $result;
                        $errors['Module'] = 'Module failure.';
                    }
                    // redirect to the view event page
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $errors['GnuPG'] = 'GnuPG not set up.';
                    $message = __('Not published given no connection to %s but no email sent given GnuPG is not configured.', $resultString);
                }
            } else {
                $message = 'Sending of email failed';
                $errors['email'] = 'The sending of emails failed.';
            }
            if ($this->ParamHandler->isRest()) {
                if (!empty($errors)) {
                    return $this->RestResponse->saveFailResponse('Events', 'alert', $event['Event']['id'], $errors);
                } else {
                    return $this->RestResponse->saveSuccessResponse('Events', 'alert', $event['Event']['id'], false, $message);
                }
            } else {
                if (isset($errors['failed_servers'])) {
                    $this->Flash->error($message);
                } else {
                    $this->Flash->success($message);
                }
                $this->redirect(['action' => 'view', $event['Event']['id']]);
            }
        } else {
            $servers = $this->Events->listServerToPush($event);
            $this->set('id', $event['Event']['id']);
            $this->set('servers', $servers);
            $this->set('type', 'alert');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    /**
     * @param int|string $id Event ID or UUID
     * @return array
     */
    private function __prepareForPublish($id)
    {
        if (empty($id)) {
            throw new NotFoundException(__('Invalid Events.'));
        }
        $event = $this->Events->find(
            'all',
            [
                'conditions' => Validation::uuid($id) ? ['Events.uuid' => $id] : ['id' => $id],
                'recursive' => -1,
                'fields' => ['id', 'info', 'publish_timestamp', 'orgc_id', 'user_id'],
            ]
        )->first();
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Events.'));
        }
        if (!$this->canPublishEvent($event)) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if (!$this->ParamHandler->isRest()) {
            $this->Events->insertLock($this->ACL->getUser()->toArray(), $event['Event']['id']);

            if ($this->request->is('post') || $this->request->is('put')) {
                $publishable = $this->Events->checkIfPublishable($event['Event']['id']);
                if ($publishable !== true) {
                    $this->Flash->error(__('Could not publish event - no tag for required taxonomies missing: %s', implode(', ', $publishable)));
                    $this->redirect(['action' => 'view', $event['Event']['id']]);
                }
            }
        }
        if (
            Configure::read('MISP.block_publishing_for_same_creator', false) &&
            $this->ACL->getUser()->toArray()['id'] == $event['Event']['user_id']
        ) {
            $message = __('Could not publish the event, the publishing user cannot be the same as the event creator as per this instance\'s configuration.');
            if (!$this->ParamHandler->isRest()) {
                $this->Flash->error($message);
            }
            throw new MethodNotAllowedException($message);
        }

        return $event;
    }

    // Send out an contact email to the person who posted the Events.
    // Users with a GnuPG key will get the mail encrypted, other users will get the mail unencrypted
    public function contact($id = null)
    {
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id, ['contain' => ['Orgc']]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        // User has filled in his contact form, send out the email.
        if ($this->request->is('post') || $this->request->is('put')) {
            $data = $this->request->getData();
            if (!isset($data['Event'])) {
                $data = ['Event' => $data];
            }
            $message = $data['Event']['message'];
            if (empty($message)) {
                $error = __('You must specify a message.');
                if ($this->ParamHandler->isRest()) {
                    throw new MethodNotAllowedException($error);
                } else {
                    $this->Flash->error($error);
                    $this->redirect(['action' => 'contact', $event['Event']['id']]);
                }
            }

            $creator_only = false;
            if (isset($data['Event']['person'])) {
                $creator_only = $data['Event']['person'];
            }
            $user = $this->ACL->getUser()->toArray();
            $user = $this->Events->User->fillKeysToUser($user);

            $success = $this->Events->sendContactEmailRouter($event['Event']['id'], $message, $creator_only, $user);
            if ($success) {
                $return_message = __('Email sent to the reporter.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Events', 'contact', $event['Event']['id'], $this->response->getType(), $return_message);
                } else {
                    $this->Flash->success($return_message);
                    // redirect to the view event page
                    $this->redirect(['action' => 'view', $event['Event']['id']]);
                }
            } else {
                $return_message = __('Sending of email failed.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Events', 'contact', $event['Event']['id'], $return_message, $this->response->getType());
                } else {
                    $this->Flash->error($return_message, 'default', [], 'error');
                    // redirect to the view event page
                    $this->redirect(['action' => 'view', $event['Event']['id']]);
                }
            }
        }
        $this->set('event', $event);
        $this->set('mayModify', $this->ACL->canModifyEvent($event));
    }

    public function automation($legacy = false)
    {
        // Simply display a static view
        $export = new BroExport();
        $temp = $export->mispTypes;
        $broTypes = ['all' => 'All types listed below.'];
        foreach ($temp as $broType => $mispTypes) {
            foreach ($mispTypes as $mT) {
                $broTypes[$broType][] = $mT[0];
            }
            $broTypes[$broType] = implode(', ', $broTypes[$broType]);
        }
        $ServersTable = $this->fetchTable('Servers');
        $this->set('command_line_functions', $ServersTable->command_line_functions);
        $this->set('broTypes', $broTypes);
        // generate the list of Attribute types
        $AttributesTable = $this->fetchTable('Attributes');
        $this->set('sigTypes', array_keys($AttributesTable->typeDefinitions));
        $ServersTable = $this->fetchTable('Servers');
        if (empty(Configure::read('Security.advanced_authkeys'))) {
            $authkey = $this->Events->User->find(
                'all',
                [
                    'fields' => ['authkey'],
                    'conditions' => ['User.id' => $this->ACL->getUser()->toArray()['id']],
                    'recursive' => -1
                ]
            )->first()['authkey'];
            $this->set('authkey', $authkey);
        }
        $rpzSettings = $ServersTable->retrieveCurrentSettings('Plugin', 'RPZ_');
        $this->set('rpzSettings', $rpzSettings);
        $this->set('hashTypes', array_keys(Attribute::FILE_HASH_TYPES));
        if ($legacy) {
            $this->render('legacy_automation');
        }
    }

    public function export()
    {
        $filesize_units = ['B', 'KB', 'MB', 'GB', 'TB'];
        if ($this->isSiteAdmin()) {
            $this->Flash->info(__('Warning, you are logged in as a site admin, any export that you generate will contain the FULL UNRESTRICTED data-set. If you would like to generate an export for your own organisation, please log in with a different user.'));
        }
        // Check if the background jobs are enabled - if not, fall back to old export page.
        if (Configure::read('MISP.background_jobs') && !Configure::read('MISP.disable_cached_exports')) {
            $now = time();

            // as a site admin we'll use the ADMIN identifier, not to overwrite the cached files of our own org with a file that includes too much data.
            $org_name = $this->isSiteAdmin() ? 'ADMIN' : $this->ACL->getUser()['Organisation']['name'];
            $conditions = $this->Events->createEventConditions($this->ACL->getUser()->toArray());
            $this->Events->recursive = -1;
            $newestEvent = $this->Events->find(
                'all',
                [
                    'conditions' => $conditions,
                    'fields' => 'timestamp',
                    'order' => 'Events.timestamp DESC',
                ]
            )->first();
            $newestEventPublished = $this->Events->find(
                'all',
                [
                    'conditions' => ['AND' => [$conditions, ['published' => 1]]],
                    'fields' => 'timestamp',
                    'order' => 'Events.timestamp DESC',
                ]
            )->first();
            $JobsTable = $this->fetchTable('Jobs');
            $exportTypes = $this->Events->exportTypes();
            foreach ($exportTypes as $k => $type) {
                if ($type['requiresPublished']) {
                    $tempNewestEvent = $newestEventPublished;
                } else {
                    $tempNewestEvent = $newestEvent;
                }
                $job = $JobsTable->find(
                    'all',
                    [
                        'fields' => ['id', 'progress'],
                        'conditions' => [
                            'job_type' => 'cache_' . $k,
                            'org_id' => $this->isSiteAdmin() ? 0 : $this->ACL->getUser()['org_id']
                        ],
                        'order' => ['Job.id' => 'desc']
                    ]
                )->first();
                $dir = new SplFileObject(APP . '../tmp/cached_exports/');

                if (!$dir->isDir()) {
                    mkdir($dir->getPathname(), 0755, true);
                }

                if ($k === 'text') {
                    // Since all of the text export files are generated together, we might as well just check for a single one md5.
                    $file = new SplFileObject($dir->getPathname() . DS . 'misp.text_md5.' . $org_name . $type['extension']);
                } else {
                    $file = new SplFileObject($dir->getPathname() . DS . 'misp.' . $k . '.' . $org_name . $type['extension']);
                }
                if (!$file->isReadable()) {
                    if (empty($tempNewestEvent)) {
                        $lastModified = 'No valid events';
                        $exportTypes[$k]['recommendation'] = 0;
                    } else {
                        $lastModified = 'N/A';
                        $exportTypes[$k]['recommendation'] = 1;
                    }
                } else {
                    $filesize = $file->getSize();
                    $filesize_unit_index = 0;
                    while ($filesize > 1024) {
                        $filesize_unit_index++;
                        $filesize = $filesize / 1024;
                    }
                    $exportTypes[$k]['filesize'] = round($filesize, 1) . $filesize_units[$filesize_unit_index];
                    $fileChange = $file->getMTime();
                    $lastModified = $this->__timeDifference($now, $fileChange);
                    if (empty($tempNewestEvent) || $fileChange > $tempNewestEvent['Event']['timestamp']) {
                        if (empty($tempNewestEvent)) {
                            $lastModified = 'No valid events';
                        }
                        $exportTypes[$k]['recommendation'] = 0;
                    } else {
                        $exportTypes[$k]['recommendation'] = 1;
                    }
                }

                $exportTypes[$k]['lastModified'] = $lastModified;
                if (!empty($job)) {
                    $exportTypes[$k]['job_id'] = $job['Job']['id'];
                    $exportTypes[$k]['progress'] = $job['Job']['progress'];
                } else {
                    $exportTypes[$k]['job_id'] = -1;
                    $exportTypes[$k]['progress'] = 0;
                }
            }
        } else {
            $exportTypes = [];
        }

        $this->set('sigTypes', array_keys($this->Events->Attributes->typeDefinitions));
        $this->set('export_types', $exportTypes);
    }

    public function downloadExport($type, $extra = null)
    {
        if (Configure::read('MISP.disable_cached_exports')) {
            throw new MethodNotAllowedException(__('This feature is currently disabled'));
        }
        if ($this->isSiteAdmin()) {
            $org = 'ADMIN';
        } else {
            $org = $this->ACL->getUser()['Organisation']['name'];
        }
        $this->autoRender = false;
        if ($extra != null) {
            $extra = '_' . $extra;
        }
        $exportType = $this->Events->exportTypes()[$type];
        $this->response->withType($exportType['extension']);
        $path = 'tmp/cached_exports/' . $type . DS . 'misp.' . strtolower($exportType['type']) . $extra . '.' . $org . $exportType['extension'];
        $this->response->withFile($path, ['download' => true]);
    }

    private function __timeDifference($now, $then)
    {
        $periods = ["second", "minute", "hour", "day", "week", "month", "year"];
        $lengths = ["60", "60", "24", "7", "4.35", "12"];
        $difference = $now - $then;
        for ($j = 0; $difference >= $lengths[$j] && $j < count($lengths) - 1; $j++) {
            $difference /= $lengths[$j];
        }
        $difference = round($difference);
        if ($difference != 1) {
            $periods[$j] .= "s";
        }
        return $difference . " " . $periods[$j] . " ago";
    }

    public function restSearchExport($id = null, $returnFormat = null)
    {
        if ($returnFormat === null) {
            $exportFormats = [
                'attack' => __('Attack matrix'),
                'attack-sightings' => __('Attack matrix by sightings'),
                'context' => __('Aggregated context data'),
                'context-markdown' => __('Aggregated context data as Markdown'),
                'csv' => __('CSV'),
                'hashes' => __('Hashes'),
                'hosts' => __('Hosts file'),
                'json' => __('MISP JSON'),
                'netfilter' => __('Netfilter'),
                'opendata' => __('Open data'),
                'openioc' => __('OpenIOC'),
                'rpz' => __('RPZ'),
                'snort' => __('Snort rules'),
                'stix' => __('STIX 1 XML'),
                'stix-json' => __('STIX 1 JSON'),
                'stix2' => __('STIX 2'),
                'suricata' => __('Suricata rules'),
                'text' => __('Text file'),
                'xml' => __('MISP XML'),
                'yara' => __('YARA rules'),
                'yara-json' => __('YARA rules (JSON)'),
            ];

            $idList = is_numeric($id) ? [$id] : $this->_jsonDecode($id);
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }
            $this->set('idList', $idList);
            $this->set('exportFormats', $exportFormats);
            $this->render('ajax/eventRestSearchExportConfirmationForm');
        } else {
            $returnFormat = !isset($this->Events->validFormats[$returnFormat]) ? 'json' : $returnFormat;
            $idList = $id;
            if (!is_array($idList)) {
                if (is_numeric($idList) || Validation::uuid($idList)) {
                    $idList = [$idList];
                } else {
                    $idList = $this->_jsonDecode($idList);
                }
            }
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }
            $filters = [
                'eventid' => $idList,
                'published' => [true, false], // fetch published and unpublished events
            ];

            $elementCounter = 0;
            $renderView = false;
            $responseType = $this->Events->validFormats[$returnFormat][0];
            $final = $this->Events->restSearch($this->ACL->getUser()->toArray(), $returnFormat, $filters, false, false, $elementCounter, $renderView);
            if ($renderView) {
                $final = JsonTool::decode($final->intoString());
                $this->set($final);
                $this->set('responseType', $responseType);
                $this->set('returnFormat', $returnFormat);
                $this->set('renderView', $renderView);
                $this->render('/Events/eventRestSearchExportResult');
            } else {
                $filename = $this->RestSearch->getFilename($filters, 'Event', $responseType);
                return $this->RestResponse->viewData(
                    $final,
                    $responseType,
                    false,
                    true,
                    $filename,
                    [
                        'X-Result-Count' => $elementCounter,
                        'X-Export-Module-Used' => $returnFormat,
                        'X-Response-Format' => $responseType
                    ]
                );
            }
        }
    }

    public function xml($key, $eventid = false, $withAttachment = false, $tags = false, $from = false, $to = false, $last = false)
    {
        $this->_legacyAPIRemap(
            [
                'paramArray' => [
                    'key', 'eventid', 'withAttachment', 'tags', 'from', 'to', 'last'
                ],
                'request' => $this->request,
                'named_params' => $this->params['named'],
                'ordered_url_params' => func_get_args(),
                'injectedParams' => [
                    'returnFormat' => 'xml'
                ]
            ]
        );
        return $this->restSearch();
    }

    public function nids()
    {
        $this->_legacyAPIRemap(
            [
                'paramArray' => [
                    'format', 'key', 'id', 'continue', 'tags', 'from', 'to', 'last',
                    'type', 'enforceWarninglist', 'includeAllTags', 'eventid'
                ],
                'request' => $this->request,
                'named_params' => $this->params['named'],
                'ordered_url_params' => func_get_args()
            ]
        );
        if (empty($this->_legacyParams['returnFormat'])) {
            $this->_legacyParams['returnFormat'] = 'suricata';
        }
        return $this->restSearch();
    }

    public function hids($type)
    {
        $typeMappings = [
            'md5' => ['malware-sample', 'md5', 'filename|md5'],
            'sha1' => ['sha1', 'filename|sha1'],
            'sha256' => ['sha256', 'filename|sha256']
        ];
        $ordered_url_params = func_get_args();
        unset($ordered_url_params[0]);
        $ordered_url_params = array_values($ordered_url_params);
        $this->scopeOverride = 'Attribute';
        $this->_legacyAPIRemap(
            [
                'paramArray' => [
                    'key', 'id', 'withAttachment', 'tags', 'from', 'to', 'last'
                ],
                'request' => $this->request,
                'named_params' => $this->params['named'],
                'ordered_url_params' => $ordered_url_params,
                'injectedParams' => [
                    'returnFormat' => 'hashes',
                    'type' => (isset($typeMappings[$type])) ? $typeMappings[$type] : $type
                ]
            ]
        );
        return $this->restSearch();
    }

    // DEPRECATED - use restSearch with "returnFormat":"csv"
    public function csv($key)
    {
        $this->_legacyAPIRemap(
            [
                'paramArray' => [
                    'key', 'eventid', 'ignore', 'tags', 'category', 'type', 'includeContext',
                    'from', 'to', 'last', 'headerless', 'enforceWarninglist', 'value', 'timestamp'
                ],
                'key' => $key,
                'request' => $this->request,
                'named_params' => $this->params['named'],
                'ordered_url_params' => func_get_args(),
                'injectedParams' => [
                    'returnFormat' => 'csv',
                    'to_ids' => '1',
                    'published' => '1'
                ]
            ]
        );
        return $this->restSearch();
    }

    public function _addIOCFile($id)
    {
        $data = $this->request->getData();
        if (
            !empty($data) && $data['Event']['submittedioc']['size'] > 0 &&
            is_uploaded_file($data['Event']['submittedioc']['tmp_name'])
        ) {
            if (!$this->Events->checkFilename($data['Event']['submittedioc']['name'])) {
                throw new Exception(__('Filename not allowed.'));
            }

            // Load event and populate the event data
            $this->Events->id = $id;
            $this->Events->recursive = -1;
            if (!$this->Events->exists()) {
                throw new NotFoundException(__('Invalid event'));
            }
            $this->Events->read(null, $id);
            $saveEvent['Event'] = $this->Events->data['Event'];
            $saveEvent['Event']['published'] = false;
            $dist = '5';
            if (Configure::read('MISP.default_attribute_distribution') != null) {
                if (Configure::read('MISP.default_attribute_distribution') === 'event') {
                    $dist = '5';
                } else {
                    $dist = '';
                    $dist .= Configure::read('MISP.default_attribute_distribution');
                }
            }
            // read XML
            $xmlFileData = FileAccessTool::readFromFile($data['Event']['submittedioc']['tmp_name'], $data['Event']['submittedioc']['size']);
            $event = $this->IOCImport->readXML($xmlFileData, $id, $dist, $data['Event']['submittedioc']['name']);

            // make some changes to have $saveEvent in the format that is needed to save the event together with its attributes
            $fails = $event['Fails'];
            $saveEvent['Attribute'] = $event['Attribute'];
            // we've already stored these elsewhere, unset them so we can extract the event related data
            unset($event['Attribute']);
            unset($event['Fails']);

            // add the original openIOC file as an attachment
            $saveEvent['Attribute'][] = [
                'category' => 'External analysis',
                'uuid' =>  Text::uuid(),
                'type' => 'attachment',
                'sharing_group_id' => '0',
                'value' => $data['Event']['submittedioc']['name'],
                'to_ids' => false,
                'distribution' => $dist,
                'data' => base64_encode($xmlFileData),
                'comment' => 'OpenIOC import source file'
            ];

            // LATER we might want to let an ioc create the event data automatically in a later version
            // save the event related data into $saveEvent['Event']
            //$saveEvent['Event'] = $event;
            //$saveEvent['Event']['id'] = $id;

            $fieldList = [
                'Event' => ['published', 'timestamp'],
                'Attribute' => ['event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'distribution', 'timestamp', 'comment', 'sharing_group_id']
            ];
            // Save it all
            $saveResult = $this->Events->saveAssociated($saveEvent, ['validate' => true, 'fieldList' => $fieldList]);
            // set stuff for the view and render the showIOCResults view.
            $this->set('attributes', $saveEvent['Attribute']);
            if (isset($fails)) {
                $this->set('fails', $fails);
            }
            $this->set('eventId', $id);
            $this->set('graph', $event['Graph']);
            $this->set('saveEvent', $saveEvent);
            $this->render('showIOCResults');
        }
    }

    public function downloadOpenIOCEvent($key, $eventid, $enforceWarninglist = false)
    {
        // return a downloadable text file called misp.openIOC.<eventId>.ioc for individual events
        // TODO implement mass download of all events - maybe in a zip file?
        $this->response->withType('text');  // set the content type
        if ($eventid == null) {
            throw new Exception(__('Not yet implemented'));
        }
        $this->layout = 'text/default';

        if ($key != 'download') {
            $user = $this->_checkAuthUser($key);
            if (!$user) {
                throw new UnauthorizedException(__('This authentication key is not authorized to be used for exports. Contact your administrator.'));
            }
        } else {
            if (!$this->ACL->getUser()['id']) {
                throw new UnauthorizedException(__('You have to be logged in to do that.'));
            }
        }

        // get the event if it exists and load it together with its attributes
        $this->Events->id = $eventid;
        if (!$this->Events->exists()) {
            throw new NotFoundException(__('Invalid event or not authorised.'));
        }
        $event = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), $options = ['eventid' => $eventid, 'to_ids' => 1, 'enforceWarninglist' => $enforceWarninglist]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event or not authorised.'));
        }
        $AllowedlistsTable = $this->fetchTable('Allowedlists');
        $temp = $AllowedlistsTable->removeAllowedlistedFromArray([$event[0]], false);
        $event = $temp[0];

        // send the event and the vars needed to check authorisation to the Component
        $this->IOCExport = new IOCExportTool();
        $final = $this->IOCExport->buildAll($this->ACL->getUser()->toArray(), $event);
        $this->response->withType('xml');
        $this->autoRender = false;
        $this->response->withStringBody($final);
        $this->response->withDownload('misp.openIOC' . $eventid . '.ioc');
        return $this->response;
    }

    public function proposalEventIndex()
    {
        $ShadowAttributesTable = $this->fetchTable('ShadowAttributes');
        $conditions = ['deleted' => 0];
        if (!$this->isSiteAdmin()) {
            $conditions[] = ['event_org_id' => $this->ACL->getUser()['org_id']];
        }
        $result = $ShadowAttributesTable->find(
            'column',
            [
                'fields' => ['event_id'],
                'conditions' => $conditions,
                'unique' => true,
            ]
        );
        $this->Events->recursive = -1;

        if (empty($result)) {
            $conditions = ['id' => -1];
        } else {
            $conditions = ['id' => $result];
        }
        $this->paginate = [
            'fields' => ['id', 'Events.org_id', 'Events.orgc_id', 'Events.publish_timestamp', 'Events.distribution', 'Events.info', 'Events.date', 'Events.published'],
            'conditions' => $conditions,
            'contain' => [
                'User' => [
                    'fields' => [
                        'User.email'
                    ]
                ],
                'ShadowAttribute' => [
                    'fields' => [
                        'ShadowAttributes.id', 'ShadowAttributes.org_id', 'ShadowAttributes.event_id'
                    ],
                    'conditions' => [
                        'ShadowAttributes.deleted' => 0
                    ],
                ],
            ]
        ];
        $events = $this->paginate();
        $orgIds = [];
        foreach ($events as $k => $event) {
            $orgs = [];
            foreach ($event['ShadowAttribute'] as $sa) {
                if (!in_array($sa['org_id'], $orgs)) {
                    $orgs[] = $sa['org_id'];
                }
                if (!in_array($sa['org_id'], $orgIds)) {
                    $orgIds[] = $sa['org_id'];
                }
            }
            $events[$k]['orgArray'] = $orgs;
            $events[$k]['Event']['proposal_count'] = count($event['ShadowAttribute']);
        }
        $orgs = $this->Events->Orgc->find(
            'list',
            [
                'conditions' => ['Orgc.id' => $orgIds],
                'fields' => ['Orgc.id', 'Orgc.name']
            ]
        );
        $this->set('orgs', $orgs);
        $this->set('events', $events);
        $this->set('eventDescriptions', $this->Events->fieldDescriptions);
        $this->set('analysisLevels', $this->Events->analysisLevels);
        $this->set('distributionLevels', $this->Events->distributionLevels);
    }

    public function reportValidationIssuesEvents()
    {
        // search for validation problems in the events
        if (!self::isSiteAdmin()) {
            throw new NotFoundException();
        }
        $results = $this->Events->reportValidationIssuesEvents();
        $result = $results[0];
        $count = $results[1];
        $this->set('result', $result);
        $this->set('count', $count);
    }

    public function addTag($id = false, $tag_id = false)
    {
        $rearrangeRules = [
            'request' => false,
            'Event' => false,
            'tag_id' => 'tag',
            'event_id' => 'event',
            'id' => 'event'
        ];
        $RearrangeTool = new RequestRearrangeTool();
        $data = $RearrangeTool->rearrangeArray($this->request->getData(), $rearrangeRules);
        if ($id === false) {
            $id = $data['event'];
        }
        $conditions = ['id' => $id];
        if (Validation::uuid($id)) {
            $conditions = ['Events.uuid' => $id];
        }
        $event = $this->Events->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => $conditions
            ]
        )->first();
        if (empty($event)) {
            return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Invalid Events.']), 'status' => 200, 'type' => 'json']);
        }
        $id = $event['Event']['id'];
        $local = !empty($this->params['named']['local']);
        if (!$this->request->is('post')) {
            $this->set('local', $local);
            $this->set('object_id', $id);
            $this->set('scope', 'Event');
            $this->layout = false;
            $this->autoRender = false;
            $this->render('/Events/add_tag');
        } else {
            if ($tag_id === false) {
                $tag_id = $data['tag'];
            }
            if (!$this->ACL->canModifyTag($event, $local)) {
                return new Response(['body' => json_encode(['saved' => false, 'errors' => 'You don\'t have permission to do that.']), 'status' => 200, 'type' => 'json']);
            }
            if (!is_numeric($tag_id)) {
                if (preg_match('/^collection_[0-9]+$/i', $tag_id)) {
                    $tagChoice = explode('_', $tag_id)[1];
                    $TagCollectionsTable = $this->fetchTable('TagCollections');
                    $tagCollection = $TagCollectionsTable->fetchTagCollection($this->ACL->getUser()->toArray(), ['conditions' => ['TagCollection.id' => $tagChoice]]);
                    if (empty($tagCollection)) {
                        return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Invalid Tag Collection.']), 'status' => 200, 'type' => 'json']);
                    }
                    $tag_id_list = [];
                    foreach ($tagCollection[0]['TagCollectionTag'] as $tagCollectionTag) {
                        $tag_id_list[] = $tagCollectionTag['tag_id'];
                    }
                } else {
                    $tag_ids = json_decode($tag_id);
                    if ($tag_ids !== null) { // can decode json
                        $tag_id_list = [];
                        foreach ($tag_ids as $tag_id) {
                            if (preg_match('/^collection_[0-9]+$/i', $tag_id)) {
                                $tagChoice = explode('_', $tag_id)[1];
                                $TagCollectionsTable = $this->fetchTable('TagCollections');
                                $tagCollection = $TagCollectionsTable->fetchTagCollection($this->ACL->getUser()->toArray(), ['conditions' => ['TagCollection.id' => $tagChoice]]);
                                if (empty($tagCollection)) {
                                    return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Invalid Tag Collection.']), 'status' => 200, 'type' => 'json']);
                                }
                                foreach ($tagCollection[0]['TagCollectionTag'] as $tagCollectionTag) {
                                    $tag_id_list[] = $tagCollectionTag['tag_id'];
                                }
                            } else {
                                $tag_id_list[] = $tag_id;
                            }
                        }
                    } else {
                        $tagId = $this->Events->EventTag->Tag->lookupTagIdForUser($this->ACL->getUser()->toArray(), trim($tag_id));
                        if (empty($tagId)) {
                            return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Invalid Tag.']), 'status' => 200, 'type' => 'json']);
                        }
                        $tag_id = $tagId;
                    }
                }
            }
            $this->autoRender = false;
            $success = 0;
            $fails = [];
            if (empty($tag_id_list)) {
                $tag_id_list = [$tag_id];
            }

            if (empty($tag_id_list)) {
                return new Response(['body' => json_encode(['saved' => false, 'errors' => __('Nothing to add.')]), 'status' => 200, 'type' => 'json']);
            }

            $TaxonomiesTable = $this->fetchTable('Taxonomies');
            foreach ($tag_id_list as $tag_id) {
                $conditions = $this->Events->EventTag->Tag->createConditions($this->ACL->getUser()->toArray());
                $conditions['Tag.id'] = $tag_id;
                $tag = $this->Events->EventTag->Tag->find(
                    'all',
                    [
                        'conditions' => $conditions,
                        'recursive' => -1,
                        'fields' => ['Tag.name', 'Tag.local_only']
                    ]
                )->first();
                if (!$tag) {
                    $fails[$tag_id] = __('Tag not found.');
                    continue;
                }
                $found = $this->Events->EventTag->hasAny(
                    [
                        'event_id' => $id,
                        'tag_id' => $tag_id
                    ]
                );
                if ($found) {
                    $fails[$tag_id] = __('Tag is already attached to this Events.');
                    continue;
                }
                $tagsOnEvent = $this->Events->EventTag->find(
                    'column',
                    [
                        'conditions' => [
                            'EventTag.event_id' => $id,
                            'EventTag.local' => $local
                        ],
                        'contain' => 'Tag',
                        'fields' => ['Tag.name'],
                        'recursive' => -1
                    ]
                );
                $exclusiveTestPassed = $TaxonomiesTable->checkIfNewTagIsAllowedByTaxonomy($tag['Tag']['name'], $tagsOnEvent);
                if (!$exclusiveTestPassed) {
                    $fails[$tag_id] = __('Tag is not allowed due to taxonomy exclusivity settings');
                    continue;
                }
                if ($tag['Tag']['local_only'] && !$local) {
                    $fails[$tag_id] = __('Invalid Tag. This tag can only be set as a local tag.');
                    continue;
                }
                $this->Events->EventTag->create();
                if ($this->Events->EventTag->save(['event_id' => $id, 'tag_id' => $tag_id, 'local' => $local])) {
                    if (!$local) {
                        $this->Events->unpublishEvent($event);
                    }
                    $LogsTable = $this->fetchTable('Logs');
                    $LogsTable->createLogEntry(
                        $this->ACL->getUser()->toArray(),
                        'tag',
                        'Event',
                        $id,
                        sprintf(
                            'Attached%s tag (%s) "%s" to event (%s)',
                            $local ? ' local' : '',
                            $tag_id,
                            $tag['Tag']['name'],
                            $id
                        ),
                        sprintf(
                            'Event (%s) tagged as Tag (%s)%s',
                            $id,
                            $tag_id,
                            $local ? ' locally' : ''
                        )
                    );
                    ++$success;
                } else {
                    $fails[$tag_id] = __('Tag could not be added.');
                }
            }

            if ($success && empty($fails)) {
                $body = ['saved' => true, 'success' => __n('Tag added.', 'Tags added.', $success), 'check_publish' => true];
            } else if ($success && !empty($fails)) {
                $message = __n('Tag added', '%s tags added', $success, $success);
                $message .= __(', but %s could not be added: %s', count($fails), implode(', ', $fails));
                $body = ['saved' => true, 'success' => $message, 'check_publish' => true];
            } else {
                $body = ['saved' => false, 'errors' => implode(', ', $fails)];
            }
            return new Response(['body' => json_encode($body), 'status' => 200, 'type' => 'json']);
        }
    }

    public function removeTag($id = false, $tag_id = false, $galaxy = false)
    {
        if (!$this->request->is('post')) {
            $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
            if (!$event) {
                throw new NotFoundException(__('Invalid Events.'));
            }
            $eventTag = $this->Events->EventTag->find(
                'all',
                [
                    'conditions' => [
                        'event_id' => $event['Event']['id'],
                        'tag_id' => $tag_id,
                    ],
                    'contain' => ['Tag'],
                    'recursive' => -1,
                ]
            )->first();
            if (!$eventTag) {
                throw new NotFoundException(__('Invalid tag.'));
            }

            $this->set('is_local', $eventTag['EventTag']['local']);
            $this->set('tag', $eventTag);
            $this->set('id', $event['Event']['id']);
            $this->set('tag_id', $tag_id);
            $this->set('model', 'Event');
            $this->set('model_name', $event['Event']['info']);
            $this->render('/Attributes/ajax/tagRemoveConfirmation');
        } else {
            $data = $this->request->getData();
            $rearrangeRules = [
                'request' => false,
                'Event' => false,
                'tag_id' => 'tag',
                'event_id' => 'event',
                'id' => 'event'
            ];
            $RearrangeTool = new RequestRearrangeTool();
            $data = $RearrangeTool->rearrangeArray($data, $rearrangeRules);
            if ($id === false) {
                $id = $data['event'];
            }
            if ($tag_id === false) {
                $tag_id = $data['tag'];
            }
            if (empty($tag_id)) {
                return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Invalid ' . ($galaxy ? 'Galaxy' : 'Tag') . '.']), 'status' => 200, 'type' => 'json']);
            }
            if (!is_numeric($tag_id)) {
                $tag = $this->Events->EventTag->Tag->find('all', ['recursive' => -1, 'conditions' => ['LOWER(Tag.name) LIKE' => strtolower(trim($tag_id))]])->first();
                if (empty($tag)) {
                    return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Invalid ' . ($galaxy ? 'Galaxy' : 'Tag') . '.']), 'status' => 200, 'type' => 'json']);
                }
                $tag_id = $tag['Tag']['id'];
            }
            if (!is_numeric($id)) {
                $id = $data['Event']['id'];
            }
            $this->Events->recursive = -1;
            $event = $this->Events->read([], $id);
            $eventTag = $this->Events->EventTag->find(
                'all',
                [
                    'conditions' => [
                        'event_id' => $id,
                        'tag_id' => $tag_id
                    ],
                    'recursive' => -1,
                ]
            )->first();
            if (!$eventTag) {
                return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Invalid event - ' . ($galaxy ? 'galaxy' : 'tag') . ' combination.']), 'status' => 200, 'type' => 'json']);
            }
            // org should allow to (un)tag too, so that an event that gets pushed can be (un)tagged locally by the owning org
            if (!$this->ACL->canModifyTag($event, $eventTag['EventTag']['local'])) {
                return new Response(['body' => json_encode(['saved' => false, 'errors' => 'You don\'t have permission to do that.']), 'status' => 200, 'type' => 'json']);
            }
            $this->Events->insertLock($this->ACL->getUser()->toArray(), $id);
            $tag = $this->Events->EventTag->Tag->find(
                'all',
                [
                    'conditions' => ['Tag.id' => $tag_id],
                    'recursive' => -1,
                    'fields' => ['Tag.name']
                ]
            )->first();
            if ($this->Events->EventTag->delete($eventTag['EventTag']['id'])) {
                if (empty($eventTag['EventTag']['local'])) {
                    $this->Events->unpublishEvent($event);
                }
                $LogsTable = $this->fetchTable('Logs');
                $LogsTable->createLogEntry($this->ACL->getUser()->toArray(), 'tag', 'Event', $id, 'Removed tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" from event (' . $id . ')', 'Event (' . $id . ') untagged of Tag (' . $tag_id . ')');
                return new Response(['body' => json_encode(['saved' => true, 'success' => ($galaxy ? 'Galaxy' : 'Tag') . ' removed.', 'check_publish' => empty($eventTag['EventTag']['local'])]), 'status' => 200, 'type' => 'json']);
            } else {
                return new Response(['body' => json_encode(['saved' => false, 'errors' => ($galaxy ? 'Galaxy' : 'Tag') . ' could not be removed.']), 'status' => 200, 'type' => 'json']);
            }
        }
    }

    /*
     * adhereToWarninglists is used when querying this function via the API
     * possible options:
     *  - false: (default) ignore warninglists
     *  - 'soft': Unset the IDS flag of all attributes hitting on a warninglist item
     *  - true / 'hard': Block attributes from being added that have a hit in the warninglists
     * returnMetaAttributes is a flag that will force the API to return the results of the
     * parsing directly for external further processing. The flag is a simple boolean flag (0||1)
     */
    public function freeTextImport($id, $adhereToWarninglists = false, $returnMetaAttributes = false)
    {
        $this->request->allowMethod(['post', 'get']);

        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Events.'));
        }
        $this->set('event_id', $event['Event']['id']);
        if ($this->request->is('get')) {
            $this->layout = false;
            $data['Attribute']['event_id'] = $event['Event']['id'];
        } else if ($this->request->is('post')) {
            $data = $this->request->getData();
            $complexTypeTool = new ComplexTypeTool();
            $WarninglistsTable = $this->fetchTable('Warninglists');
            $complexTypeTool->setTLDs($WarninglistsTable->fetchTLDLists());
            $complexTypeTool->setSecurityVendorDomains($WarninglistsTable->fetchSecurityVendorDomains());
            if (!isset($data['Attribute'])) {
                $data = ['Attribute' => $data];
            }
            if (!isset($data['Attribute']['value'])) {
                $data['Attribute'] = ['value' => $data['Attribute']];
            }
            if (isset($data['Attribute']['adhereToWarninglists'])) {
                $adhereToWarninglists = $data['Attribute']['adhereToWarninglists'];
            }
            $resultArray = $complexTypeTool->checkFreeText($data['Attribute']['value']);
            foreach ($resultArray as &$attribute) {
                $attribute['to_ids'] = $this->Events->Attributes->typeDefinitions[$attribute['default_type']]['to_ids'];
            }
            if ($this->ParamHandler->isRest()) {
                // Keep this 'types' format for rest response, but it is not necessary for UI
                foreach ($resultArray as $key => $r) {
                    $temp = [];
                    foreach ($r['types'] as $type) {
                        $temp[$type] = $type;
                    }
                    $resultArray[$key]['types'] = $temp;
                }
                if ($returnMetaAttributes || !empty($data['Attribute']['returnMetaAttributes'])) {
                    return $this->RestResponse->viewData($resultArray, $this->response->getType());
                } else {
                    return $this->__pushFreetext(
                        $resultArray,
                        $event,
                        isset($data['Attribute']['distribution']) ? $data['Attribute']['distribution'] : false,
                        isset($data['Attribute']['sharing_group_id']) ? $data['Attribute']['sharing_group_id'] : false,
                        $adhereToWarninglists
                    );
                }
            }
            $this->Events->Attributes->fetchRelated($this->ACL->getUser()->toArray(), $resultArray);
            $typeCategoryMapping = [];
            foreach ($this->Events->Attributes->categoryDefinitions as $k => $cat) {
                foreach ($cat['types'] as $type) {
                    $typeCategoryMapping[$type][$k] = $k;
                }
            }
            $distributions = $this->Events->Attributes->distributionLevels;
            $sgs = $this->Events->SharingGroup->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'name', 1);
            if (empty($sgs)) {
                unset($distributions[4]);
            }

            $this->set('proposals', !$this->ACL->canModifyEvent($event));
            $this->set('distributions', $distributions);
            $this->set('sgs', $sgs);
            $this->set('event', $event);
            $this->set('mayModify', $this->ACL->canModifyEvent($event));
            $this->set('typeDefinitions', $this->Events->Attributes->typeDefinitions);
            $this->set('typeCategoryMapping', $typeCategoryMapping);
            $this->set('defaultAttributeDistribution', $this->Events->Attributes->defaultDistribution());
            $this->set('resultArray', $resultArray);
            $this->set('importComment', '');
            $this->set('title_for_layout', __('Freetext Import Results'));
            $this->set('title', __('Freetext Import Results'));
            $this->set('missingTldLists', $this->Warninglist->missingTldLists());
            $this->render('resolved_attributes');
        }
    }

    private function __pushFreetext($attributes, array $event, $distribution = false, $sg = false, $adhereToWarninglists = false)
    {
        if ($distribution === false) {
            if (Configure::read('MISP.default_attribute_distribution') != null) {
                $distribution = $this->Events->Attributes->defaultDistribution();
            } else {
                $distribution = 0;
            }
        }
        // prepare the default choices
        foreach ($attributes as $k => $attribute) {
            $attribute['type'] = $attribute['default_type'];
            unset($attribute['default_type']);
            unset($attribute['types']);
            if (isset($attribute['default_category'])) {
                $attribute['category'] = $attribute['default_category'];
                unset($attribute['default_category']);
            } else {
                $attribute['category'] = $this->Events->Attributes->typeDefinitions[$attribute['type']]['default_category'];
            }
            $attribute['distribution'] = $distribution;
            $attribute['event_id'] = $event['Event']['id'];
            $attributes[$k] = $attribute;
        }
        // actually save the attribute now
        $proposals = !$this->ACL->canModifyEvent($event);
        $temp = $this->Events->processFreeTextDataRouter($this->ACL->getUser()->toArray(), $attributes, $event['Event']['id'], '', $proposals, $adhereToWarninglists, empty(Configure::read('MISP.background_jobs')));
        if (empty(Configure::read('MISP.background_jobs'))) {
            $attributes = $temp;
        }
        // FIXME $attributes does not contain the onteflyattributes
        $attributes = array_values($attributes);
        return $this->RestResponse->viewData($attributes, $this->response->getType());
    }

    public function saveFreeText($id)
    {
        $this->request->allowMethod(['post']);
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (!$event) {
            throw new NotFoundException(__('Invalid Events.'));
        }

        $this->Events->insertLock($this->ACL->getUser()->toArray(), $id);
        $attributes = $this->_jsonDecode($this->request->getData()['Attribute']['JsonObject']);
        $defaultComment = $this->request->getData()['Attribute']['default_comment'];
        $proposals = !$this->ACL->canModifyEvent($event) || (isset($this->request->getData()['Attribute']['force']) && $this->request->getData()['Attribute']['force']);
        $flashMessage = $this->Events->processFreeTextDataRouter($this->ACL->getUser()->toArray(), $attributes, $id, $defaultComment, $proposals);
        $this->Flash->info($flashMessage);

        if ($this->request->is('ajax')) {
            return $this->RestResponse->viewData($flashMessage, $this->response->getType());
        } else {
            $this->redirect(['controller' => 'events', 'action' => 'view', $id]);
        }
    }

    public function stix2()
    {
        $this->_legacyAPIRemap(
            [
                'paramArray' => [
                    'key', 'id', 'withAttachment', 'tags', 'from', 'to', 'last'
                ],
                'request' => $this->request,
                'named_params' => $this->params['named'],
                'ordered_url_params' => func_get_args(),
                'injectedParams' => [
                    'returnFormat' => 'stix2'
                ],
                'alias' => [
                    'id' => 'eventid'
                ]
            ]
        );
        return $this->restSearch();
    }

    public function stix()
    {
        $this->_legacyAPIRemap(
            [
                'paramArray' => [
                    'key', 'id', 'withAttachment', 'tags', 'from', 'to', 'last'
                ],
                'request' => $this->request,
                'named_params' => $this->params['named'],
                'ordered_url_params' => func_get_args(),
                'injectedParams' => [
                    'returnFormat' => 'stix'
                ],
                'alias' => [
                    'id' => 'eventid'
                ]
            ]
        );
        return $this->restSearch();
    }

    public function filterEventIdsForPush()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint requires a POST request.'));
        }

        $incomingUuids = [];
        $incomingEvents = [];
        foreach ($this->request->getData() as $event) {
            $incomingUuids[] = $event['Event']['uuid'];
            $incomingEvents[$event['Event']['uuid']] = $event['Event']['timestamp'];
        }
        $events = $this->Events->find(
            'all',
            [
                'conditions' => ['Events.uuid' => $incomingUuids],
                'recursive' => -1,
                'fields' => ['Events.uuid', 'Events.timestamp', 'Events.locked'],
            ]
        );
        foreach ($events as $event) {
            if ($event['Event']['timestamp'] >= $incomingEvents[$event['Event']['uuid']]) {
                unset($incomingEvents[$event['Event']['uuid']]);
                continue;
            }
            if ($event['Event']['locked'] == 0) {
                unset($incomingEvents[$event['Event']['uuid']]);
            }
        }
        return $this->RestResponse->viewData(array_keys($incomingEvents), $this->response->getType());
    }

    public function checkuuid($uuid)
    {
        if (!$this->ACL->getUser()['Role']['perm_sync']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        $events = $this->Events->find(
            'all',
            [
                'conditions' => ['Events.uuid' => $uuid],
                'recursive' => -1,
                'fields' => ['Events.uuid'],
            ]
        )->first();
        $this->set('result', ['result' => empty($events)]);
    }

    public function pushProposals($uuid)
    {
        $message = "";
        $success = true;
        $counter = 0;
        if (!$this->ACL->getUser()['Role']['perm_sync'] || !$this->ACL->getUser()['Role']['perm_add']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if ($this->request->is('post')) {
            $event = $this->Events->find(
                'all',
                [
                    'conditions' => ['Events.uuid' => $uuid],
                    'contains' => [
                        'ShadowAttribute', 'Attribute' => [
                            'fields' => ['id', 'uuid', 'event_id'],
                        ]

                    ],
                    'fields' => ['Events.uuid', 'id'],
                ]
            )->first();
            if (empty($event)) {
                $message = "Event not found.";
                $success = false;
            } else {
                foreach ($this->request->getData() as $k => $sa) {
                    if (isset($event['ShadowAttribute'])) {
                        foreach ($event['ShadowAttribute'] as $oldk => $oldsa) {
                            if ($sa['event_uuid'] == $oldsa['event_uuid'] && $sa['value'] == $oldsa['value'] && $sa['type'] == $oldsa['type'] && $sa['category'] == $oldsa['category'] && $sa['to_ids'] == $oldsa['to_ids']) {
                                if ($oldsa['timestamp'] < $sa['timestamp']) {
                                    $this->Events->ShadowAttribute->delete($oldsa['id']);
                                } else {
                                    continue 2;
                                }
                            }
                        }
                    }
                    $sa['event_id'] = $event['Event']['id'];
                    if ($sa['old_id'] != 0) {
                        foreach ($event['Attribute'] as $attribute) {
                            if ($sa['uuid'] == $attribute['uuid']) {
                                $sa['old_id'] = $attribute['id'];
                            }
                        }
                    }
                    if (isset($sa['id'])) {
                        unset($sa['id']);
                    }
                    $this->Events->ShadowAttribute->create();
                    if (!$this->Events->ShadowAttribute->save(['ShadowAttribute' => $sa])) {
                        $message = "Some of the proposals could not be saved.";
                        $success = false;
                    } else {
                        $counter++;
                    }
                    if (!$sa['deleted']) {
                        $this->Events->ShadowAttribute->sendProposalAlertEmail($event['Event']['id']);
                    }
                }
            }
            if ($success) {
                if ($counter) {
                    $message = $counter . " Proposal(s) added.";
                } else {
                    $message = "Nothing to update.";
                }
            }
            $this->set('data', ['success' => $success, 'message' => $message, 'counter' => $counter]);
            $this->set('_serialize', 'data');
        }
    }

    public function exportChoice($id)
    {
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
        }
        $id = $event['Event']['id'];
        $exports = [
            'json' => [
                'url' => $this->baseurl . '/events/restSearch/json/eventid:' . $id . '.json',
                'text' => __('MISP JSON (metadata + all attributes)'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/json/withAttachments:1/eventid:' . $id . '.json',
                'checkbox_default' => true,
            ],
            'xml' => [
                'url' => $this->baseurl . '/events/restSearch/xml/eventid:' . $id . '.xml',
                'text' => __('MISP XML (metadata + all attributes)'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/xml/eventid:' . $id . '/withAttachments:1.xml',
                'checkbox_default' => true,
            ],
            'openIOC' => [
                'url' => $this->baseurl . '/events/restSearch/openioc/to_ids:1/published:1/eventid:' . $id . '.json',
                'text' => __('OpenIOC (all indicators marked to IDS)'),
                'requiresPublished' => false,
                'checkbox' => false,
            ],
            'csv' => [
                'url' => $this->baseurl . '/events/restSearch/returnFormat:csv/to_ids:1/published:1/includeContext:0/eventid:' . $id,
                'text' => 'CSV',
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Include non-IDS marked attributes'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/returnFormat:csv/to_ids:1||0/published:1||0/includeContext:0/eventid:' . $id,
            ],
            'csv_with_context' => [
                'url' => $this->baseurl . '/events/restSearch/returnFormat:csv/to_ids:1/published:1/includeContext:1/eventid:' . $id,
                'text' => __('CSV with additional context'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Include non-IDS marked attributes'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/returnFormat:csv/to_ids:1||0/published:1||0/includeContext:1/eventid:' . $id,
            ],
            'stix_xml' => [
                'url' => $this->baseurl . '/events/restSearch/stix/eventid:' . $id,
                'text' => __('STIX 1 XML (metadata + all attributes)'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/stix/eventid:' . $id . '/withAttachments:1',
            ],
            'stix_json' => [
                'url' => $this->baseurl . '/events/restSearch/stix-json/eventid:' . $id,
                'text' => __('STIX 1 JSON (metadata + all attributes)'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/stix-json/withAttachments:1/eventid:' . $id,
            ],
            'stix2_json' => [
                'url' => $this->baseurl . '/events/restSearch/stix2/eventid:' . $id,
                'text' => 'STIX 2',
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/stix2/eventid:' . $id . '/withAttachments:1',
            ],
            'rpz' => [
                'url' => $this->baseurl . '/attributes/restSearch/returnFormat:rpz/published:1||0/eventid:' . $id,
                'text' => __('RPZ Zone file'),
                'requiresPublished' => false,
                'checkbox' => false,
            ],
            'suricata' => [
                'url' => $this->baseurl . '/events/restSearch/returnFormat:suricata/published:1||0/eventid:' . $id,
                'text' => __('Suricata rules'),
                'requiresPublished' => false,
                'checkbox' => false,
            ],
            'snort' => [
                'url' => $this->baseurl . '/events/restSearch/returnFormat:snort/published:1||0/eventid:' . $id,
                'text' => __('Snort rules'),
                'requiresPublished' => false,
                'checkbox' => false,
            ],
            'bro' => [
                'url' => $this->baseurl . '/attributes/bro/download/all/false/' . $id,
                // 'url' => $this->baseurl . '/attributes/restSearch/returnFormat:bro/published:1||0/eventid:' . $id,
                'text' => __('Bro rules'),
                'requiresPublished' => false,
                'checkbox' => false,
            ],
            'text' => [
                'text' => __('Export all attribute values as a text file'),
                'url' => $this->baseurl . '/attributes/restSearch/returnFormat:text/published:1||0/eventid:' . $id,
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Include non-IDS marked attributes'),
                'checkbox_set' => $this->baseurl . '/attributes/restSearch/returnFormat:text/published:1||0/to_ids:1||0/eventid:' . $id,
            ],
        ];
        if ($event['Event']['published'] == 0) {
            foreach ($exports as $k => $export) {
                if ($export['requiresPublished']) {
                    unset($exports[$k]);
                }
            }
            $exports['csv'] = [
                'url' => $this->baseurl . '/events/restSearch/returnFormat:csv/includeContext:0/eventid:' . $id,
                'text' => __('CSV (event not published, IDS flag ignored)'),
                'requiresPublished' => false,
                'checkbox' => false,
            ];
        }
        $ModulesTable = $this->fetchTable('Modules');
        $modules = $ModulesTable->getEnabledModules($this->ACL->getUser()->toArray(), false, 'Export');
        if (is_array($modules) && !empty($modules)) {
            foreach ($modules['modules'] as $module) {
                $exports[$module['name']] = [
                    'url' => $this->baseurl . '/events/exportModule/' . $module['name'] . '/' . $id,
                    'text' => Inflector::humanize($module['name']),
                    'requiresPublished' => true,
                    'checkbox' => false,
                ];
            }
        }
        $this->set('exports', $exports);
        $this->set('id', $id);
        $this->render('ajax/exportChoice');
    }

    public function importChoice($id = false, $scope = 'event')
    {
        if ($scope === 'event') {
            $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
            if (empty($event)) {
                throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
            }
            $imports = [
                'MISP JSON' => [
                    'url' => $this->baseurl . '/events/populate/' . $id,
                    'text' => __('Populate using a JSON file containing MISP event content data'),
                    'ajax' => false
                ],
                'freetext' => [
                    'url' => $this->baseurl . '/events/freeTextImport/' . $id,
                    'text' => __('Freetext Import'),
                    'ajax' => true,
                    'target' => 'popover_form'
                ],
                'template' => [
                    'url' => $this->baseurl . '/templates/templateChoices/' . $id,
                    'text' => __('Populate using a Template'),
                    'ajax' => true,
                    'target' => 'popover_form'
                ],
                'OpenIOC' => [
                    'url' => $this->baseurl . '/events/addIOC/' . $id,
                    'text' => __('OpenIOC Import'),
                    'ajax' => false,
                ],
                'ThreatConnect' => [
                    'url' => $this->baseurl . '/attributes/add_threatconnect/' . $id,
                    'text' => __('ThreatConnect Import'),
                    'ajax' => false
                ],
                'Forensic analysis' => [
                    'url' => $this->baseurl . '/events/upload_analysis_file/' . $id,
                    'text' => __('(Experimental) Forensic analysis - Mactime'),
                    'ajax' => false,
                ]
            ];
            $ModulesTable = $this->fetchTable('Modules');
            $modules = $ModulesTable->getEnabledModules($this->ACL->getUser()->toArray(), false, 'Import');
            if (is_array($modules) && !empty($modules)) {
                foreach ($modules['modules'] as $module) {
                    $imports[$module['name']] = [
                        'url' => $this->baseurl . '/events/importModule/' . $module['name'] . '/' . $id,
                        'text' => Inflector::humanize($module['name']),
                        'ajax' => false,
                    ];
                }
            }
        } else {
            $imports = [
                'MISP' => [
                    'url' => $this->baseurl . '/events/add_misp_export',
                    'text' => __('MISP standard (recommended exchange format - lossless)'),
                    'ajax' => false,
                    'bold' => true,
                ],
                'STIX' => [
                    'url' => $this->baseurl . '/events/upload_stix',
                    'text' => __('STIX 1.x format (lossy)'),
                    'ajax' => false,
                ],
                'STIX2' => [
                    'url' => $this->baseurl . '/events/upload_stix/2',
                    'text' => __('STIX 2.x format (lossy)'),
                    'ajax' => false,
                ]
            ];
        }
        $this->set('imports', $imports);
        $this->set('id', $id);
        $this->render('ajax/importChoice');
    }

    // API for pushing samples to MISP
    // Either send it to an existing event, or let MISP create a new one automatically
    public function upload_sample($event_id = null, $advanced = false)
    {
        $LogsTable = $this->fetchTable('Logs');
        $hashes = ['md5' => 'malware-sample', 'sha1' => 'filename|sha1', 'sha256' => 'filename|sha256'];
        $categoryDefinitions = $this->Events->Attributes->categoryDefinitions;
        $categories = [];
        foreach ($categoryDefinitions as $k => $v) {
            if (in_array('malware-sample', $v['types']) && !in_array($k, $categories)) {
                $categories[] = $k;
            }
        }
        $default_distribution = !empty(Configure::read('MISP.default_attribute_distribution')) ? Configure::read('MISP.default_attribute_distribution') : 5;
        if ($default_distribution == 'event') {
            $default_distribution = 5;
        }
        // #TODO i18n
        $parameter_options = [
            'distribution' => ['valid_options' => [0, 1, 2, 3, 5], 'default' => $default_distribution],
            'threat_level_id' => ['valid_options' => [1, 2, 3, 4], 'default' => 4],
            'analysis' => ['valid_options' => [0, 1, 2], 'default' => 0],
            'info' => ['default' =>  'Malware samples uploaded on ' . date('Y-m-d')],
            'to_ids' => ['valid_options' => [0, 1], 'default' => 1],
            'category' => ['valid_options' => $categories, 'default' => 'Payload installation'],
            'comment' => ['default' => '']
        ];

        if (!$this->ACL->getUser()['Role']['perm_auth']) {
            throw new MethodNotAllowedException(__('This functionality requires API key access.'));
        }
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('Please POST the samples as described on the automation page.'));
        }
        if ($this->response->getType() === 'application/json') {
            $data = $this->request->getJson();
        } elseif ($this->response->getType() === 'application/xml') {
            $data = $this->request->getData();
        } else {
            throw new BadRequestException(__('Please POST the samples as described on the automation page.'));
        }

        if (isset($data['request'])) {
            $data = $data['request'];
        }
        foreach ($parameter_options as $k => $v) {
            if (isset($data[$k])) {
                if (isset($v['valid_options']) && !in_array($data[$k], $v['valid_options'])) {
                    $data['settings'][$k] = $v['default'];
                } else {
                    $data['settings'][$k] = $data[$k];
                }
                unset($data[$k]);
            } else {
                $data['settings'][$k] = $v['default'];
            }
        }
        if (isset($data['files'])) {
            foreach ($data['files'] as $k => $file) {
                if (!isset($file['filename']) || !isset($file['data'])) {
                    unset($data['files'][$k]);
                } else {
                    $data['files'][$k]['md5'] = md5(base64_decode($file['data']));
                }
            }
        }

        if (empty($data['files'])) {
            throw new BadRequestException(__('No samples received, or samples not in the correct format. Please refer to the API documentation on the automation page.'));
        }
        if (isset($event_id)) {
            $data['settings']['event_id'] = $event_id;
        }
        if (isset($data['settings']['event_id'])) {
            $this->Events->id = $data['settings']['event_id'];
            if (!$this->Events->exists()) {
                throw new NotFoundException(__('Event not found'));
            }
        }
        if (isset($data['advanced'])) {
            $advanced = $data['advanced'];
        }

        // check if the user has permission to create attributes for an event, if the event ID has been passed
        // If not, create an event
        if (isset($data['settings']['event_id']) && !empty($data['settings']['event_id']) && is_numeric($data['settings']['event_id'])) {
            $conditions = ['id' => $data['settings']['event_id']];
            if (!$this->isSiteAdmin()) {
                $conditions[] = ['Events.orgc_id' => $this->ACL->getUser()['org_id']];
                if (!$this->ACL->getUser()['Role']['perm_modify_org']) {
                    $conditions[] = ['Events.user_id' => $this->ACL->getUser()['id']];
                }
            }
            $event = $this->Events->find(
                'all',
                [
                    'recursive' => -1,
                    'conditions' => $conditions,
                    'fields' => ['id'],
                ]
            )->first();
            if (empty($event)) {
                throw new NotFoundException(__('Event not found.'));
            }
            $this->Events->insertLock($this->ACL->getUser()->toArray(), $event['Event']['id']);
            $this->Events->id = $data['settings']['event_id'];
            $date = new Chronos();
            $this->Events->saveField('timestamp', $date->getTimestamp());
            $this->Events->saveField('published', 0);
        } else {
            $this->Events->create();
            if ($data['settings']['distribution'] == 5) {
                throw new BadRequestException(__('Distribution level 5 is not supported when uploading a sample without passing an event ID. Distribution level 5 is meant to take on the distribution level of an existing Events.'));
            }
            $result = $this->Events->save(
                [
                    'info' => $data['settings']['info'],
                    'analysis' => $data['settings']['analysis'],
                    'threat_level_id' => $data['settings']['threat_level_id'],
                    'distribution' => $data['settings']['distribution'],
                    'date' => date('Y-m-d'),
                    'orgc_id' => $this->ACL->getUser()['org_id'],
                    'org_id' => $this->ACL->getUser()['org_id'],
                    'user_id' => $this->ACL->getUser()['id'],
                ]
            );
            if (!$result) {
                $LogsTable->saveOrFailSilently(
                    [
                        'org' => $this->ACL->getUser()['Organisation']['name'],
                        'model' => 'Event',
                        'model_id' => 0,
                        'email' => $this->ACL->getUser()['email'],
                        'action' => 'upload_sample',
                        'user_id' => $this->ACL->getUser()['id'],
                        'title' => 'Error: Failed to create event using the upload sample functionality',
                        'change' => 'There was an issue creating an event (' . $data['settings']['info'] . '). The validation errors were: ' . json_encode($this->Events->validationErrors),
                    ]
                );
                throw new BadRequestException(__('The creation of a new event with the supplied information has failed.'));
            }
            $data['settings']['event_id'] = $this->Events->id;
            $event_id = $this->Events->id;
        }

        if (!isset($data['settings']['to_ids']) || !in_array($data['settings']['to_ids'], ['0', '1', 0, 1])) {
            $data['settings']['to_ids'] = 1;
        }
        $successCount = 0;
        $errors = [];
        foreach ($data['files'] as $file) {
            $tmpdir = Configure::read('MISP.tmpdir') ? Configure::read('MISP.tmpdir') : APP . 'tmp';
            $tmpfile = FileAccessTool::createTempFile($tmpdir, $prefix = 'MISP_upload');
            FileAccessTool::writeToFile($tmpfile, base64_decode($file['data']));
            $tmpfile = new SplFileInfo($tmpfile);
            if ($advanced) {
                $result = $this->Events->Attributes->advancedAddMalwareSample(
                    $event_id,
                    $data['settings'],
                    $file['filename'],
                    $tmpfile
                );
                if ($result) {
                    $successCount++;
                } else {
                    $errors[] = $file['filename'];
                }
            } else {
                $result = $this->Events->Attributes->simpleAddMalwareSample(
                    $event_id,
                    $data['settings'],
                    $file['filename'],
                    $tmpfile
                );
                if ($result) {
                    $successCount++;
                } else {
                    $errors[] = $file['filename'];
                }
            }
            if (!empty($result)) {
                foreach ($result['Object'] as $object) {
                    if (isset($data['settings']['distribution'])) {
                        $object['distribution'] = $data['settings']['distribution'];
                    }
                    $object['sharing_group_id'] = isset($data['settings']['sharing_group_id']) ? $data['settings']['sharing_group_id'] : 0;
                    if (!empty($object['Attribute'])) {
                        foreach ($object['Attribute'] as $k => $attribute) {
                            if ($attribute['value'] == $tmpfile->getFilename()) {
                                $object['Attribute'][$k]['value'] = $file['filename'];
                            }
                            if (isset($data['settings']['distribution'])) {
                                $object['Attribute'][$k]['distribution'] = $data['settings']['distribution'];
                            }
                            $object['Attribute'][$k]['sharing_group_id'] = isset($data['settings']['sharing_group_id']) ? $data['settings']['sharing_group_id'] : 0;
                        }
                    }
                    $MispObjectsTable = $this->fetchTable('MispObjects');
                    $MispObjectsTable->captureObject(['Object' => $object], $event_id, $this->ACL->getUser()->toArray());
                }
                if (!empty($result['ObjectReference'])) {
                    foreach ($result['ObjectReference'] as $reference) {
                        $MispObjectsTable->ObjectReference->smartSave($reference, $event_id);
                    }
                }
            }
            FileAccessTool::deleteFile($tmpfile->getPathname());
        }
        if (!empty($errors)) {
            $this->set('errors', $errors);
            if ($successCount > 0) {
                $this->set('name', 'Partial success');
                $this->set('message', 'Successfuly saved ' . $successCount . ' sample(s), but some samples could not be saved.');
                $this->set('url', $this->baseurl . '/events/view/' . $data['settings']['event_id']);
                $this->set('id', $data['settings']['event_id']);
                $this->set('_serialize', ['name', 'message', 'url', 'id', 'errors']);
            } else {
                $this->set('name', 'Failed');
                $this->set('message', 'Failed to save any of the supplied samples.');
                $this->set('_serialize', ['name', 'message', 'errors']);
            }
        } else {
            $this->set('name', 'Success');
            $this->set('message', 'Success, saved all attributes.');
            $this->set('url', $this->baseurl . '/events/view/' . $data['settings']['event_id']);
            $this->set('id', $data['settings']['event_id']);
            $this->set('_serialize', ['name', 'message', 'url', 'id']);
        }
        $this->view($data['settings']['event_id']);
        $this->render('view');
    }

    public function viewGraph($id)
    {
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Events.'));
        }

        $this->set('event', $event);
        $this->set('scope', 'event');
        $this->set('mayModify', $this->canModifyEvent($event));
        $this->set('mayPublish', $this->canPublishEvent($event));
        $this->set('id', $event['Event']['id']);
    }

    /*
        public function deleteNode($id) {
            if (!$this->request->is('post')) throw new MethodNotAllowedException(__('Only POST requests are allowed.'));
            App::uses('CorrelationGraphTool', 'Tools');
            $grapher = new CorrelationGraphTool();
            $grapher->construct($this->Event, $TaxonomiesTable, $this->GalaxyCluster, $this->ACL->getUser()->toArray(), $this->request->data);
            $json = $grapher->deleteNode($id);
        }
    */

    public function updateGraph($id, $type = 'event')
    {
        $user = $this->closeSession();
        $validTools = ['event', 'galaxy', 'tag'];
        if (!in_array($type, $validTools, true)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $TaxonomiesTable = $this->fetchTable('Taxonomies');
        $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
        $grapher = new CorrelationGraphTool();
        $data = $this->request->is('post') ? $this->request->getData() : [];
        $grapher->construct($this->Event, $TaxonomiesTable, $GalaxyClustersTable, $user, $data);
        $json = $grapher->buildGraphJson($id, $type);
        array_walk_recursive(
            $json,
            function (&$item, $key) {
                if (!mb_detect_encoding($item, 'utf-8', true)) {
                    $item = mb_convert_encoding($item, 'UTF-8');
                }
            }
        );
        return $this->RestResponse->viewData($json, 'json');
    }

    private function __genDistributionGraph($id, $type = 'event', $extended = 0, $user = null)
    {
        $validTools = ['event'];
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }

        $ServersTable = $this->fetchTable('Servers');
        $servers = $ServersTable->find(
            'column',
            [
                'fields' => ['name'],
            ]
        )->toArray();

        $user = $user ?: $this->ACL->getUser()->toArray();
        $grapher = new DistributionGraphTool($this->Event, $servers, $user, $extended);
        $json = $grapher->get_distributions_graph($id);

        array_walk_recursive(
            $json,
            function (&$item, $key) {
                if (!mb_detect_encoding($item, 'utf-8', true)) {
                    $item = mb_convert_encoding($item, 'UTF-8');
                    Friday:
                }
            }
        );
        return $json;
    }

    public function getEventTimeline($id, $type = 'event')
    {
        $validTools = ['event'];
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException('Invalid type.');
        }
        $grapher = new EventTimelineTool();
        $data = $this->request->is('post') ? $this->request->getData() : [];
        $dataFiltering = array_key_exists('filtering', $data) ? $data['filtering'] : [];
        $scope = isset($data['scope']) ? $data['scope'] : 'seen';

        $extended = isset($this->params['named']['extended']) ? 1 : 0;

        $grapher->construct($this->Event, $this->ACL->getUser()->toArray(), $dataFiltering, $extended);
        if ($scope == 'seen') {
            $json = $grapher->get_timeline($id);
        } elseif ($scope == 'sightings') {
            $json = $grapher->get_sighting_timeline($id);
        }

        array_walk_recursive(
            $json,
            function (&$item, $key) {
                if (!mb_detect_encoding($item, 'utf-8', true)) {
                    $item = mb_convert_encoding($item, 'UTF-8');
                }
            }
        );
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getDistributionGraph($id, $type = 'event')
    {
        $user = $this->closeSession();
        $extended = isset($this->params['named']['extended']) ? 1 : 0;
        $json = $this->__genDistributionGraph($id, $type, $extended, $user);
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getEventGraphReferences($id, $type = 'event')
    {
        $validTools = ['event'];
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $TagsTable = $this->fetchTable('Tags');
        $grapher = new EventGraphTool();
        $data = $this->request->is('post') ? $this->request->getData() : [];

        $extended = isset($this->params['named']['extended']) ? 1 : 0;

        $grapher->construct($this->Event, $TagsTable, $this->ACL->getUser()->toArray(), $data['filtering'], $extended);
        $json = $grapher->get_references($id);

        array_walk_recursive(
            $json,
            function (&$item, $key) {
                if (!mb_detect_encoding($item, 'utf-8', true)) {
                    $item = mb_convert_encoding($item, 'UTF-8');
                }
            }
        );
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getEventGraphTags($id, $type = 'event')
    {
        $validTools = ['event'];
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $TagsTable = $this->fetchTable('Tags');
        $grapher = new EventGraphTool();
        $data = $this->request->is('post') ? $this->request->getData() : [];

        $extended = isset($this->params['named']['extended']) ? 1 : 0;

        $grapher->construct($this->Event, $TagsTable, $this->ACL->getUser()->toArray(), $data['filtering'], $extended);
        $json = $grapher->get_tags($id);

        array_walk_recursive(
            $json,
            function (&$item, $key) {
                if (!mb_detect_encoding($item, 'utf-8', true)) {
                    $item = mb_convert_encoding($item, 'UTF-8');
                }
            }
        );
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getEventGraphGeneric($id, $type = 'event')
    {
        $validTools = ['event'];
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $TagsTable = $this->fetchTable('Tags');
        $grapher = new EventGraphTool();
        $data = $this->request->is('post') ? $this->request->getData() : [];

        $extended = isset($this->params['named']['extended']) ? 1 : 0;

        $grapher->construct($this->Event, $TagsTable, $this->ACL->getUser()->toArray(), $data['filtering'], $extended);
        if (!array_key_exists('keyType', $data)) {
            $keyType = ''; // empty key
        } else {
            $keyType = $data['keyType'];
        }
        $json = $grapher->get_generic_from_key($id, $keyType);

        array_walk_recursive(
            $json,
            function (&$item, $key) {
                if (!mb_detect_encoding($item, 'utf-8', true)) {
                    $item = mb_convert_encoding($item, 'UTF-8');
                }
            }
        );
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getReferenceData($uuid, $type = 'reference')
    {
        $validTools = ['reference'];
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $grapher = new EventGraphTool();
        $data = $this->request->is('post') ? $this->request->getData() : [];
        $grapher->construct_for_ref($this->Events->Object, $this->ACL->getUser()->toArray());
        $json = $grapher->get_reference_data($uuid);

        array_walk_recursive(
            $json,
            function (&$item, $key) {
                if (!mb_detect_encoding($item, 'utf-8', true)) {
                    $item = mb_convert_encoding($item, 'UTF-8');
                }
            }
        );
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getObjectTemplate($type = 'templates')
    {
        $validTools = ['templates'];
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $eventGraphTool = new EventGraphTool();

        $data = $this->request->is('post') ? $this->request->getData() : [];
        $eventGraphTool->construct_for_ref($this->Events->Object, $this->ACL->getUser()->toArray());
        $json = $eventGraphTool->get_object_templates();

        array_walk_recursive(
            $json,
            function (&$item, $key) {
                if (!mb_detect_encoding($item, 'utf-8', true)) {
                    $item = mb_convert_encoding($item, 'UTF-8');
                }
            }
        );
        return $this->RestResponse->viewData($json, 'json');
    }

    public function viewGalaxyMatrix($scope_id, $galaxy_id, $scope = 'event', $disable_picking = false, $extended = false)
    {
        $GalaxiesTable = $this->fetchTable('Galaxies');
        $mitreAttackGalaxyId = $GalaxiesTable->getMitreAttackGalaxyId();
        if ($galaxy_id === 'mitre-attack') { // specific case for MITRE ATTACK matrix
            $galaxy_id = $mitreAttackGalaxyId;
        }

        $matrixData = $this->Galaxy->getMatrix($galaxy_id); // throws exception if matrix not found

        $local = !empty($this->params['named']['local']);
        $this->set('local', $local);

        $tabs = $matrixData['tabs'];
        $matrixTags = $matrixData['matrixTags'];
        $killChainOrders = $matrixData['killChain'];
        $instanceUUID = $matrixData['instance-uuid'];

        if ($scope == 'event') {
            $eventId = $scope_id;
        } elseif ($scope == 'attribute') {
            if ($scope_id == 'selected') {
                if (empty($this->params['named']['eventid'])) {
                    throw new Exception("Invalid Events.");
                }
                $eventId = $this->params['named']['eventid'];
            } else {
                $attribute = $this->Events->Attributes->fetchAttributes(
                    $this->ACL->getUser()->toArray(),
                    [
                        'conditions' => ['Attribute.id' => $scope_id],
                        'fields' => ['event_id'],
                        'flatten' => 1,
                    ]
                );
                if (empty($attribute)) {
                    throw new Exception("Invalid Attribute.");
                }
                $attribute = $attribute[0];
                $eventId = $attribute['Attribute']['event_id'];
            }
        } elseif ($scope == 'tag_collection') {
            $eventId = 0; // no event_id for tag_collection, consider all events
        } else {
            throw new Exception("Invalid options.");
        }

        if ($scope !== 'tag_collection') {
            $event = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), ['eventid' => $eventId, 'metadata' => true, 'extended' => $extended]);
            if (empty($event)) {
                throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
            }
            if ($extended) {
                $eventIds = [];
                $eventIds[] = $eventId;
                foreach ($event[0]['Event']['extensionEvents'] as $extensionEvent) {
                    $eventIds[] = $extensionEvent['id'];
                }
                $eventId = $eventIds;
            }
            $scoresDataAttr = $this->Events->Attributes->AttributeTag->getTagScores($this->ACL->getUser()->toArray(), $eventId, $matrixTags);
            $scoresDataEvent = $this->Events->EventTag->getTagScores($eventId, $matrixTags);
            $maxScore = 0;
            $scoresData = [];
            foreach (array_keys($scoresDataAttr['scores'] + $scoresDataEvent['scores']) as $key) {
                $sum = (isset($scoresDataAttr['scores'][$key]) ? $scoresDataAttr['scores'][$key] : 0) + (isset($scoresDataEvent['scores'][$key]) ? $scoresDataEvent['scores'][$key] : 0);
                $scoresData[$key] = $sum;
                $maxScore = max($maxScore, $sum);
            }
            $scores = $scoresData;
        } else {
            $scores = $scoresData = [];
        }
        // FIXME: temporary fix: add the score of deprecated mitre galaxies to the new one (for the stats)
        if ($matrixData['galaxy']['id'] == $mitreAttackGalaxyId) {
            $mergedScore = [];
            foreach ($scoresData as $tag => $v) {
                $predicateValue = explode(':', $tag, 2)[1];
                $predicateValue = explode('=', $predicateValue, 2);
                $predicate = $predicateValue[0];
                $clusterValue = $predicateValue[1];
                $mappedTag = '';
                $mappingWithoutExternalId = [];
                if ($predicate == 'mitre-attack-pattern') {
                    $mappedTag = $tag;
                    $name = explode(" ", $tag);
                    $name = join(" ", array_slice($name, 0, -2)); // remove " - external_id"
                    $mappingWithoutExternalId[$name] = $tag;
                } else {
                    $name = explode(" ", $clusterValue);
                    $name = join(" ", array_slice($name, 0, -2)); // remove " - external_id"
                    if (isset($mappingWithoutExternalId[$name])) {
                        $mappedTag = $mappingWithoutExternalId[$name];
                    } else {
                        $adjustedTagName = $this->Galaxy->GalaxyCluster->find(
                            'list',
                            [
                                'group' => ['GalaxyCluster.id', 'GalaxyCluster.tag_name'],
                                'conditions' => ['GalaxyCluster.tag_name LIKE' => 'misp-galaxy:mitre-attack-pattern=' . $name . '% T%'],
                                'fields' => ['GalaxyCluster.tag_name']
                            ]
                        );
                        $adjustedTagName = array_values($adjustedTagName)[0];
                        $mappingWithoutExternalId[$name] = $adjustedTagName;
                        $mappedTag = $mappingWithoutExternalId[$name];
                    }
                }

                if (isset($mergedScore[$mappedTag])) {
                    $mergedScore[$mappedTag] += $v;
                } else {
                    $mergedScore[$mappedTag] = $v;
                }
            }
            $scores = $mergedScore;
            $maxScore = !empty($mergedScore) ? max(array_values($mergedScore)) : 0;
        }
        // end FIXME

        $this->Galaxy->sortMatrixByScore($tabs, $scores);
        if ($this->ParamHandler->isRest()) {
            $json = ['matrix' => $tabs, 'scores' => $scores, 'instance-uuid' => $instanceUUID];
            return $this->RestResponse->viewData($json, 'json');
        }

        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('Invalid method.'));
        }

        $gradientTool = new ColourGradientTool();
        $colours = $gradientTool->createGradientFromValues($scores);
        $this->set('eventId', $eventId);
        $this->set('target_type', $scope);
        $this->set('columnOrders', $killChainOrders);
        $this->set('tabs', $tabs);
        $this->set('scores', $scores);
        $this->set('maxScore', $maxScore);
        if (!empty($colours)) {
            $this->set('colours', $colours['mapping']);
            $this->set('interpolation', $colours['interpolation']);
        }
        $this->set('pickingMode', !$disable_picking);
        $this->set('target_id', $scope_id);
        if ($matrixData['galaxy']['id'] == $mitreAttackGalaxyId) {
            $this->set('defaultTabName', 'mitre-attack');
            $this->set('removeTrailling', 2);
        }

        $this->render('/Elements/view_galaxy_matrix');
    }

    // Displays all the cluster relations for the provided event
    public function viewClusterRelations($eventId)
    {
        $event = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), ['eventid' => $eventId, 'flatten' => true]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Events.'));
        }
        $event = $event[0];
        $clusterIds = [];
        foreach ($event['Galaxy'] as $galaxy) {
            foreach ($galaxy['GalaxyCluster'] as $cluster) {
                $clusterIds[$cluster['id']] = $cluster['id'];
            }
        }
        foreach ($event['Attribute'] as $attribute) {
            foreach ($attribute['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $cluster) {
                    $clusterIds[$cluster['id']] = $cluster['id'];
                }
            }
        }
        $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
        $clusters = $GalaxyClustersTable->fetchGalaxyClusters($this->ACL->getUser()->toArray(), ['conditions' => ['GalaxyCluster.id' => $clusterIds]], $full = true);
        $grapher = new ClusterRelationsGraphTool($this->ACL->getUser()->toArray(), $GalaxyClustersTable);
        $relations = $grapher->getNetwork($clusters, $keepNotLinkedClusters = true, $includeReferencingRelation = true);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($relations, $this->response->getType());
        }
        $this->set('relations', $relations);
        $this->set('distributionLevels', $this->Events->distributionLevels);
    }

    public function delegation_index()
    {
        $EventDelegationsTable = $this->fetchTable('EventDelegations');
        $delegatedEvents = $this->EventDelegation->find(
            'list',
            [
                'conditions' => ['EventDelegation.org_id' => $this->ACL->getUser()['org_id']],
                'fields' => ['event_id']
            ]
        );
        $this->Events->contain(['User.email', 'EventTag' => ['Tag']]);
        $tags = $this->Events->EventTag->Tag->find('all', ['recursive' => -1]);
        $tagNames = ['None'];
        foreach ($tags as $k => $v) {
            $tagNames[$v['Tag']['id']] = $v['Tag']['name'];
        }
        $this->set('tags', $tagNames);
        $this->paginate = [
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => [
                'Events.timestamp' => 'DESC'
            ],
            'contain' => [
                'Org' => ['fields' => ['id', 'name']],
                'Orgc' => ['fields' => ['id', 'name']],
                'SharingGroup' => ['fields' => ['id', 'name']],
                'ThreatLevel' => ['fields' => ['ThreatLevel.name']]

            ],
            'conditions' => ['id' => $delegatedEvents],
        ];

        $this->set('events', $this->paginate());
        $this->set('threatLevels', $this->Events->ThreatLevel->listThreatLevels());
        $this->set('eventDescriptions', $this->Events->fieldDescriptions);
        $this->set('analysisLevels', $this->Events->analysisLevels);
        $this->set('distributionLevels', $this->Events->distributionLevels);

        $shortDist = [0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group'];
        $this->set('shortDist', $shortDist);
        $this->set('ajax', false);
        $this->set('simple', true);
        $this->Events->contain(['User.email', 'EventTag' => ['Tag']]);
        $tags = $this->Events->EventTag->Tag->find('all', ['recursive' => -1]);
        $tagNames = ['None'];
        foreach ($tags as $k => $v) {
            $tagNames[$v['Tag']['id']] = $v['Tag']['name'];
        }
        $this->set('tags', $tagNames);
        $this->render('index');
    }

    // expects a model ID, model type, the module to be used (optional) and the type of enrichment (optional)
    public function queryEnrichment($id, $module = false, $type = 'Enrichment', $model = 'Attribute')
    {
        if (!Configure::read('Plugin.' . $type . '_services_enable')) {
            throw new MethodNotAllowedException(__('%s services are not enabled.', $type));
        }

        if (!in_array($model, ['Attribute', 'ShadowAttribute', 'Object', 'Event'])) {
            throw new MethodNotAllowedException(__('Invalid model.'));
        }

        $ModulesTable = $this->fetchTable('Modules');
        $enabledModules = $ModulesTable->getEnabledModules($this->ACL->getUser()->toArray(), false, $type);

        if (!is_array($enabledModules) || empty($enabledModules)) {
            throw new MethodNotAllowedException(__('No valid %s options found for this %s.', $type, strtolower($model)));
        }

        if ($model === 'Attribute' || $model === 'ShadowAttribute') {
            $attribute = $this->Events->Attributes->fetchAttributes(
                $this->ACL->getUser()->toArray(),
                [
                    'conditions' => [
                        'Attribute.id' => $id
                    ],
                    'flatten' => 1,
                    'includeEventTags' => 1,
                    'contain' => ['Event' => ['fields' => ['distribution', 'sharing_group_id']]],
                ]
            );
            if (empty($attribute)) {
                throw new MethodNotAllowedException(__('Attribute not found or you are not authorised to see it.'));
            }
        }

        if ($model === 'Object') {
            $object = $this->Events->Object->fetchObjects(
                $this->ACL->getUser()->toArray(),
                [
                    'conditions' => [
                        'Object.id' => $id
                    ],
                    'flatten' => 1,
                    'includeEventTags' => 1,
                    'contain' => ['Event' => ['fields' => ['distribution', 'sharing_group_id']]],
                ]
            );
            if (empty($object)) {
                throw new MethodNotAllowedException(__('Object not found or you are not authorised to see it.'));
            }
        }

        if ($this->request->is('ajax')) {
            $modules = [];

            if ($model === 'Attribute' || $model === 'ShadowAttribute') {
                foreach ($enabledModules['modules'] as $module) {
                    if (in_array($attribute[0]['Attribute']['type'], $module['mispattributes']['input'])) {
                        $modules[] = ['name' => $module['name'], 'description' => $module['meta']['description']];
                    }
                }
            }

            if ($model === 'Object') {
                foreach ($enabledModules['modules'] as $module) {
                    if (
                        in_array($object[0]['Object']['name'], $module['mispattributes']['input']) ||
                        in_array($object[0]['Object']['uuid'], $module['mispattributes']['input'])
                    ) {
                        $modules[] = ['name' => $module['name'], 'description' => $module['meta']['description']];
                    }
                }
            }

            $this->set('id', $id);
            $this->set('modules', $modules);
            $this->set('type', $type);
            $this->set('model', $model);
            $this->render('ajax/enrichmentChoice');
        } else {
            $options = [];
            $format = 'simplified';
            foreach ($enabledModules['modules'] as $temp) {
                if ($temp['name'] == $module) {
                    $format = !empty($temp['mispattributes']['format']) ? $temp['mispattributes']['format'] : 'simplified';
                    if (isset($temp['meta']['config'])) {
                        foreach ($temp['meta']['config'] as $conf) {
                            $options[$conf] = Configure::read('Plugin.' . $type . '_' . $module . '_' . $conf);
                        }
                    }
                    break;
                }
            }
            $distributions = $this->Events->Attributes->distributionLevels;
            $sgs = $this->Events->SharingGroup->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'name', 1);
            if (empty($sgs)) {
                unset($distributions[4]);
            }
            $this->set('distributions', $distributions);
            $this->set('sgs', $sgs);
            $this->set('title_for_layout', __('Enrichment Results'));
            $this->set('title', __('Enrichment Results'));
            if ($format == 'misp_standard') {
                if ($model === 'Attribute' || $model === 'ShadowAttribute') {
                    $this->__queryEnrichment($attribute, $module, $options, $type);
                }

                if ($model === 'Object') {
                    $this->__queryObjectEnrichment($object, $module, $options, $type);
                }
            } else {
                $this->__queryOldEnrichment($attribute, $module, $options, $type);
            }
        }
    }

    private function __queryEnrichment($attribute, $module, $options, $type)
    {
        if ($this->Events->Attributes->typeIsAttachment($attribute[0]['Attribute']['type'])) {
            $attribute[0]['Attribute']['data'] = $this->Events->Attributes->base64EncodeAttachment($attribute[0]['Attribute']);
        }
        $event_id = $attribute[0]['Event']['id'];
        $data = ['module' => $module, 'attribute' => $attribute[0]['Attribute'], 'event_id' => $event_id];
        if (!empty($options)) {
            $data['config'] = $options;
        }
        $ModulesTable = $this->fetchTable('Modules');
        $result = $ModulesTable->queryModuleServer($data, false, $type, false, $attribute[0]);
        if (!$result) {
            throw new InternalErrorException(__('%s service not reachable.', $type));
        }
        if (isset($result['error'])) {
            $this->Flash->error($result['error']);
        }
        if (!is_array($result)) {
            throw new Exception($result);
        }
        $event = $this->Events->handleMispFormatFromModuleResult($result);
        if (empty($event['Attribute']) && empty($event['Object'])) {
            $this->__handleSimplifiedFormat($attribute, $module, $options, $result, $type);
        } else {
            $importComment = !empty($result['comment']) ? $result['comment'] : $attribute[0]['Attribute']['value'] . __(': Enriched via the ') . $module . ($type != 'Enrichment' ? ' ' . $type : '')  . ' module';
            $this->set('importComment', $importComment);
            $event['Event'] = $attribute[0]['Event'];
            $org_name = $this->Events->Orgc->find(
                'all',
                [
                    'conditions' => ['Orgc.id' => $event['Event']['orgc_id']],
                    'fields' => ['Orgc.name']
                ]
            )->first();
            $event['Event']['orgc_name'] = $org_name['Orgc']['name'];
            if ($attribute[0]['Object']['id']) {
                $object_id = $attribute[0]['Object']['id'];
                $initial_object = $this->Events->fetchInitialObject($event_id, $object_id);
                if (!empty($initial_object)) {
                    $event['initialObject'] = $initial_object;
                }
            }
            $this->set('event', $event);
            $this->set('menuItem', 'enrichmentResults');
            $this->set('title_for_layout', __('Enrichment Results'));
            $this->set('title', __('Enrichment Results'));
            $this->render('resolved_misp_format');
        }
    }

    private function __queryObjectEnrichment($object, $module, $options, $type)
    {
        $object[0]['Object']['Attribute'] = $object[0]['Attribute'];
        foreach ($object[0]['Object']['Attribute'] as &$attribute) {
            if ($this->Events->Attributes->typeIsAttachment($attribute['type'])) {
                $attribute['data'] = $this->Events->Attributes->base64EncodeAttachment($attribute);
            }
        }

        $event_id = $object[0]['Event']['id'];
        $data = ['module' => $module, 'object' => $object[0]['Object'], 'event_id' => $event_id];
        if (!empty($options)) {
            $data['config'] = $options;
        }
        $ModulesTable = $this->fetchTable('Modules');
        $result = $ModulesTable->queryModuleServer($data, false, $type, false, $object[0]);
        if (!$result) {
            throw new InternalErrorException(__('%s service not reachable.', $type));
        }
        if (isset($result['error'])) {
            $this->Flash->error($result['error']);
        }
        if (!is_array($result)) {
            throw new Exception($result);
        }
        $event = $this->Events->handleMispFormatFromModuleResult($result);
        if (empty($event['Attribute']) && empty($event['Object'])) {
            throw new NotImplementedException(__('No Attribute or Object returned by the module.'));
        } else {
            $importComment = !empty($result['comment']) ? $result['comment'] : $object[0]['Object']['value'] . __(': Enriched via the ') . $module . ($type != 'Enrichment' ? ' ' . $type : '')  . ' module';
            $this->set('importComment', $importComment);
            $event['Event'] = $object[0]['Event'];
            $org_name = $this->Events->Orgc->find(
                'all',
                [
                    'conditions' => ['Orgc.id' => $event['Event']['orgc_id']],
                    'fields' => ['Orgc.name']
                ]
            )->first();
            $event['Event']['orgc_name'] = $org_name['Orgc']['name'];
            if ($attribute[0]['Object']['id']) {
                $object_id = $attribute[0]['Object']['id'];
                $initial_object = $this->Events->fetchInitialObject($event_id, $object_id);
                if (!empty($initial_object)) {
                    $event['initialObject'] = $initial_object;
                }
            }
            $this->set('event', $event);
            $this->set('menuItem', 'enrichmentResults');
            $this->set('title_for_layout', __('Enrichment Results'));
            $this->set('title', __('Enrichment Results'));
            $this->render('resolved_misp_format');
        }
    }

    private function __queryOldEnrichment($attribute, $module, $options, $type)
    {
        $data = ['module' => $module, $attribute[0]['Attribute']['type'] => $attribute[0]['Attribute']['value'], 'event_id' => $attribute[0]['Attribute']['event_id'], 'attribute_uuid' => $attribute[0]['Attribute']['uuid']];
        if ($this->Events->Attributes->typeIsAttachment($attribute[0]['Attribute']['type'])) {
            $data['data'] = $this->Events->Attributes->base64EncodeAttachment($attribute[0]['Attribute']);
        }
        if (!empty($options)) {
            $data['config'] = $options;
        }
        $ModulesTable = $this->fetchTable('Modules');
        $result = $ModulesTable->queryModuleServer($data, false, $type, false, $attribute[0]);
        if (!$result) {
            throw new InternalErrorException(__('%s service not reachable.', $type));
        }
        if (isset($result['error'])) {
            $this->Flash->error($result['error']);
        }
        if (!is_array($result)) {
            throw new Exception($result);
        }
        $this->__handleSimplifiedFormat($attribute, $module, $options, $result, $type);
    }

    private function __handleSimplifiedFormat($attribute, $module, $options, $result, $type, $event = false)
    {
        $resultArray = $this->Events->handleModuleResult($result, $attribute[0]['Attribute']['event_id']);
        if (!empty($result['comment'])) {
            $importComment = $result['comment'];
        } else {
            $importComment = $attribute[0]['Attribute']['value'] . __(': Enriched via the %s', $module) . ($type != 'Enrichment' ? ' ' . $type : '')  . ' module';
        }
        $typeCategoryMapping = [];
        foreach ($this->Events->Attributes->categoryDefinitions as $k => $cat) {
            foreach ($cat['types'] as $type) {
                $typeCategoryMapping[$type][$k] = $k;
            }
        }
        $this->Events->Attributes->fetchRelated($this->ACL->getUser()->toArray(), $resultArray);
        foreach ($resultArray as $key => $result) {
            if (isset($result['data'])) {
                $tmpdir = Configure::read('MISP.tmpdir') ? Configure::read('MISP.tmpdir') : '/tmp';
                $tempFile = FileAccessTool::createTempFile($tmpdir, $prefix = 'MISP');
                FileAccessTool::writeToFile($tempFile, $result['data']);
                $resultArray[$key]['data'] = basename($tempFile) . '|' . filesize($tempFile);
            }
        }
        $this->set('type', $type);
        if (!$event) {
            $this->set('event', ['Event' => $attribute[0]['Event']]);
        }
        $this->set('resultArray', $resultArray);
        $this->set('typeDefinitions', $this->Events->Attributes->typeDefinitions);
        $this->set('typeCategoryMapping', $typeCategoryMapping);
        $this->set('defaultAttributeDistribution', $this->Events->Attributes->defaultDistribution());
        $this->set('importComment', $importComment);
        $this->render('resolved_attributes');
    }

    public function handleModuleResults($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
        }
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (!$event) {
            throw new NotFoundException(__('Invalid Events.'));
        }
        if (!$this->ACL->canModifyEvent($event)) {
            throw new ForbiddenException(__('You don\'t have permission to do that.'));
        }

        $resolved_data = $this->_jsonDecode($this->request->getData()['Event']['JsonObject']);
        $data = $this->_jsonDecode($this->request->getData()['Event']['data']);
        if (!empty($data['initialObject'])) {
            $resolved_data['initialObject'] = $data['initialObject'];
        }
        unset($data);
        $default_comment = $this->request->getData()['Event']['default_comment'];
        $flashMessage = $this->Events->processModuleResultsDataRouter($this->ACL->getUser()->toArray(), $resolved_data, $event['Event']['id'], $default_comment);
        $this->Flash->info($flashMessage);

        if ($this->request->is('ajax')) {
            return $this->RestResponse->viewData($flashMessage, $this->response->getType());
        } else {
            $this->redirect(['controller' => 'events', 'action' => 'view', $event['Event']['id']]);
        }
    }

    public function importModule($moduleName, $eventId)
    {
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $eventId);
        if (!$event) {
            throw new NotFoundException(__('Invalid Events.'));
        }
        $mayModify = $this->ACL->canModifyEvent($event);
        $eventId = $event['Event']['id'];

        $ModulesTable = $this->fetchTable('Modules');
        $module = $ModulesTable->getEnabledModule($moduleName, 'Import');
        if (!is_array($module)) {
            throw new MethodNotAllowedException($module);
        }
        if (!isset($module['mispattributes']['inputSource'])) {
            $module['mispattributes']['inputSource'] = ['paste'];
        }
        if ($this->request->is('post')) {
            $requestData = $this->request->getData()['Event'];
            $fail = false;
            $modulePayload = [
                'module' => $module['name'],
                'event_id' => $eventId,
            ];
            if (isset($module['meta']['config'])) {
                foreach ($module['meta']['config'] as $conf) {
                    $modulePayload['config'][$conf] = Configure::read('Plugin.Import_' . $moduleName . '_' . $conf);
                }
            }
            if ($moduleName === 'csvimport') {
                if (empty($requestData['config']['header']) && $requestData['config']['has_header'] === '1') {
                    $requestData['config']['header'] = ' ';
                }
                if (empty($requestData['config']['special_delimiter'])) {
                    $requestData['config']['special_delimiter'] = ' ';
                }
            }
            if (isset($module['mispattributes']['userConfig'])) {
                foreach ($module['mispattributes']['userConfig'] as $configName => $config) {
                    if (!$fail) {
                        if (isset($config['validation'])) {
                            if ($config['validation'] === '0' && $config['type'] == 'String') {
                                $validation = true;
                            }
                        } else {
                            $validationMethod = Module::CONFIG_TYPES[$config['type']]['validation'];
                            $validation = $ModulesTable->{$validationMethod}($requestData['config'][$configName]);
                        }
                        if ($validation !== true) {
                            $fail = ucfirst($configName) . ': ' . $validation;
                        } else {
                            if (isset($config['regex']) && !empty($config['regex'])) {
                                $fail = preg_match($config['regex'], $requestData['config'][$configName]) ? false : ucfirst($configName) . ': Invalid setting' . ($config['errorMessage'] ? ' - ' . $config['errorMessage'] : '');
                                if (!empty($fail)) {
                                    $modulePayload['config'][$configName] = $requestData['config'][$configName];
                                }
                            } else {
                                $modulePayload['config'][$configName] = $requestData['config'][$configName];
                            }
                        }
                    }
                }
            }
            if (!$fail) {
                if (!empty($module['mispattributes']['inputSource'])) {
                    if (!isset($requestData['source'])) {
                        if (in_array('paste', $module['mispattributes']['inputSource'])) {
                            $requestData['source'] = '0';
                        } else {
                            $requestData['source'] = '1';
                        }
                    }
                    if ($requestData['source'] == '1') {
                        if (isset($requestData['data'])) {
                            $modulePayload['data'] = base64_decode($requestData['data']);
                        } elseif (empty($requestData['fileupload'])) {
                            $fail = __('Invalid file upload.');
                        } else {
                            $fileupload = $requestData['fileupload'];
                            if ((isset($fileupload['error']) && $fileupload['error'] == 0) || (!empty($fileupload['tmp_name']) && $fileupload['tmp_name'] != 'none') && is_uploaded_file($fileupload['tmp_name'])) {
                                $filename = basename($fileupload['name']);
                                $modulePayload['data'] = FileAccessTool::readAndDelete($fileupload['tmp_name']);
                            } else {
                                $fail = __('Invalid file upload.');
                            }
                        }
                    } else {
                        $modulePayload['data'] = $requestData['paste'];
                    }
                } else {
                    $modulePayload['data'] = '';
                }
                if (!$fail) {
                    $modulePayload['data'] = base64_encode($modulePayload['data']);
                    if (!empty($filename)) {
                        $modulePayload['filename'] = $filename;
                    }
                    $result = $ModulesTable->queryModuleServer($modulePayload, false, $moduleFamily = 'Import');
                    if (!$result) {
                        throw new InternalErrorException(__('Import service not reachable.'));
                    }
                    if (isset($result['error'])) {
                        $this->Flash->error($result['error']);
                    }
                    if (!is_array($result)) {
                        throw new Exception($result);
                    }
                    $importComment = !empty($result['comment']) ? $result['comment'] : 'Enriched via the ' . $module['name'] . ' module';
                    if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] === 'misp_standard') {
                        $resolvedEvent = $this->Events->handleMispFormatFromModuleResult($result);
                        $resolvedEvent['Event'] = $event['Event'];
                        if ($this->ParamHandler->isRest()) {
                            $this->Events->processModuleResultsDataRouter($this->ACL->getUser()->toArray(), $resolvedEvent, $eventId, $importComment);
                            return $this->RestResponse->viewData($resolvedEvent, $this->response->getType());
                        }
                        $this->set('event', $resolvedEvent);
                        $this->set('menuItem', 'importResults');
                        $render_name = 'resolved_misp_format';
                    } else {
                        $resultArray = $this->Events->handleModuleResult($result, $eventId);
                        if ($this->ParamHandler->isRest()) {
                            return $this->__pushFreetext(
                                $resultArray,
                                $event,
                                false,
                                false,
                                'soft'
                            );
                        }
                        $typeCategoryMapping = [];
                        foreach ($this->Events->Attributes->categoryDefinitions as $k => $cat) {
                            foreach ($cat['types'] as $type) {
                                $typeCategoryMapping[$type][$k] = $k;
                            }
                        }
                        $this->Events->Attributes->fetchRelated($this->ACL->getUser()->toArray(), $resultArray);
                        $this->set('event', $event);
                        $this->set('resultArray', $resultArray);
                        $this->set('typeDefinitions', $this->Events->Attributes->typeDefinitions);
                        $this->set('typeCategoryMapping', $typeCategoryMapping);
                        $this->set('defaultAttributeDistribution', $this->Events->Attributes->defaultDistribution());
                        $render_name = 'resolved_attributes';
                    }

                    $distributionData = $this->Events->Attributes->fetchDistributionData($this->ACL->getUser()->toArray());
                    $this->set('distributions', $distributionData['levels']);
                    $this->set('sgs', $distributionData['sgs']);
                    $this->set('title', __('Import Results'));
                    $this->set('title_for_layout', __('Import Results'));
                    $this->set('importComment', $importComment);
                    $this->render($render_name);
                }
            }
            if ($fail) {
                $this->Flash->error($fail);
            }
        }
        $this->set('configTypes', Module::CONFIG_TYPES);
        $this->set('module', $module);
        $this->set('eventId', $eventId);
        $this->set('event', $event);
        $this->set('mayModify', $mayModify);
    }

    public function exportModule($module, $id, $standard = false)
    {
        $result = $this->Events->export($this->ACL->getUser()->toArray(), $module, ['eventid' => $id, 'standard' => $standard]);
        $this->response->withStringBody(base64_decode($result['data']));
        $this->response->withType($result['response']);
        $this->response->withDownload('misp.Events.' . $id . '.' . $module . '.export.' . $result['extension']);
        return $this->response;
    }

    public function toggleCorrelation($id)
    {
        if (!$this->isSiteAdmin() && !Configure::read('MISP.allow_disabling_correlation')) {
            throw new MethodNotAllowedException(__('Disabling the correlation is not permitted on this instance.'));
        }
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if (!$this->ACL->canModifyEvent($event)) {
            throw new ForbiddenException(__('You don\'t have permission to do that.'));
        }
        if ($this->request->is('post')) {
            if ($event['Event']['disable_correlation']) {
                $event['Event']['disable_correlation'] = 0;
                $this->Events->save($event);
                $this->Events->Attributes->Correlation->generateCorrelation(false, $event['Event']['id']);
            } else {
                $event['Event']['disable_correlation'] = 1;
                $this->Events->save($event);
                $this->Events->Attributes->Correlation->purgeCorrelations($event['Event']['id']);
            }
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('events', 'toggleCorrelation', $event['Event']['id'], false, 'Correlation ' . ($event['Event']['disable_correlation'] ? 'disabled' : 'enabled') . '.');
            } else {
                $this->Flash->success('Correlation ' . ($event['Event']['disable_correlation'] ? 'disabled' : 'enabled') . '.');
                $this->redirect(['controller' => 'events', 'action' => 'view', $event['Event']['id']]);
            }
        } else {
            $this->set('event', $event);
            $this->render('ajax/toggle_correlation');
        }
    }

    public function checkPublishedStatus($id)
    {
        $user = $this->closeSession();
        $event = $this->Events->fetchSimpleEvent($user, $id, ['fields' => 'Events.published']);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        return new Response(['body' => $event['Event']['published'], 'status' => 200, 'type' => 'txt']);
    }
    // #TODO i18n
    public function pushEventToZMQ($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Events, $id);
        if ($this->request->is('Post')) {
            if (Configure::read('Plugin.ZeroMQ_enable')) {
                $pubSubTool = $this->Events->getPubSubTool();
                $event = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), ['eventid' => $id, 'includeAllTags' => true]);
                if (!empty($event)) {
                    $pubSubTool->publishEvent($event[0]);
                    $success = 1;
                    $message = 'Event published to ZMQ';
                } else {
                    $message = 'Invalid Events.';
                }
            } else {
                $message = 'ZMQ event publishing not enabled.';
            }
        } else {
            $message = 'This functionality is only available via POST requests';
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Events', 'pushEventToZMQ', $id, $this->response->getType(), $message);
        } else {
            if (!empty($success)) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error($message);
            }
            $this->redirect($this->referer());
        }
    }

    public function pushEventToKafka($id)
    {
        if ($this->request->is('Post')) {
            $message = 'Kafka event publishing not enabled.';
            if (Configure::read('Plugin.Kafka_enable')) {
                $kafkaEventTopic = Configure::read('Plugin.Kafka_event_notifications_topic');
                $event = $this->Events->quickFetchEvent(['eventid' => $id]);
                if (Configure::read('Plugin.Kafka_event_notifications_enable') && !empty($kafkaEventTopic)) {
                    $kafkaPubTool = $this->Events->getKafkaPubTool();
                    if (!empty($event)) {
                        $kafkaPubTool->publishJson($kafkaEventTopic, $event, 'manual_publish');
                        $success = 1;
                        $message = 'Event published to Kafka';
                    } else {
                        $success = 0;
                        $message = 'Invalid Events.';
                    }
                }
                $kafkaPubTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
                if (!empty($event['Event']['published']) && Configure::read('Plugin.Kafka_event_publish_notifications_enable') && !empty($kafkaPubTopic)) {
                    $kafkaPubTool = $this->Events->getKafkaPubTool();
                    $params = ['eventid' => $id, 'includeAllTags' => true];
                    if (Configure::read('Plugin.Kafka_include_attachments')) {
                        $params['includeAttachments'] = 1;
                    }
                    $event = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), $params);
                    if (!empty($event)) {
                        $kafkaPubTool->publishJson($kafkaPubTopic, $event[0], 'manual_publish');
                        if (!isset($success)) {
                            $success = 1;
                            $message = 'Event published to Kafka';
                        }
                    } else {
                        $success = 0;
                        $message = 'Invalid Events.';
                    }
                }
            }
        } else {
            $message = 'This functionality is only available via POST requests';
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Events', 'pushEventToKafka', $id, $this->response->getType(), $message);
        } else {
            if (!empty($success)) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error($message);
            }
            $this->redirect($this->referer());
        }
    }

    public function getEventInfoById($id)
    {
        $user = $this->closeSession();
        if (empty($id)) {
            throw new MethodNotAllowedException(__('Invalid ID.'));
        }
        $event = $this->Events->fetchSimpleEvent(
            $user,
            $id,
            [
                'fields' => ['id', 'Events.info', 'Events.threat_level_id', 'Events.analysis'],
                'contain' => ['EventTag' => ['Tag.id', 'Tag.name', 'Tag.colour'], 'ThreatLevel.name'],
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($event, $this->response->getType());
        }

        if ($this->request->is('ajax')) {
            $this->layout = false;
        }
        $this->set('analysisLevels', $this->Events->analysisLevels);
        $this->set('validUuid', Validation::uuid($id));
        $this->set('id', $id);
        $this->set('event', $event);
    }

    public function enrichEvent($id)
    {
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event)) {
            throw new MethodNotAllowedException(__('Invalid Event'));
        }
        if (!$this->ACL->canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        $this->Events->insertLock($this->ACL->getUser()->toArray(), $event['Event']['id']);
        if ($this->request->is('post')) {
            $modules = [];
            $data = $this->request->getData();
            if (!isset($data['Event'])) {
                $data = ['Event' => $data];
            }
            foreach ($data['Event'] as $module => $enabled) {
                if ($enabled) {
                    $modules[] = $module;
                }
            }
            $result = $this->Events->enrichmentRouter(
                [
                    'user' => $this->ACL->getUser()->toArray(),
                    'event_id' => $event['Event']['id'],
                    'modules' => $modules
                ]
            );
            if ($this->ParamHandler->isRest()) {
            } else {
                if ($result === true) {
                    $result = __('Enrichment task queued for background processing. Check back later to see the results.');
                }
                $this->Flash->success($result);
                $this->redirect('/events/view/' . $id);
            }
        } else {
            $ModulesTable = $this->fetchTable('Modules');
            $modules = $ModulesTable->getEnabledModules($this->ACL->getUser()->toArray(), 'expansion');
            $this->layout = false;
            $this->set('modules', $modules);
            $this->render('ajax/enrich_event');
        }
    }

    public function addEventLock($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
        }

        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event)) {
            throw new MethodNotAllowedException(__('Invalid Event'));
        }
        if (!$this->ACL->canModifyEvent($event)) {
            throw new UnauthorizedException(__('You do not have permission to do that.'));
        }

        $EventLocksTable = $this->fetchTable('EventLocks');
        $lockId = $EventLocksTable->insertLockApi($event['Event']['id'], $this->ACL->getUser()->toArray());
        return $this->RestResponse->viewData(['lock_id' => $lockId], $this->response->getType());
    }

    public function removeEventLock($id, $lockId)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
        }

        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event)) {
            throw new MethodNotAllowedException(__('Invalid Event'));
        }

        $EventLocksTable = $this->fetchTable('EventLocks');
        $deleted = $EventLocksTable->deleteApiLock($event['Event']['id'], $lockId, $this->ACL->getUser()->toArray());
        return $this->RestResponse->viewData(['deleted' => $deleted], $this->response->getType());
    }

    public function checkLocks($id, $timestamp)
    {
        $user = $this->closeSession();

        $event = $this->Events->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['id' => $id],
                'fields' => ['Events.orgc_id', 'Events.timestamp', 'Events.user_id'],
            ]
        )->first();
        // Return empty response if event not found or user don't have permission to modify it
        if (empty($event) || !$this->ACL->canModifyEvent($event, $user)) {
            return new Response(['status' => 204]);
        }

        $EventLocksTable = $this->fetchTable('EventLocks');
        $locks = $EventLocksTable->checkLock($user, $id);

        $editors = [];
        foreach ($locks as $t) {
            if ($t['type'] === 'user' && $t['User']['id'] !== $user['id']) {
                if (!$this->isSiteAdmin() && $t['User']['org_id'] != $user['org_id']) {
                    $editors[] = __('another user');
                } else {
                    $editors[] = $t['User']['email'];
                }
            } else if ($t['type'] === 'job') {
                $editors[] = __('background job');
            } else if ($t['type'] === 'api') {
                $editors[] = __('external tool');
            }
        }
        $editors = array_unique($editors);

        if ($event['Event']['timestamp'] > $timestamp && empty($editors)) {
            $message = __('<b>Warning</b>: This event view is outdated. Please reload page to see the latest changes.');
            $this->set('class', 'alert');
        } else if ($event['Event']['timestamp'] > $timestamp) {
            $message = __('<b>Warning</b>: This event view is outdated, because is currently being edited by: %s. Please reload page to see the latest changes.', h(implode(', ', $editors)));
            $this->set('class', 'alert');
        } else if (empty($editors)) {
            return new Response(['status' => 204]);
        } else {
            $message = __('This event is currently being edited by: %s', h(implode(', ', $editors)));
            $this->set('class', 'alert alert-info');
        }

        $this->set('message', $message);
        $this->layout = false;
        $this->render('/Events/ajax/event_lock');
    }

    public function getEditStrategy($id)
    {
        // find the id of the event, change $id to it and proceed to read the event as if the ID was entered.
        $event = $this->Events->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => Validation::uuid($id) ? ['Events.uuid' => $id] : ['id' => $id],
                'fields' => ['id', 'Events.uuid', 'Events.orgc_id', 'Events.user_id']
            ]
        )->first();
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $response = ['extensions' => []];
        if ($this->ACL->canModifyEvent($event)) {
            $response['strategy'] = 'edit';
        } else {
            $response['strategy'] = 'extend';
        }
        $extendedEvents = $this->Events->find(
            'all',
            [
                'recursive' => -1,
                'fields' => ['id', 'Events.info', 'Events.uuid'],
                'conditions' => [
                    'Events.extends_uuid' => $event['Event']['uuid'],
                    'Events.orgc_id' => $this->ACL->getUser()['org_id']
                ]
            ]
        );
        foreach ($extendedEvents as $extendedEvent) {
            $response['extensions'][] = $extendedEvent['Event'];
        }
        return $this->RestResponse->viewData($response, $this->response->getType());
    }

    public function cullEmptyEvents()
    {
        $eventIds = $this->Events->find(
            'list',
            [
                'conditions' => ['Events.published' => 1],
                'fields' => ['id', 'Events.uuid'],
                'recursive' => -1
            ]
        );
        $count = 0;
        $this->Events->skipBlocklist = true;
        foreach ($eventIds as $eventId => $eventUuid) {
            $result = $this->Events->Attributes->find(
                'all',
                [
                    'conditions' => ['Attribute.event_id' => $eventId],
                    'recursive' => -1,
                    'fields' => ['Attribute.id', 'Attribute.event_id']
                ]
            )->first();
            if (empty($result)) {
                $this->Events->delete($eventId);
                $count++;
            }
        }
        $this->Events->skipBlocklist = null;
        $message = __('%s event(s) deleted.', $count);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($message, $this->response->getType());
        } else {
            $this->Flash->success($message);
            $this->redirect($this->referer());
        }
    }

    public function restoreDeletedEvents($force = false)
    {
        $startDate = '2020-07-31 00:00:00';
        $AdminSettingsTable = $this->fetchTable('AdminSettings');
        $endDate = date('Y-m-d H:i:s', $AdminSettingsTable->getSetting('fix_login'));
        if (empty($endDate)) {
            $endDate = date('Y-m-d H:i:s', time());
        }
        $LogsTable = $this->fetchTable('Logs');
        $redis = $this->Events->setupRedis();
        if ($force || ($redis && !$redis->exists('misp:event_recovery'))) {
            $deleted_events = $LogsTable->findDeletedEvents(['created BETWEEN ? AND ?' => [$startDate, $endDate]]);
            $redis->set('misp:event_recovery', json_encode($deleted_events));
            $redis->expire('misp:event_recovery', 600);
        } else {
            $deleted_events = json_decode($redis->get('misp:event_recovery'), true);
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($deleted_events, 'json');
        } else {
            $this->set('data', $deleted_events);
        }
    }

    public function recoverEvent($id, $mock = false)
    {
        if ($mock || !Configure::read('MISP.background_jobs')) {
            if ($this->request->is('post')) {
                $LogsTable = $this->fetchTable('Logs');
                $result = $LogsTable->recoverDeletedEvent($id, $mock);
                if ($mock) {
                    $message = __('Recovery simulation complete. Event #%s can be recovered using %s log entries.', $id, $result);
                } else {
                    $message = __('Recovery complete. Event #%s recovered, using %s log entries.', $id, $result);
                }
                if ($this->ParamHandler->isRest()) {
                    if ($mock) {
                        $results = $LogsTable->mockLog;
                    } else {
                        $results = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), ['eventid' => $id]);
                    }
                    return $this->RestResponse->viewData($results, $this->response->getType());
                } else {
                    $this->Flash->success($message);
                    if (!$mock) {
                        $this->redirect(['action' => 'restoreDeletedEvents']);
                    }
                }
            } else {
                $message = __('This action is only accessible via POST requests.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->viewData(['message' => $message, 'error' => true], $this->response->getType());
                } else {
                    $this->Flash->error($message);
                }
                $this->redirect(['action' => 'restoreDeletedEvents']);
            }
            $this->set('data', $LogsTable->mockLog);
        } else {
            if ($this->request->is('post')) {
                $job_type = 'recover_event';
                $function = 'recoverEvent';
                $message = __('Bootstraping recovering of event %s', $id);
                $JobsTable = $this->fetchTable('Jobs');
                $job = $JobsTable->newEntity(
                    [
                        'worker' => 'prio',
                        'job_type' => $job_type,
                        'job_input' => sprintf('Event ID: %s', $id),
                        'status' => 0,
                        'retries' => 0,
                        'org_id' => 0,
                        'org' => 'ADMIN',
                        'message' => $message
                    ]
                );
                $JobsTable->save($job);

                $this->Events->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::PRIO_QUEUE,
                    BackgroundJobsTool::CMD_EVENT,
                    [
                        $function,
                        $job->id,
                        $id
                    ],
                    true,
                    $job->id
                );

                $message = __('Recover event job queued. Job ID: %s', $job->id);
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->viewData(['message' => $message], $this->response->getType());
                } else {
                    $this->Flash->success($message);
                }
            } else {
                $message = __('This action is only accessible via POST requests.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->viewData(['message' => $message, 'error' => true], $this->response->getType());
                } else {
                    $this->Flash->error($message);
                }
            }
            $this->redirect(['action' => 'restoreDeletedEvents']);
        }
    }

    public function runTaxonomyExclusivityCheck($id)
    {
        if (Configure::read('MISP.disable_taxonomy_consistency_checks')) {
            return $this->RestResponse->saveFailResponse('Events', 'runTaxonomyExclusivityCheck', null, 'Taxonomy consistency checks are disabled, set `MISP.disable_taxonomy_consistency_checks` to `false` to enable them.', 'json');
        }

        $conditions = [];
        if (is_numeric($id)) {
            $conditions = ['eventid' => $id];
        } else if (Validation::uuid($id)) {
            $conditions = ['event_uuid' => $id];
        } else {
            throw new NotFoundException(__('Invalid event'));
        }
        $conditions['excludeLocalTags'] = false;
        $conditions['excludeGalaxy'] = true;
        $event = $this->Events->fetchEvent($this->ACL->getUser()->toArray(), $conditions);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $event = $event[0];
        $TaxonomiesTable = $this->fetchTable('Taxonomies');
        $allConflicts = [];
        $tagConflicts = $TaxonomiesTable->checkIfTagInconsistencies($event['EventTag']);
        if (!empty($tagConflicts['global']) || !empty($tagConflicts['local'])) {
            $tagConflicts['Event'] = $event['Event'];
            $allConflicts[] = $tagConflicts;
        }
        foreach ($event['Object'] as $k => $object) {
            if (isset($object['Attribute'])) {
                foreach ($object['Attribute'] as $k2 => $attribute) {
                    $this->Events->Attributes->removeGalaxyClusterTags($event['Object'][$k]['Attribute'][$k2]);
                    $tagConflicts = $TaxonomiesTable->checkIfTagInconsistencies($attribute['AttributeTag']);
                    if (!empty($tagConflicts['global']) || !empty($tagConflicts['local'])) {
                        $tagConflicts['Attribute'] = $event['Object'][$k]['Attribute'][$k2];
                        unset($tagConflicts['Attribute']['AttributeTag'], $tagConflicts['Attribute']['Galaxy'], $tagConflicts['Attribute']['ShadowAttribute']);
                        $allConflicts[] = $tagConflicts;
                    }
                }
            }
        }
        foreach ($event['Attribute'] as $k => $attribute) {
            $this->Events->Attributes->removeGalaxyClusterTags($event['Attribute'][$k]);
            $tagConflicts = $TaxonomiesTable->checkIfTagInconsistencies($attribute['AttributeTag']);
            if (!empty($tagConflicts['global']) || !empty($tagConflicts['local'])) {
                $tagConflicts['Attribute'] = $event['Attribute'][$k];
                unset($tagConflicts['Attribute']['AttributeTag'], $tagConflicts['Attribute']['Galaxy'], $tagConflicts['Attribute']['ShadowAttribute']);
                $allConflicts[] = $tagConflicts;
            }
        }
        return $this->RestResponse->viewData($allConflicts);
    }

    public function generateCount()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        // do one SQL query with the counts
        // loop over events, update in db
        $AttributesTable = $this->fetchTable('Attributes');
        $events = $AttributesTable->find(
            'all',
            [
                'recursive' => -1,
                'fields' => ['event_id', 'count(event_id) as attribute_count'],
                'group' => ['Attribute.event_id'],
                'order' => ['Attribute.event_id ASC'],
            ]
        );
        foreach ($events as $k => $event) {
            $this->Events->read(null, $event['Attribute']['event_id']);
            $this->Events->set('attribute_count', $event[0]['attribute_count']);
            $this->Events->save();
        }
        $this->Flash->success(__('All done. attribute_count generated from scratch for ' . (isset($k) ? $k : 'no') . ' events.'));
        $this->redirect(['controller' => 'pages', 'action' => 'display', 'administration']);
    }

    /**
     * @param array $event
     * @return ResponseFile
     * @throws Exception
     */
    private function __restResponse(array $event)
    {
        $tmpFile = new TmpFileTool();

        if ($this->request->is('json')) {
            if ($this->RestResponse->isAutomaticTool() && empty($event['Event']['protected'])) {
                foreach (JSONConverterTool::streamConvert($event) as $part) {
                    $tmpFile->write($part);
                }
            } else {
                $tmpFile->write(JSONConverterTool::convert($event));
            }
            $format = 'json';
        } elseif ($this->request->is('xml')) {
            $converter = new XMLConverterTool();
            foreach ($converter->frameCollection($converter->convert($event)) as $chunk) {
                $tmpFile->write($chunk);
            }
            $format = 'xml';
        } else {
            throw new Exception("Invalid format, only JSON or XML is supported.");
        }
        return $this->RestResponse->viewData($tmpFile, $format, false, true);
    }

    public function protect($id)
    {
        return $this->__toggleProtect($id, true);
    }

    public function unprotect($id)
    {
        return $this->__toggleProtect($id, false);
    }

    /**
     * @param string|int $id Event ID or UUID
     * @param bool $protect
     * @return Response|void
     * @throws Exception
     */
    private function __toggleProtect($id, $protect)
    {
        $event = $this->Events->fetchSimpleEvent($this->ACL->getUser()->toArray(), $id);
        if (empty($event) || !$this->ACL->canModifyEvent($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if ($this->request->is('post')) {
            $event['Event']['protected'] = $protect;
            $event['Event']['timestamp'] = time();
            $event['Event']['published'] = false;
            if ($this->Events->save($event)) {
                $message = __('Event switched to %s mode.', $protect ? __('protected') : __('unprotected'));
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('events', $protect ? 'protect' : 'unprotect', $event['Event']['id'], false, $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(['controller' => 'events', 'action' => 'view', $id]);
                }
            } else {
                $message = __('Something went wrong - could not switch event to %s mode.', $protect ? __('protected') : __('unprotected'));
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Events', $protect ? 'protect' : 'unprotect', $event['Event']['id'], $message);
                } else {
                    $this->Flash->error($message);
                    $this->redirect(['controller' => 'events', 'action' => 'view', $event['Event']['id']]);
                }
            }
        } else {
            $this->set('id', $event['Event']['id']);
            $this->set('title', $protect ? __('Protect event') : __('Remove event protection'));
            $this->set(
                'question',
                $protect ?
                    __('Are you sure you want switch the event to protected mode? The event and its subsequent modifications will be rejected by MISP instances that you synchronise with, unless the hop through which the event is propagated has their signing key in the list of event signing keys.') :
                    __('Are you sure you want to switch the event to unprotected mode? Unprotected mode is the default behaviour of MISP events, with creation and modification being purely limited by the distribution mechanism and eligible sync users.')
            );
            $this->set('actionName', $protect ? __('Switch to protected mode') : __('Remove protected mode'));
            $this->layout = false;
            $this->render('/genericTemplates/confirm');
        }
    }

    /**
     * @param array $event
     * @return void
     */
    private function __setHighlightedTags($event)
    {
        $TaxonomiesTable = $this->fetchTable('Taxonomies');
        $highlightedTags = $TaxonomiesTable->getHighlightedTags($TaxonomiesTable->getHighlightedTaxonomies(), $event['EventTag']);
        $this->set('highlightedTags', $highlightedTags);
    }

    /**
     *
     * @param array $events
     * @return array
     */
    private function __attachHighlightedTagsToEvents($events)
    {
        $TaxonomiesTable = $this->fetchTable('Taxonomies');
        $highlightedTaxonomies = $TaxonomiesTable->getHighlightedTaxonomies();
        foreach ($events as $k => $event) {
            $events[$k]['Event']['highlightedTags'] = $TaxonomiesTable->getHighlightedTags($highlightedTaxonomies, $event['EventTag']);
        }

        return $events;
    }
}
