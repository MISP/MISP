<?php
include_once APP . 'Model/WorkflowModules/action/Module_tag_operation.php';
include_once APP . 'Model/WorkflowModules/action/Module_webhook.php';
include_once APP . 'Model/WorkflowModules/action/Module_attribute_edition_operation.php';

class Module_tag_cve_from_enrichment extends Module_webhook
{
    public $blocking = false;
    public $id = 'tag_cve_from_enrichment';
    public $name = 'Tag attribute with CVE information';
    public $version = '0.1';
    public $description = 'Tag an attribute based on CVE information extracted from CVE premium (not via an enrichment module). The CVSS score is used to create relevant tags, and the CVE summary is appended to the attribute comment.';
    public $icon = 'globe';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $params = [];

    private $Tag;
    private $Attribute;
    private $Note;
    private $cveEndpoint = 'https://vulnerability.circl.lu/api/cve/';
    private $cveKeys = ["cvssV3_1", "cvssV4", "cvssV3", "cvssV2"];
    private $threatHigh = 7.0;
    private $threatMedium = 4.0;
    private $vulnerability_ttp = 'misp-galaxy:mitre-attack-pattern="Vulnerabilities - T1588.006"';
    

    public function __construct()
    {
        parent::__construct();
        $this->Tag = ClassRegistry::init('Tag');
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $this->Note = ClassRegistry::init('Note');
        $this->params = [
                [
                    'id' => 'locality',
                    'label' => __('Tag locality'),
                    'type' => 'select',
                    'options' => array('local' => __('Local'), 'global' => __('Global')),
                    'default' => 'local',
                ],
                [
                    'id' => 'add_vulnerability_ttp',
                    'label' => 'Add vulnerability TTP (T1588.006)',
                    'type' => 'select',
                    'default' => '1',
                    'options' => [
                        'no' => __('No'),
                        'yes' => __('Yes'),
                    ],
                ],                
            ];
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        $user = $roamingData->getUser();

        if ($this->filtersEnabled($node)) {
            $filters = $this->getFilters($node);
            $extracted = $this->extractData($rData, $filters['selector']);
            if ($extracted === false) {
                return false;
            }
            $matchingItems = $this->getItemsMatchingCondition($extracted, $filters['value'], $filters['operator'], $filters['path']);
        } else {
            $matchingItems = $rData;
        }

        $matchingAttributes = Hash::extract($matchingItems, 'Event._AttributeFlattened.{n}');
        $success = false;
        $localityIsLocal = (isset($params['locality']['value']) && $params['locality']['value'] === 'local');

        foreach ($matchingAttributes as $attribute) {
            $cve_summary = 'No summary found';
            $cvss_base_score = null;
                       
            if ($attribute['type'] !== 'vulnerability') {
                continue;
            }

            $cve = isset($attribute['value']) ? $attribute['value'] : null;
            if (empty($cve)) {
                continue;
            }

            $response = $this->doRequest($this->cveEndpoint . urlencode($cve), 'application/json', null, array(), 'get');
            if (!isset($response->code) || $response->code !== 200) {
                $errors[] = __('Request failed with HTTP %s: %s', $response->code ?? 'N/A', $response->body ?? '');
                continue;
            }

            $body = $response->body ?? '';
            $cve_data = json_decode($body, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $clean = trim($body);
                if (strlen($clean) >= 2 && $clean[0] === '"' && $clean[strlen($clean)-1] === '"') {
                    $clean = substr($clean, 1, -1);
                    $clean = str_replace('\"', '"', $clean);
                    $clean = stripslashes($clean);
                }
                if (json_last_error() !== JSON_ERROR_NONE) {
                    $lines = preg_split('/\r\n|\r|\n/', $clean);
                    foreach ($lines as $ln) {
                        $ln = trim($ln);
                        if ($ln === '') {
                            continue;
                        }
                        if ($ln[0] === '{') {
                            $try = json_decode($ln, true);
                            if (json_last_error() === JSON_ERROR_NONE) {
                                $cve_data = $try;
                                break;
                            }
                        }
                    }
                }
                if (empty($cve_data)) {
                    $cve_data = json_decode($clean, true) ?: array();
                }
            }
            $containers = is_array($cve_data['containers'] ?? null) ? $cve_data['containers'] : array();
            $cna = is_array($containers['cna'] ?? null) ? $containers['cna'] : array();
            $adp = is_array($containers['adp'] ?? null) ? $containers['adp'] : array();

            $descs = array();
            if (isset($cna['descriptions']) && is_array($cna['descriptions'])) {
                $descs = array_merge($descs, $cna['descriptions']);
            }
            if (isset($cve_data['description']['description_data']) && is_array($cve_data['description']['description_data'])) {
                $descs = array_merge($descs, $cve_data['description']['description_data']);
            }
            if (isset($cna['description'])) {
                $d = $cna['description'];
                if (is_array($d)) {
                    $descs = array_merge($descs, $d);
                } elseif (is_string($d) && $d !== '') {
                    $descs[] = array('value' => $d);
                }
            }
            if (empty($descs) && isset($cve_data['x_legacyV4Record']['description']['description_data']) && is_array($cve_data['x_legacyV4Record']['description']['description_data'])) {
                $descs = array_merge($descs, $cve_data['x_legacyV4Record']['description']['description_data']);
            }
            foreach ($descs as $desc) {
                if (!is_array($desc)) {
                    continue;
                }
                $lang = strtolower(trim((string)($desc['lang'] ?? $desc['language'] ?? '')));
                $val = $desc['value'] ?? $desc['description'] ?? null;
                if ($val === null) {
                    continue;
                }
                if ($lang === 'en' || $lang === 'eng' || strpos($lang, 'en') === 0) {
                    $cve_summary = trim($val);
                    break;
                }
            }
            if ($cve_summary === 'No summary found' && !empty($descs)) {
                $first = reset($descs);
                $cve_summary = trim($first['value'] ?? $first['description'] ?? $cve_summary);
            }

            if (is_array($cna)) {
                foreach ($cna['metrics'] ?? array() as $metric) {
                    foreach ($this->cveKeys as $key) {
                        if (isset($metric[$key]['baseScore'])) {
                            $cvss_base_score = $metric[$key]['baseScore'];
                            break 2;
                        }
                    }
                }
            }
 
            if ($cvss_base_score === null && is_array($adp)) {
                foreach ($adp as $adp_entry) {
                    foreach ($adp_entry['metrics'] ?? array() as $metric) {
                        foreach ($this->cveKeys as $key) {
                            if (isset($metric[$key]['baseScore'])) {
                                $cvss_base_score = $metric[$key]['baseScore'];
                                break 3;
                            }
                        }
                    }
                }
            }

            $moduleTags = array();
            if ((isset($params['add_vulnerability_ttp']['value']) && $params['add_vulnerability_ttp']['value'] === 'yes')) {
                $moduleTags[] = $this->vulnerability_ttp; 
            }            
            if (is_numeric($cvss_base_score)) {
                $moduleTags[] = 'CVSS:' . $cvss_base_score;
                $score = (float) $cvss_base_score;
                if ($score >= $this->threatHigh) {
                    $moduleTags[] = 'misp:threat-level="high-risk"';
                } elseif ($score >= $this->threatMedium) {
                    $moduleTags[] = 'misp:threat-level="medium-risk"';
                } else {
                    $moduleTags[] = 'misp:threat-level="low-risk"';
                }
            } else {
                $moduleTags[] = 'CVSS:unknown';
                $moduleTags[] = 'misp:threat-level="unknown-risk"';
            }

            if (!empty($moduleTags)) {
                $options = array(
                    'tags' => array_values(array_unique($moduleTags)),
                    'local' => $localityIsLocal,
                    'relationship_type' => ''
                );
                $tagAttached = array();
                $saveSuccess = $this->Attribute->attachTagsToAttributeAndTouch($attribute['id'], $attribute['event_id'], $options, $user, $tagAttached);
                if ($saveSuccess) { 
                    $this->_buildFastLookupForRoamingData($roamingData->getData()); // Ensure fast lookup is updated before adding tags
                    $tags = $this->genTagObjectsFromTagNames($tagAttached, $options); 
                    $updatedRData = $this->_addTag($tags, 'attribute', $roamingData->getData(), $attribute); 
                    $roamingData->setData($updatedRData); 
                    $this->_buildFastLookupForRoamingData($roamingData->getData()); // Rebuild fast lookup after adding tags
                }                
                $success = $success || !empty($saveSuccess);
            }

            if ($success && strlen(trim($cve_summary)) > 0 && (strpos($attribute['comment'], 'CVE Summary:') === false)) {
                $newAttribute = $attribute;
                unset($newAttribute['timestamp']);
                $existingComment = isset($attribute['comment']) ? $attribute['comment'] : '';
                $newComment = trim($existingComment . ' CVE Summary: ' . $cve_summary);
                $newAttribute['comment'] = mb_substr($newComment, 0, 65535);
                $saveSuccess = $this->Attribute->editAttribute($newAttribute, $rData, $user, isset($newAttribute['object_id']) ? $newAttribute['object_id'] : null);
                $this->Attribute->editAttributeBulk([$newAttribute], $rData , $user);                
                $success = $success || !empty($saveSuccess);
                if ($success) {
                    $this->_buildFastLookupForRoamingData($roamingData->getData()); // Ensure fast lookup is updated before overriding
                    $rData = $this->_overrideAttribute($attribute, $newAttribute, $rData);
                    $roamingData->setData($rData);
                    $this->_buildFastLookupForRoamingData($roamingData->getData()); // Rebuild fast lookup after overriding
                }
            }

        }

        return $success;
    }

    /* copied from private function in Module_tag_operation.php */
    private function genTagObjectsFromTagNames($tagNames, $options): array
    {
        return array_map(function ($tagName) use ($options) {
            return [
                'name' => $tagName,
                'relationship_type' => $options['relationship_type'],
                'local' => $options['local'],
            ];
        }, $tagNames);
    }
}
