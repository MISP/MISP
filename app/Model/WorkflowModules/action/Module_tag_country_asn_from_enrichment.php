<?php
include_once APP . 'Model/WorkflowModules/action/Module_tag_operation.php';

class Module_tag_country_asn_from_enrichment extends WorkflowBaseActionModule
{
    public $blocking = false;
    public $id = 'tag_country_asn_from_enrichment';
    public $name = 'Tag attribute with country and ASN';
    public $version = '0.1';
    public $description = 'Tag attributes based on country and ASN information extracted from enrichment data.';
    public $icon = 'globe';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $params = [];

    private $Tag;
    private $Attribute;

    public function __construct()
    {
        parent::__construct();
        $this->Tag = ClassRegistry::init('Tag');
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $this->params = [
            [
                'id' => 'locality',
                'label' => __('Tag Locality'),
                'type' => 'select',
                'options' => ['local' => __('Local'), 'global' => __('Global')],
                'default' => 'local',
            ]
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
        $localIsLocal = (isset($params['locality']['value']) && $params['locality']['value'] === 'local');

        foreach ($matchingAttributes as $attribute) {
            $country = "";
            $country_code = "";
            $asn = "";
            $asnOrg = "";

            $country = $this->firstNonEmpty([
                Hash::extract($attribute, 'enrichment.{n}.Object.{n}.Attribute.{n}[object_relation=country].value'),
                Hash::extract($attribute, 'enrichment.{n}.Attribute.{n}[object_relation=country].value'),
            ]);
            $country = trim($country);

            $country_code = $this->firstNonEmpty([
                Hash::extract($attribute, 'enrichment.{n}.Object.{n}.Attribute.{n}[object_relation=countrycode].value'),
                Hash::extract($attribute, 'enrichment.{n}.Attribute.{n}[object_relation=countrycode].value'),
            ]);

            $asn = $this->firstNonEmpty([
                Hash::extract($attribute, 'enrichment.{n}.Object.{n}.Attribute.{n}[object_relation=asn].value'),
                Hash::extract($attribute, 'enrichment.{n}.Attribute.{n}[object_relation=asn].value'),
                Hash::extract($attribute, 'enrichment.{n}.Object.{n}.Attribute.{n}[object_relation=ASN].value'),
            ]);
            if (!empty($asn) && preg_match('/\d+/', $asn, $m)) {
                $asn = $m[0];
            } else {
                $asn = null;
            }

            $asnOrg = $this->firstNonEmpty([
                Hash::extract($attribute, 'enrichment.{n}.Object.{n}.Attribute.{n}[object_relation=ASNOrganization].value'),
                Hash::extract($attribute, 'enrichment.{n}.Attribute.{n}[object_relation=ASNOrganization].value'),
            ]);
            if (empty($asnOrg)) {
                $descVals = Hash::extract($attribute, 'enrichment.{n}.Object.{n}.Attribute.{n}[object_relation=description].value');
                if (empty($descVals)) {
                    $descVals = Hash::extract($attribute, 'enrichment.{n}.Attribute.{n}[object_relation=description].value');
                }
                if (!empty($descVals)) {
                    foreach ($descVals as $dv) {
                        if (!is_string($dv) || trim($dv) === '') {
                            continue;
                        }
                        if (preg_match('/ASNOrganization\s*[:\-]?\s*"?([A-Za-z0-9\-\._\s]+?)"?(\.|$)/i', $dv, $m)) {
                            $asnOrg = trim($m[1]);
                            break;
                        }
                        if (preg_match('/\bASN(?:Organization|Org)?\b.*?([A-Z][A-Za-z0-9\-\._\s]+)/i', $dv, $m2)) {
                            $asnOrg = trim($m2[1]);
                            break;
                        }
                    }
                }
            }

            $moduleTags = [];
            if (!empty($country)) {
                $moduleTags[] = 'country:"' . strtoupper($country) . '"';
            }
            if (!empty($asn)) {
                $moduleTags[] = 'asn_number:"' . $asn . '"';
            }
            if (!empty($asnOrg)) {
                $moduleTags[] = 'asn_org:"' . str_replace('"', "'", $asnOrg) . '"';
            }
            if (!empty($country_code)) {
                $moduleTags[] = 'country_code:"' . $country_code . '"';
            }

            $moduleTags = array_values(array_unique($moduleTags));
            if (!empty($moduleTags)) {
                $options = [
                    'tags' => $moduleTags,
                    'local' => $localIsLocal,
                    'relationship_type' => ''
                ];
                $tagAttached = [];
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

    private function firstNonEmpty($arrays)
    {
        if (!is_array($arrays)) {
            return null;
        }
        foreach ($arrays as $arr) {
            if (!is_array($arr)) {
                    continue;
            }
            foreach ($arr as $v) {
                if (is_string($v) && trim($v) !== '') {
                    return trim($v);
                }
            }
        }
        return null;
    }
}
