<?php

namespace MetaFieldsTypes;

use Cake\Database\Expression\QueryExpression;
use Cake\ORM\TableRegistry;
use Cake\ORM\Query;

use MetaFieldsTypes\TextType;
use TypeError;
use App\Lib\Tools\CidrTool;

class IPv4Type extends TextType
{
    public const OPERATORS = ['contains', 'excludes'];
    public const TYPE = 'ipv4';

    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Validate the provided value against the expected type
     *
     * @param string $value
     * @return boolean
     */
    public function validate(string $value): bool
    {
        return $this->_isValidIP($value) || $this->_isValidIP(explode('/', $value)[0]);
    }

    public function setQueryExpression(QueryExpression $exp, string $searchValue, \App\Model\Entity\MetaTemplateField $metaTemplateField): QueryExpression
    {
        if (strpos($searchValue, '%') !== false) {
            $textHandler = new TextType(); // we are wildcard filtering, use text filter instead
            return $textHandler->setQueryExpression($exp, $searchValue, $metaTemplateField);
        }
        $allMetaValues = $this->fetchAllValuesForThisType([], $metaTemplateField);
        $isNegation = false;
        if (substr($searchValue, 0, 1) == '!') {
            $searchValue = substr($searchValue, 1);
            $isNegation = true;
        }

        foreach ($allMetaValues as $fieldID => $ip) {
            $cidrTool = new CidrTool([$ip]);
            if ($cidrTool->contains($searchValue) === false) {
                if (!$isNegation) {
                    unset($allMetaValues[$fieldID]);
                }
            } else if ($isNegation) {
                unset($allMetaValues[$fieldID]);
            }
        }
        $matchingIDs = array_keys($allMetaValues);
        if (!empty($matchingIDs)) {
            $exp->in('MetaFields.id', $matchingIDs);
        } else {
            $exp->eq('MetaFields.id', -1); // No matching meta-fields, generate an impossible condition to return nothing
        }
        return $exp;
    }

    protected function fetchAllMetatemplateFieldsIdForThisType(\App\Model\Entity\MetaTemplateField $metaTemplateField = null): Query
    {
        $this->MetaTemplateFields = TableRegistry::getTableLocator()->get('MetaTemplateFields');
        $conditions = [];
        if (!is_null($metaTemplateField)) {
            $conditions['id'] = $metaTemplateField->id;
        } else {
            $conditions['type'] = $this::TYPE;
        }
        $query = $this->MetaTemplateFields->find()->select(['id'])
            ->distinct()
            ->where($conditions);
        return $query;
    }

    protected function fetchAllValuesForThisType(array $conditions=[], \App\Model\Entity\MetaTemplateField $metaTemplateField=null): array
    {
        $metaTemplateFieldsIDs = $this->fetchAllMetatemplateFieldsIdForThisType($metaTemplateField);
        if (empty($metaTemplateFieldsIDs)) {
            return [];
        }
        $conditions = array_merge($conditions, ['meta_template_field_id IN' => $metaTemplateFieldsIDs]);
        $allMetaValues = $this->MetaFields->find('list', [
            'keyField' => 'id',
            'valueField' => 'value'
        ])->where($conditions)->toArray();
        return $allMetaValues;
    }

    protected function _isValidIP(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }
}
