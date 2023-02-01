<?php


namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Cake\ORM\RulesChecker;
use Cake\ORM\Rule\IsUnique;

class AllowedlistsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('allowedlist');
        $this->addBehavior('AuditLog');
        $this->setDisplayField('name');
    }

    public $allowedlistedItems = false;

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence('name')
            ->notEmptyString('name')
            ->add('name', 'validRegex', [
                'rule' => 'isValidRegex',
                'message' => __('You need to provide a valid regex'),
                'provider' => 'table',
            ]);
        return $validator;
    }

    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['name']));
        return $rules;
    }

    public $validate = array(
        'name' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
            'userdefined' => array(
                'rule' => array('validateValue'),
                'message' => 'Name not in the right format. Allowedlist entries have to be enclosed by a valid php delimiter (which can be most non-alphanumeric / non-whitespace character). Format: "/8.8.8.8/" Please double check the name.',             //'allowEmpty' => false,
                //'allowEmpty' => false,
                //'required' => true,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
            'unique' => array(
                    'rule' => 'isUnique', //array('valueIsUnique'),
                    'message' => 'A similar name already exists.',
                    //'allowEmpty' => false,
                    //'required' => true,
                    //'last' => false, // Stop validation after this rule
                    //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
    );

    // regexp validation
    public function isValidRegex($value, array $context)
    {
        return preg_match($value, 'test') !== false;
    }

    public function getBlockedValues()
    {
        if ($this->allowedlistedItems === false) {
            $data = $this->find()->select(['name'])->disableHydration()->all();
            $this->allowedlistedItems = [];
            foreach ($data as $item) {
                $this->allowedlistedItems[] = $item['name'];
            }
        }
        return $this->allowedlistedItems;
    }

    private function removeAllowlistedFromAttributeArray(array $data, array $allowedlists): array
    {
        foreach ($data as $k => $attribute) {
            // loop through each allowedlist item and run a preg match against the attribute value. If it matches, unset the attribute
            foreach ($allowedlists as $wlitem) {
                if (preg_match($wlitem, $attribute['Attribute']['value'])) {
                    unset($data[$k]);
                }
            }
        }
        return array_values($data);
    }

    // TODO: decide on entity lists vs array as the input and change the function accordingly
    public function removeAllowedlistedFromArray(mixed $data, bool $isAttributeArray): mixed
    {
        $allowedlists = $this->getBlockedValues();
        if (!empty($allowedlists)) {
            if ($isAttributeArray) {
                $data = $this->removeAllowlistedFromAttributeArray($data, $allowedlists);
            } else {
                foreach ($data as $ke => $event) {
                    if (isset($event['Attribute'])) {
                        $data[$ke]['Attribute'] = $this->removeAllowlistedFromAttributeArray($event['Attribute'], $allowedlists);
                    }
                }
            }
        }
        return $data;
    }

    // A simplified allowedlist removal, for when we just want to throw values against the list instead of attributes / events
    public function removeAllowedlistedValuesFromArray(mixed $data): mixed
    {
        $allowedlists = $this->getBlockedValues();
        if (!empty($allowedlists)) {
            $data = $this->removeAllowlistedFromAttributeArray($data, $allowedlists);
        }
        return $data;
    }
}
