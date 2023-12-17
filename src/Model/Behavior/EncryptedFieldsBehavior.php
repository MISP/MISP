<?php
namespace App\Model\Behavior;

use App\Lib\Tools\EncryptedValue;
use ArrayObject;
use Cake\Collection\CollectionInterface;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\ORM\Behavior;
use Cake\ORM\Query;


class EncryptedFieldsBehavior extends Behavior
{
    protected $_defaultConfig = [
        'fields' => []
    ];
    
    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $config = $this->getConfig();

        foreach ($config['fields'] as $field) {
            if (!$entity->has($field)) {
                continue;
            }
            $value = $entity->get($field) ?? '';
            $entity->set($field.'_orig', $value);
            $entity->set($field, EncryptedValue::encryptIfEnabled($value));
        }
    }

    // restore the changed value to have the unencrypted version in memory.
    public function afterSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $config = $this->getConfig();

        foreach ($config['fields'] as $field) {
            if (!$entity->has($field)) {
                continue;
            }
            $entity->set($field, $entity->get($field.'_orig'));
        }
    }

    public function beforeFind(EventInterface $event, Query $query, ArrayObject $options)
    {
        $config = $this->getConfig();
        $options = $query->getOptions();
        if (isset($options['decryption_key']))
            $decryption_key = $options['decryption_key'];
        else
            $decryption_key = false;
        $query->formatResults(
            function (CollectionInterface $results) use ($config, $decryption_key) {
                return $results->map(
                    function ($row) use ($config, $decryption_key) {
                        foreach ($config['fields'] as $field) {
                            if (isset($row[$field]) && !is_array($row[$field])) {
                                $row[$field] = EncryptedValue::decryptIfEncrypted($row[$field], $decryption_key);
                            }
                        }
                        return $row;
                    }
                );
            },
            $query::APPEND
        );
    }

    /**
     * Re-encrypt all data from the model. New encryption key is taken from the settings.
     * @param string|null $oldKey Old (or current) encryption key.
     * @throws Exception
     */
    public function changeKey($oldKey) {
        // we need to be careful here to not have a timing issue
        // the newKey must be enabled site-wide as otherwise new data would be saved with the old key
        $config = $this->getConfig();
        $fields = array_merge(['id'], $config['fields']);
        // decrypt the data using the after find decryption magic, and the old key
        $query = $this->_table->find('all', [
            'fields' => $fields,
            'decryption_key' => $oldKey
        ]);
        // save the data and let the behaviour save the key automagically
        // to work around issues with AuditLog loading data with a wrong encryption key we first need to unload that behaviour, if it's loaded
        $hasAuditLog = $this->_table->behaviors()->has('AuditLog');
        if ($hasAuditLog) $this->_table->removeBehavior('AuditLog');
        $result = $this->_table->saveMany($query);
        if ($hasAuditLog) $this->_table->addBehavior('AuditLog');
        return $result;
    }
}
