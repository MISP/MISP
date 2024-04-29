<?php
declare(strict_types=1);

namespace App\Model\Entity;

use Cake\ORM\TableRegistry;

class Warninglist extends AppModel
{
    public const CATEGORY_FALSE_POSITIVE = 'false_positive',
        CATEGORY_KNOWN = 'known';

    public const TLDS = [
        'TLDs as known by IANA',
    ];

    /**
     * _getWarninglistEntryCount adds virtual field counting the number of entries in the warninglist
     *
     * @return int the amount of entries in the warninglist
     */
    protected function _getWarninglistEntryCount()
    {
        $warninglist_entries_table = TableRegistry::getTableLocator()->get('WarninglistEntries');
        $entry_count = $warninglist_entries_table->find('all')
            ->where(['warninglist_id' => $this->id])
            ->count();

        return $entry_count;
    }
}
