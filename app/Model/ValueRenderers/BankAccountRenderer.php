<?php

/**
 * Whose account an IBAN is, and where.
 *
 * **Nothing anywhere emits this**, and the renderer is written anyway.
 * A renderer keyed on a shape nothing emits never matches, so it costs
 * the reader nothing — there is no empty panel and no promise of a
 * capability, which is what makes this different from shipping an
 * inert control.
 *
 * What it does instead is invert the dependency. Whoever writes the
 * module that resolves an IBAN emits the template that already has a
 * widget, rather than landing as a generic chip until somebody
 * notices; and because the template is named here, the module and the
 * widget can be built independently without disagreeing about the
 * shape. The structure and the institution are derivable from the IBAN
 * registry with no third-party call at all, which makes this the
 * cheapest of the missing modules.
 */
class BankAccountRenderer extends ValueRendererBase
{
    public $id = 'bank-account';

    public $templates = array('bank-account', 'ftm-BankAccount');

    public $compact = 'Values/Renderers/bank_account_compact';

    public $full = 'Values/Renderers/bank_account_full';

    public $eventUse = self::EVENT_SET;

    public $producer = self::PRODUCER_NONE;

    public function __construct()
    {
        $this->description = __('The institution and country behind an'
            . ' account number.');
        $this->producer_note = __('No module resolves an IBAN or a BIC'
            . ' yet.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->accountOf($object) !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $accounts = array();
        foreach ($objects as $object) {
            $account = $this->accountOf($object);
            if ($account !== null) {
                $accounts[] = $account;
            }
        }
        return array(
            'accounts' => $accounts,
            'headline' => empty($accounts) ? null : $accounts[0],
            'sources' => $this->sources($objects),
        );
    }

    /**
     * Both templates say the same things under different names — one
     * is MISP's own and the other follows an external ontology — so
     * each field asks for both spellings.
     *
     * @param array $object
     * @return array|null
     */
    private function accountOf(array $object)
    {
        $iban = $this->firstValue($object, array('iban', 'account',
            'accountNumber'));
        $institution = $this->firstValue($object, array(
            'institution-name', 'bankName', 'non-banking-institution',
        ));
        if ($iban === null && $institution === null) {
            return null;
        }
        return array(
            'iban' => $iban,
            'institution' => $institution,
            'bic' => $this->firstValue($object, array('swift', 'bic')),
            'country' => $this->value($object, 'country'),
            'holder' => $this->firstValue($object, array(
                'account-name', 'beneficiary', 'name',
            )),
            'currency' => $this->firstValue($object, array(
                'currency-code', 'currency',
            )),
            'balance' => $this->number(
                $this->value($object, 'balance')
            ),
            'status' => $this->firstValue($object, array(
                'status-code', 'accountType', 'personal-account-type',
            )),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }
}
