<?php

/**
 * Who issued a card, and on which scheme.
 *
 * **Nothing anywhere emits this**, for the same reason the widget is
 * written anyway: the template exists, the module does not, and
 * naming the template here is what lets the two be built without
 * agreeing about anything else first. The open question upstream is
 * not difficulty — the first six digits of a card number identify the
 * issuer — but the licensing of a dataset that maps them.
 */
class PaymentCardRenderer extends ValueRendererBase
{
    public $id = 'payment-card';

    public $templates = array('credit-card');

    public $compact = 'Values/Renderers/payment_card_compact';

    public $full = 'Values/Renderers/payment_card_full';

    public $eventUse = self::EVENT_SET;

    public $producer = self::PRODUCER_NONE;

    public function __construct()
    {
        $this->description = __('The issuer and scheme behind a card'
            . ' number.');
        $this->producer_note = __('No module resolves a card prefix'
            . ' yet.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->cardOf($object) !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $cards = array();
        foreach ($objects as $object) {
            $card = $this->cardOf($object);
            if ($card !== null) {
                $cards[] = $card;
            }
        }
        return array(
            'cards' => $cards,
            'headline' => empty($cards) ? null : $cards[0],
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function cardOf(array $object)
    {
        $issuer = $this->value($object, 'bank_name');
        $iin = $this->value($object, 'iin');
        if ($issuer === null && $iin === null) {
            return null;
        }
        return array(
            'issuer' => $issuer,
            'iin' => $iin,
            /*
             * The scheme is derived from the first digit, which is
             * fixed by the numbering standard rather than by any
             * dataset — so it is the one fact this widget can state
             * with nothing more than the number in front of it.
             */
            'scheme' => $this->schemeOf($iin
                ?? $this->value($object, 'cc-number')),
            'holder' => $this->value($object, 'name'),
            'expires' => $this->value($object, 'expiration'),
            'issued' => $this->value($object, 'issued'),
            'comment' => $this->value($object, 'comment'),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }

    /**
     * @param string|null $number
     * @return string|null
     */
    private function schemeOf($number)
    {
        if ($number === null) {
            return null;
        }
        $digits = preg_replace('/\D/', '', $number);
        if ($digits === '') {
            return null;
        }
        $first = $digits[0];
        $two = strlen($digits) > 1 ? substr($digits, 0, 2) : '';
        if ($first === '4') {
            return 'Visa';
        }
        if ($two >= '51' && $two <= '55') {
            return 'Mastercard';
        }
        if ($two === '34' || $two === '37') {
            return 'American Express';
        }
        if ($two === '65' || substr($digits, 0, 4) === '6011') {
            return 'Discover';
        }
        if ($two === '35') {
            return 'JCB';
        }
        return null;
    }
}
