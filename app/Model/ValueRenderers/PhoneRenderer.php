<?php

/**
 * Where a number is, whose network it is on, and what kind of line.
 *
 * **Nothing emits this in practice.** One keyed module accepts a phone
 * number as input and answers about something else entirely; nothing
 * resolves a number to a carrier and a line type, which is the
 * question a fraud reader asks — a mobile, a landline and a VoIP
 * number carry different weight in the same case.
 *
 * Two templates: one describes a handset and the subscriber identities
 * in it, the other decomposes the number itself. They answer different
 * halves of the question and a reader wants both under one widget.
 */
class PhoneRenderer extends ValueRendererBase
{
    public $id = 'phone';

    public $templates = array('phone', 'phone-number');

    public $compact = 'Values/Renderers/phone_compact';

    public $full = 'Values/Renderers/phone_full';

    public $eventUse = self::EVENT_SET;

    public $producer = self::PRODUCER_NONE;

    public function __construct()
    {
        $this->description = __('The country, carrier and line type'
            . ' behind a phone number.');
        $this->producer_note = __('No module resolves a phone number'
            . ' to a carrier yet.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->numberOf($object) !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $numbers = array();
        foreach ($objects as $object) {
            $number = $this->numberOf($object);
            if ($number === null) {
                continue;
            }
            $key = $number['number'] ?? count($numbers);
            if (!isset($numbers[$key])) {
                $numbers[$key] = $number;
                continue;
            }
            /*
             * The two templates describe one number from two sides, so
             * a second object fills the gaps in the first rather than
             * standing beside it as a second row.
             */
            foreach ($numbers[$key] as $field => $value) {
                if ($value === null && isset($number[$field])) {
                    $numbers[$key][$field] = $number[$field];
                }
            }
        }
        $numbers = array_values($numbers);
        return array(
            'numbers' => $numbers,
            'headline' => empty($numbers) ? null : $numbers[0],
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function numberOf(array $object)
    {
        $number = $this->firstValue($object, array(
            'phone-number', 'msisdn',
        ));
        $country = $this->value($object, 'country-code');
        $device = $this->firstValue($object, array('brand', 'model'));
        if ($number === null && $country === null && $device === null) {
            return null;
        }
        return array(
            'number' => $number,
            'country' => $country,
            'destination' => $this->value(
                $object,
                'national-destination-code'
            ),
            'subscriber' => $this->value($object, 'subscriber-number'),
            'brand' => $this->value($object, 'brand'),
            'model' => $this->value($object, 'model'),
            'imei' => $this->value($object, 'imei'),
            'imsi' => $this->value($object, 'imsi'),
            'iccid' => $this->value($object, 'iccid'),
            'serial' => $this->value($object, 'serial-number'),
            'carrier' => null,
            'line_type' => null,
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }
}
