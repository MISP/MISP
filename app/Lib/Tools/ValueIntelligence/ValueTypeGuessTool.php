<?php

App::uses('ComplexTypeTool', 'Tools');
App::uses('AttributeValidationTool', 'Tools');

/**
 * A type for a value the reader holds no occurrence of, so that it can
 * still be matched to enrichment modules.
 *
 * `read()` is the freetext import parser's opinion of the value's shape.
 * It recognises about half of MISP's types, so it only ever suggests;
 * `rank()` orders every other type by whether MISP would accept the value
 * as one, so the reader can pick a type the parser missed.
 *
 * Pure and static, and it takes no `$user`.
 */
class ValueTypeGuessTool
{
    /** The value validates as the type, and the type does not take any text. */
    const FITS = 'fits';

    /** The type validates any text, so accepting this value says nothing. */
    const ANY_TEXT = 'any_text';

    /** MISP would refuse the value as this type. */
    const FAILS = 'fails';

    /**
     * No structured type accepts this; a type that does accepts anything.
     */
    const PROBE = 'not a ~ value';

    /**
     * The types the freetext parser reads the value as, its default first.
     *
     * Empty when it reads nothing, finds more than one indicator, or hands
     * back a different string — it turns `1.2.3.4:443` into `1.2.3.4|443`,
     * and enriching that would be enriching another value.
     *
     * @param string $value
     * @param array $known Type names that may be offered
     * @param array|null $tlds As `ComplexTypeTool::setTLDs`
     * @param array|null $vendorDomains As `setSecurityVendorDomains`
     * @return array<string>
     */
    public static function read($value, array $known, $tlds = null,
        $vendorDomains = null
    ) {
        $value = (string)$value;
        if ($value === '') {
            return array();
        }
        $tool = new ComplexTypeTool();
        if ($tlds !== null) {
            $tool->setTLDs($tlds);
        }
        if ($vendorDomains !== null) {
            $tool->setSecurityVendorDomains($vendorDomains);
        }
        $hits = $tool->checkFreeText($value);
        if (count($hits) !== 1 || (string)$hits[0]['value'] !== $value) {
            return array();
        }
        $types = array_merge(
            array($hits[0]['default_type']),
            (array)$hits[0]['types']
        );
        return array_values(array_unique(
            array_intersect($types, $known)
        ));
    }

    /**
     * Split types into what the value fits, what takes any text, and
     * what MISP would refuse it as. Input order is kept within a group.
     *
     * @param string $value
     * @param array $types
     * @return array `fits`, `any_text`, `fails`, each a list of type names
     */
    public static function rank($value, array $types)
    {
        $out = array(
            self::FITS => array(),
            self::ANY_TEXT => array(),
            self::FAILS => array(),
        );
        foreach ($types as $type) {
            if (!self::accepts($type, (string)$value)) {
                $out[self::FAILS][] = $type;
            } elseif (self::accepts($type, self::PROBE)) {
                $out[self::ANY_TEXT][] = $type;
            } else {
                $out[self::FITS][] = $type;
            }
        }
        return $out;
    }

    /**
     * Whether MISP would save the value as this type.
     *
     * @param string $type
     * @param string $value
     * @return bool
     */
    public static function accepts($type, $value)
    {
        try {
            return AttributeValidationTool::validate(
                $type,
                AttributeValidationTool::modifyBeforeValidation($type, $value)
            ) === true;
        } catch (InvalidArgumentException $e) {
            return false;
        }
    }
}
