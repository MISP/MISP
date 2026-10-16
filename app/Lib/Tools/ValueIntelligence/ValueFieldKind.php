<?php

/**
 * Which of an object's fields lead somewhere, and which describe it.
 *
 * MISP records no relational/descriptive split of *templates*, which is
 * why none is invented here. It does record it per **attribute**:
 * `disable_correlation` is the template's own statement of which of its
 * fields exist to link and which exist to describe, and the correlation
 * engine acts on exactly that column.
 *
 * It is one rule with several callers, and this class gives it one
 * name and one spelling. What rests on it:
 *
 *   the object branch    which attributes may identify a far object
 *                        `Value::referenceFacesFor`
 *   the edge label       `rrname → rdata`, not
 *                        `rrname → count, origin, time_first`
 *   the far value        a dated row's other end, so a resolution is
 *                        not described as `rrtype = A`
 *   the sibling order    linking fields before describing ones, and
 *                        the Field kind facet over them
 *
 * **It is read from the attribute and not from the template**, which
 * matters because the two disagree. The template is where the intent is
 * authored (`object_template_elements.disable_correlation`), but core
 * copies the flag onto the attribute at creation and never reconciles
 * it: attributes in template-backed objects can carry something their
 * template no longer says, and objects can belong to a template that is
 * not installed at all. The attribute is also the only one of the two
 * the engine consults, so a panel that classified from the template
 * would promise pivots MISP will not make.
 *
 * Pure and static, and it takes no `$user`.
 */
class ValueFieldKind
{
    /**
     * A field the correlation engine links on.
     *
     * The string is also the facet token and the array key the sibling
     * bar counts under, so the fold, the row's `data-vp-facet` and the
     * dropdown cannot spell it three ways.
     */
    const LINKING = 'linking';

    /** The same, for a field it does not link on. */
    const DESCRIPTIVE = 'descriptive';

    /**
     * @param array $attribute An attribute row, `Attribute` scope
     * @return bool
     */
    public static function isLinking(array $attribute)
    {
        return empty($attribute['disable_correlation']);
    }

    /**
     * @param array $attribute An attribute row, `Attribute` scope
     * @return string self::LINKING or self::DESCRIPTIVE
     */
    public static function of(array $attribute)
    {
        return self::isLinking($attribute)
            ? self::LINKING
            : self::DESCRIPTIVE;
    }

    /**
     * The same rule as a `find()` condition, for the callers that have
     * to apply it in SQL rather than over rows already read.
     *
     * @param string $alias Model alias the condition is written against
     * @return array
     */
    public static function linkingConditions($alias = 'Attribute')
    {
        return array($alias . '.disable_correlation' => 0);
    }

    /**
     * One field's kind, from the flags its attributes carry.
     *
     * **A field votes once.** The flag is stored per attribute and
     * templates are inconsistent about it — one field can carry 0 on
     * some of its attributes and 1 on the rest — so deciding row by row
     * puts two rows of the *same field* on opposite sides of a table
     * that then dims one and not the other with nothing on screen to
     * explain it.
     *
     * A tie goes to linking: the engine correlated on half of them, so
     * it is a field you can actually pivot from.
     *
     * @param int $linking Attributes under the field flagged 0
     * @param int $descriptive The same, flagged 1
     * @return string self::LINKING or self::DESCRIPTIVE
     */
    public static function fromTally($linking, $descriptive)
    {
        return (int)$linking >= (int)$descriptive
            ? self::LINKING
            : self::DESCRIPTIVE;
    }
}
