<?php

/**
 * What a value renderer is: a class that turns one enrichment answer
 * into something a person can read at a glance.
 *
 * The Overview's enrichment panel summarises a module's answer as
 * chips — `country United States`, `1,374 passive-dns` — and that
 * summary was always a placeholder. It reads well for a module that
 * answered with four relations and says almost nothing for one that
 * answered with a thousand. What an analyst wants from a geolocation
 * answer is a map, from a passive-DNS answer a timeline, and from a
 * verdict a ratio; none of that is derivable from a chip.
 *
 * ## Keyed on the shape of the answer, never on the module
 *
 * A renderer claims one or more **MISP object template names** and is
 * chosen when the answer carries one. Three keys were available and
 * only this one survives contact with the data:
 *
 * - *By module* — there are over a hundred expansion modules and
 *   contributors add more. A roster mapping each to a layout is a
 *   maintenance list that is wrong the week after it is written.
 * - *By attribute type* — `ip-src` is declared by dozens of modules,
 *   which all answer different questions about it. One fixed layout
 *   per type is the wrong layout for most of them.
 * - *By returned shape* — a `geolocation` object is a map whether it
 *   came from `mmdb_lookup`, `geoip_city` or `ipinfo`. A set of
 *   `passive-dns` relations carrying dates is a timeline whoever
 *   fetched it.
 *
 * The object template name is the stable contract both sides of the
 * request already share, and it is user-extensible: an organisation
 * that defines its own object and runs a module returning it gets a
 * widget by dropping a file in, without patching core.
 *
 * **A module returning a bare `text` relation matches no shape and
 * keeps its chip.** That is the honest fallback and is explicitly not
 * a defect.
 *
 * **Two shapes claim a set of templates rather than one name**, because
 * the ecosystem answers the same question with different templates:
 * a reputation verdict arrives as `greynoise-ip`, `abuseipdb` or
 * `crowdsec-ip-context`, and a file verdict as `virustotal-report` or
 * `google-threat-intelligence-report`. Verdict vendors do not share a
 * template — each ships its own — so for those two shapes the set is a
 * per-vendor list until a generic one exists upstream. The key is
 * still the template and never the module.
 *
 * ## Discovery, and the five rules that come with it
 *
 * Renderers are **discovered from the filesystem**, the third subject
 * to be: the shipped ones live beside this file, an instance admin
 * drops their own in `app/Lib/ValueRenderers/`, and every rule the
 * loader already applies to signals and to escalations applies here.
 *
 * 1. **Discovery is not activation.** Dropping a renderer in changes
 *    nothing until a profile ranks its shape. Nothing moves on the
 *    instance because a file appeared.
 * 2. **A colliding claim is refused, not overridden.** Shipped files
 *    load first and keep their templates; a custom file claiming a
 *    template already claimed is logged and skipped. Two renderers for
 *    one shape would mean two instances drawing the same answer
 *    differently — so the uniqueness here is on `$templates` as well
 *    as on `$id`.
 * 3. **A broken file is an honest state, never a fatal.** It does not
 *    parse, the class is missing, the class is not a renderer: logged,
 *    skipped, the shape unavailable, and the reason kept for the
 *    editor.
 * 4. **One scan per request, no cache across requests.**
 * 5. **Nothing in the UI ever writes one of these files.**
 *
 * ## The class to write
 *
 * ```php
 * class GeolocationRenderer extends ValueRendererBase
 * {
 *     public $id = 'geolocation';
 *     public $templates = array('geolocation', 'ip-api-address');
 *     public $compact = 'Values/Renderers/geolocation_compact';
 *     public $full = 'Values/Renderers/geolocation_full';
 *
 *     public function matches(array $objects, array $attributes)
 *     {
 *         return $this->firstWith($objects, 'country') !== null;
 *     }
 *
 *     public function prepare(array $objects, array $attributes)
 *     {
 *         return array('points' => …);
 *     }
 * }
 * ```
 *
 * `matches()` exists so a renderer can **decline an answer that
 * carries its template but not the fields it needs**. A `passive-dns`
 * object with no dates cannot be a timeline, and drawing an empty
 * chart is worse than keeping the chip. Declining is not an error and
 * is not reported anywhere: the answer simply stays a chip.
 *
 * `prepare()` returns the view's data and is **where every computation
 * lives**. A template that computes is how two surfaces start to
 * disagree, and the compact and full forms of one shape are two
 * surfaces over one answer; with the arithmetic in one function they
 * cannot drift.
 *
 * **Both templates are pure.** They take `prepare()`'s output and
 * nothing else — no model calls, no requests, no `Configure::read`.
 * The one thing that looks like an exception is the map, and it is
 * not one: tiles are fetched by the reader's browser from the
 * instance's configured tile server, which is already how the event
 * view's geolocation popover works, and whether to draw a map at all
 * is decided in `prepare()` rather than in the template.
 *
 * ## What arrives in `$objects`
 *
 * The enrichment run shapes a module's answer into objects and
 * attributes, and the caller hands over **only the objects whose
 * template this renderer claims**, from every run it has for the
 * value, each tagged with where it came from:
 *
 * ```
 * name          string   the object template name
 * meta_category string|null
 * description   string|null
 * comment       string|null
 * attributes    [['relation','type','value','category','comment',
 *                 'to_ids','correlates','known'], …]
 * module        string   which module answered — added by the caller
 * ran_at        int      when it answered, unix seconds — likewise
 * ```
 *
 * `module` and `ran_at` are not part of a module's answer and are not
 * stored with one. They are added on the way in because a full
 * rendering that merges three modules' geolocation points has to be
 * able to say which point came from where, and because the newest
 * answer is the one that takes a slot.
 *
 * `$attributes` is the same run's top-level attributes, for a shape
 * whose answer is not an object. Most renderers ignore it.
 */
abstract class ValueRendererBase
{
    /**
     * The loader's handshake, in the shape of its two in-tree
     * precedents. A class that subclasses this and overrides nothing
     * else still answers it, so what it proves is that the file's
     * class was constructed rather than merely defined.
     */
    const LOADED = 'SHAPE RECOGNISED';

    /** Something in the modules build emits this template today. */
    const PRODUCER_TODAY = 'today';

    /**
     * A module holds this answer and flattens it to prose before
     * sending it. The data is already fetched and already structured
     * inside the module, so what is missing is a conversion rather
     * than a new module.
     */
    const PRODUCER_CONVERSION = 'conversion';

    /**
     * Nothing anywhere emits it. The renderer is written anyway: a
     * renderer keyed on a shape nothing emits never matches, so it
     * costs the reader nothing, and whoever writes the module emits
     * the template that already has a widget instead of landing as a
     * generic chip until somebody notices.
     */
    const PRODUCER_NONE = 'none';

    /** The shape id, unique across the instance. */
    public $id = 'to-override';

    /** One line, shown wherever a shape is offered for ranking. */
    public $description = 'to-override';

    /**
     * The MISP object template names this shape is drawn from. Unique
     * across the instance: the loader refuses a second claim on any
     * one of them.
     */
    public $templates = array();

    /**
     * Element paths for the two renderings, relative to the theme's
     * `Elements/` directory. A renderer may leave `full` null, in
     * which case the Enrichment pane draws the object table alone.
     */
    public $compact = null;

    public $full = null;

    /**
     * Whether anything produces this shape today, and if not, what is
     * missing. One of the three `PRODUCER_*` words.
     *
     * This is a fact about the modules ecosystem rather than about
     * this instance, and it is deliberately not a list of module
     * names — that would be the roster this design refuses. What it is
     * for is the editor: a profile ranking a shape nothing can emit
     * gets an empty slot, and the reader is owed the reason at
     * declaration time rather than a blank widget at read time.
     */
    public $producer = self::PRODUCER_TODAY;

    /**
     * What is missing, in a sentence, where `producer` is not
     * `today`. Rendered beside the shape in the editor.
     */
    public $producer_note = null;

    public $version = 1;

    /** Set by the loader on anything found under `app/Lib/`. */
    public $is_custom = false;

    const EVENT_SET = 'set';

    const EVENT_EACH = 'each';

    /**
     * How the event page may draw this shape. null keeps it off the
     * event page; `set` means prepare() is right over every object of the
     * event at once; `each` means prepare() is about one subject, so the
     * caller groups the event's objects by subjectsOf() first.
     */
    public $eventUse = null;

    /** An `each` group about the subject it names. */
    const SUBJECT_NAMED = 'named';

    /** An `each` group of one object that names no subject: its own. */
    const SUBJECT_OWN = 'own';

    /** An `each` group of objects that name nothing the event holds. */
    const SUBJECT_NONE = 'none';

    public function checkLoading()
    {
        return self::LOADED;
    }

    /**
     * The identity the loader hands the editor's palette.
     *
     * @return array
     */
    public function getConfig()
    {
        return array(
            'id' => $this->id,
            'description' => $this->description,
            'templates' => $this->templates,
            'compact' => $this->compact,
            'full' => $this->full,
            'producer' => $this->producer,
            'producer_note' => $this->producer_note,
            'version' => $this->version,
            'is_custom' => $this->is_custom,
            'event_use' => $this->eventUse,
        );
    }

    /**
     * The subjects an object is about, for an `each` shape. An object may
     * name several (a transaction names every address it moved value
     * between); an empty list makes the object its own subject.
     *
     * @param array $object
     * @return array
     */
    public function subjectsOf(array $object)
    {
        return array();
    }

    /**
     * An `each` shape's objects split into the groups prepare() is called
     * on, in first-seen order. A group whose objects name no subject is
     * one object, with a null subject.
     *
     * @param array $objects Tagged objects claiming this shape
     * @return array [['subject' => string|null, 'kind' => SUBJECT_*,
     *         'objects' => [...]], …]
     */
    public function groupsOf(array $objects)
    {
        $groups = array();
        foreach ($objects as $index => $object) {
            $subjects = array_unique(array_filter(
                $this->subjectsOf($object),
                function ($one) {
                    return $one !== null && $one !== '';
                }
            ));
            if (empty($subjects)) {
                $groups["\0" . $index] = array(
                    'subject' => null,
                    'kind' => self::SUBJECT_OWN,
                    'objects' => array($object),
                );
                continue;
            }
            foreach ($subjects as $subject) {
                $subject = (string)$subject;
                if (!isset($groups[$subject])) {
                    $groups[$subject] = array(
                        'subject' => $subject,
                        'kind' => self::SUBJECT_NAMED,
                        'objects' => array(),
                    );
                }
                $groups[$subject]['objects'][] = $object;
            }
        }
        return array_values($groups);
    }

    /**
     * `each` only: what the event page calls one subject and several
     * ("host", "hosts"), and how a group naming none reads: on its tile,
     * as its title, and after a count of such groups.
     *
     * @return array one, many, none, none_title, none_group
     */
    public function subjectWords()
    {
        return array(
            'one' => __('subject'),
            'many' => __('subjects'),
            'none' => __('Nothing named'),
            'none_title' => __('Objects naming nothing'),
            'none_group' => __('naming nothing'),
        );
    }

    /**
     * Whether this answer carries the fields the shape needs.
     *
     * Called with objects already filtered to this renderer's
     * templates, so the question is never *is this mine* — it is
     * *can I draw it*. Returning false leaves the answer as a chip.
     *
     * @param array $objects Tagged objects claiming this shape
     * @param array $attributes The run's top-level attributes
     * @return bool
     */
    abstract public function matches(array $objects, array $attributes);

    /**
     * Everything the two templates need, computed once.
     *
     * Only called where `matches()` said yes.
     *
     * @param array $objects Tagged objects claiming this shape
     * @param array $attributes The run's top-level attributes
     * @return array The view's data
     */
    abstract public function prepare(array $objects, array $attributes);

    /**
     * The first value of a relation on one object, or null.
     *
     * @param array $object
     * @param string $relation
     * @return string|null
     */
    protected function value(array $object, $relation)
    {
        foreach ($this->attributesOf($object) as $attribute) {
            if (($attribute['relation'] ?? null) === $relation
                && isset($attribute['value'])
                && $attribute['value'] !== ''
            ) {
                return (string)$attribute['value'];
            }
        }
        return null;
    }

    /**
     * Every value of a relation on one object, in the order the module
     * sent them.
     *
     * A relation repeats legitimately — an `asn` object carries one
     * `subnet-announced` per prefix — so taking the first would drop
     * most of the answer.
     *
     * @param array $object
     * @param string $relation
     * @return array
     */
    protected function values(array $object, $relation)
    {
        $out = array();
        foreach ($this->attributesOf($object) as $attribute) {
            if (($attribute['relation'] ?? null) === $relation
                && isset($attribute['value'])
                && $attribute['value'] !== ''
            ) {
                $out[] = (string)$attribute['value'];
            }
        }
        return $out;
    }

    /**
     * The first value found for any of several relations.
     *
     * Templates disagree about what to call the same field — a country
     * is `country`, `country-code` or `countrycode` depending on who
     * wrote the template — and a renderer claiming a set of them needs
     * to ask for all the spellings at once.
     *
     * @param array $object
     * @param array $relations In preference order
     * @return string|null
     */
    protected function firstValue(array $object, array $relations)
    {
        foreach ($relations as $relation) {
            $value = $this->value($object, $relation);
            if ($value !== null) {
                return $value;
            }
        }
        return null;
    }

    /**
     * The objects that carry at least one of these relations.
     *
     * The usual test in a `matches()`: an object of the right template
     * that does not carry the field the widget is about cannot be
     * drawn, and a template's relations are all optional.
     *
     * @param array $objects
     * @param array $relations
     * @return array
     */
    protected function carrying(array $objects, array $relations)
    {
        $out = array();
        foreach ($objects as $object) {
            if ($this->firstValue($object, $relations) !== null) {
                $out[] = $object;
            }
        }
        return $out;
    }

    /**
     * The newest object of the set, by the run it came from.
     *
     * Where three modules answered the same question, the answer a
     * reader sees is the most recent one — so a re-run visibly wins
     * rather than being averaged into what it replaced.
     *
     * @param array $objects
     * @return array|null
     */
    protected function newest(array $objects)
    {
        $best = null;
        foreach ($objects as $object) {
            if ($best === null
                || ($object['ran_at'] ?? 0) > ($best['ran_at'] ?? 0)
            ) {
                $best = $object;
            }
        }
        return $best;
    }

    /**
     * Which modules answered, in the order they are drawn, each once.
     *
     * @param array $objects
     * @return array
     */
    protected function sources(array $objects)
    {
        $out = array();
        foreach ($objects as $object) {
            $module = $object['module'] ?? null;
            if ($module !== null && !in_array($module, $out, true)) {
                $out[] = $module;
            }
        }
        return $out;
    }

    /**
     * A date a module sent, as a unix stamp, or null.
     *
     * Modules send dates in whatever their upstream used — ISO 8601,
     * `Y-m-d`, a bare epoch — and a widget that reads one format
     * silently draws an empty axis for the others.
     *
     * @param mixed $value
     * @return int|null
     */
    protected function stamp($value)
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_int($value) || ctype_digit((string)$value)) {
            $stamp = (int)$value;
            /*
             * A four-digit number is a year and not an epoch three
             * weeks into 1970, and a certificate's validity window is
             * exactly where a bare year turns up.
             */
            return $stamp > 100000 ? $stamp : null;
        }
        $stamp = strtotime((string)$value);
        return $stamp === false ? null : $stamp;
    }

    /**
     * A number a module sent, or null where it sent something else.
     *
     * @param mixed $value
     * @return float|null
     */
    protected function number($value)
    {
        return is_numeric($value) ? (float)$value : null;
    }

    /**
     * A boolean a module sent, whatever it sent it as.
     *
     * Modules send `true`, `"true"`, `1` and `"True"` for the same
     * fact, and `"false"` is a non-empty string — so the naive test
     * reads every explicit denial as an assertion.
     *
     * @param array $object
     * @param string $relation
     * @return bool
     */
    protected function flag(array $object, $relation)
    {
        $value = $this->value($object, $relation);
        if ($value === null) {
            return false;
        }
        $value = strtolower(trim($value));
        return in_array($value, array('1', 'true', 'yes'), true);
    }

    /**
     * @param array $object
     * @return array
     */
    private function attributesOf(array $object)
    {
        return isset($object['attributes'])
            && is_array($object['attributes'])
            ? $object['attributes']
            : array();
    }
}
