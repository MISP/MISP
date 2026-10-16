<?php

/**
 * Which of an event's elements the Pivot Explorer opens on: everything an
 * object reference or analyst relationship touches, and the elements a feed
 * or server has seen when all of them fit the budget. When the links alone
 * do not fit, the canvas opens on nothing and says what was left out.
 *
 * An object is drawn with its children, so it costs one node plus one per
 * live attribute it holds.
 */
class PivotSeed
{
    // Pivotick's detail threshold: past it the minimap reads as a density map.
    const NODE_BUDGET = 1500;

    // Finding feed and server hits reads every attribute of the event. Up to
    // this many, that costs about what drawing a full canvas does.
    const FEED_SCAN_LIMIT = 20000;

    /** @var int */
    private $budget;

    /** @var array free attribute id => true */
    private $attributes = [];

    /** @var array object id => true */
    private $objects = [];

    /** @var array node key => true, for nodes outside this event's elements */
    private $farEnds = [];

    /** @var array object id => live children */
    private $children = [];

    /** @var array free attribute id => true */
    private $hitAttributes = [];

    /** @var array object id => true */
    private $hitObjects = [];

    /** @var array relationship type => links of that type */
    private $types = [];

    /** @var int */
    private $references = 0;

    /** @var int */
    private $relationships = 0;

    public function __construct($budget = self::NODE_BUDGET)
    {
        $this->budget = (int)$budget;
    }

    /**
     * @param int|string $attributeCount Event.attribute_count
     * @return bool
     */
    public static function scansFeedHits($attributeCount)
    {
        return (int)$attributeCount <= self::FEED_SCAN_LIMIT;
    }

    /**
     * An attribute a link touches; one inside an object brings the object.
     *
     * @param int|string $attributeId
     * @param int|string $objectId 0 when the attribute is in no object
     */
    public function linkAttribute($attributeId, $objectId = 0)
    {
        if ((int)$objectId) {
            $this->linkObject($objectId);
        } else {
            $this->attributes[(int)$attributeId] = true;
            unset($this->hitAttributes[(int)$attributeId]);
        }
    }

    /**
     * @param int|string $objectId
     */
    public function linkObject($objectId)
    {
        $this->objects[(int)$objectId] = true;
        unset($this->hitObjects[(int)$objectId]);
    }

    /**
     * A node a link brings that is none of this event's attributes or objects:
     * the event itself, another event, its element, a galaxy cluster.
     *
     * @param string $key identifies the node, so two links to it count once
     */
    public function linkFarEnd($key)
    {
        $this->farEnds[(string)$key] = true;
    }

    /**
     * A drawable object reference, for the summary of what the links hold.
     *
     * @param string|null $type
     */
    public function countReference($type)
    {
        $this->references++;
        $this->countType($type);
    }

    /**
     * A drawable analyst relationship, as countReference().
     *
     * @param string|null $type
     */
    public function countRelationship($type)
    {
        $this->relationships++;
        $this->countType($type);
    }

    /**
     * Whether everything the links touch fits the budget. An object whose
     * children are not counted yet costs one node, so a false here is final
     * before any count is read.
     *
     * @return bool
     */
    public function linksFit()
    {
        return $this->linkedCost() <= $this->budget;
    }

    /**
     * What the links hold, for a canvas that does not open on them.
     *
     * @param int $top how many relationship types to name
     * @return array objects, attributes (outside objects), references,
     *               relationships, nodes (a floor while children are
     *               uncounted), types [[type, count]]
     */
    public function linkedSummary($top = 3)
    {
        $types = $this->types;
        uksort($types, function ($a, $b) use ($types) {
            return $types[$b] <=> $types[$a] ?: strcmp($a, $b);
        });
        $out = [];
        foreach (array_slice($types, 0, $top, true) as $type => $n) {
            $out[] = [(string)$type, $n];
        }
        return [
            'objects' => count($this->objects),
            'attributes' => count($this->attributes),
            'references' => $this->references,
            'relationships' => $this->relationships,
            'nodes' => $this->linkedCost(),
            'types' => $out,
        ];
    }

    private function countType($type)
    {
        $type = (string)($type ?? '') === '' ? 'related-to' : (string)$type;
        $this->types[$type] = ($this->types[$type] ?? 0) + 1;
    }

    /**
     * @param array $counts object id => live children
     */
    public function addChildCounts(array $counts)
    {
        foreach ($counts as $objectId => $n) {
            $this->children[(int)$objectId] = (int)$n;
        }
    }

    /**
     * @return array object ids already drawn
     */
    public function linkedObjectIds()
    {
        return array_keys($this->objects);
    }

    /**
     * @return array free attribute ids already drawn
     */
    public function linkedAttributeIds()
    {
        return array_keys($this->attributes);
    }

    /**
     * An attribute a feed or server has seen. Already drawn, it changes nothing.
     *
     * @param int|string $attributeId
     * @param int|string $objectId
     */
    public function hit($attributeId, $objectId = 0)
    {
        $objectId = (int)$objectId;
        if ($objectId) {
            if (!isset($this->objects[$objectId])) {
                $this->hitObjects[$objectId] = true;
            }
        } elseif (!isset($this->attributes[(int)$attributeId])) {
            $this->hitAttributes[(int)$attributeId] = true;
        }
    }

    /**
     * @return array objects whose cost is not known yet
     */
    public function uncountedObjectIds()
    {
        $out = [];
        foreach ($this->objects + $this->hitObjects as $objectId => $_) {
            if (!isset($this->children[$objectId])) {
                $out[] = $objectId;
            }
        }
        return $out;
    }

    /**
     * @return int
     */
    public function linkedCost()
    {
        return count($this->attributes) + count($this->farEnds) + $this->objectCost($this->objects);
    }

    /**
     * @return int
     */
    public function hitCost()
    {
        return count($this->hitAttributes) + $this->objectCost($this->hitObjects);
    }

    /**
     * @return bool
     */
    public function hasHits()
    {
        return !empty($this->hitAttributes) || !empty($this->hitObjects);
    }

    /**
     * Whether the hits fit beside what the links already draw.
     *
     * @return bool
     */
    public function hitsFit()
    {
        return $this->linkedCost() + $this->hitCost() <= $this->budget;
    }

    /**
     * @return array 'attributes' and 'objects': the ids to draw
     */
    public function elements()
    {
        $attributes = $this->attributes;
        $objects = $this->objects;
        if ($this->hitsFit()) {
            $attributes += $this->hitAttributes;
            $objects += $this->hitObjects;
        }
        return ['attributes' => array_keys($attributes), 'objects' => array_keys($objects)];
    }

    private function objectCost(array $objects)
    {
        $cost = 0;
        foreach ($objects as $objectId => $_) {
            $cost += 1 + ($this->children[$objectId] ?? 0);
        }
        return $cost;
    }
}
