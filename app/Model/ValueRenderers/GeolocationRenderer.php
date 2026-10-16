<?php

/**
 * Where an address is, drawn as a place rather than as two numbers.
 *
 * `geolocation` and `ip-api-address` answer the same question with
 * different spellings — a country is `countrycode` on one and
 * `country-code` on the other — so both are claimed here and every
 * read asks for the spellings in turn.
 *
 * **The map costs nothing to draw, so it is always drawn.** The
 * outline both templates plot on ships as markup — the same Natural
 * Earth geometry the dashboard's map widgets use, baked to an SVG
 * path by `app/files/scripts/build_world_outline.py`. Nothing here is
 * behind `Plugin.Geolocation_enabled`: that setting gates fetching
 * tiles from a server outside the instance, which is a question about
 * a network round trip rather than about whether a reader may see
 * where an address is. A place name with no map beside it was the
 * older answer to that question and it is not needed now.
 */
class GeolocationRenderer extends ValueRendererBase
{
    public $id = 'geolocation';

    public $templates = array('geolocation', 'ip-api-address', 'gpx',
        'geojson', 'uav');

    public $compact = 'Values/Renderers/geolocation_compact';

    public $full = 'Values/Renderers/geolocation_full';

    public $eventUse = self::EVENT_SET;

    /** The two spellings of each field, in preference order. */
    const COUNTRY = array('country', 'countrycode', 'country-code');

    const CODE = array('countrycode', 'country-code');

    const CITY = array('city', 'neighborhood');

    const REGION = array('region', 'state', 'region-code');

    /**
     * Objects describing an area or a path, drawn by their bounding box. A
     * uav carries no box: its path is in its flight-path files.
     */
    const EXTENT = array('gpx', 'geojson', 'uav');

    /** An extent's name and times, across the three templates' relations. */
    const EXTENT_NAME = array('name', 'filename', 'craftname',
        'registration-id', 'model');

    const EXTENT_START = array('start-time', 'first-seen');

    const EXTENT_END = array('end-time', 'last-seen');

    public function __construct()
    {
        $this->description = __('Where an address is, on a map or as a'
            . ' place name.');
    }

    /**
     * A geolocation object carrying neither a place name nor a
     * coordinate pair is a row about a lookup rather than about a
     * location, and there is nothing to draw.
     */
    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->isExtent($object)
                || $this->placeOf($object) !== null
                || $this->pointOf($object) !== null
            ) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $points = array();
        $places = array();
        $extents = array();
        $located = array();
        foreach ($objects as $object) {
            if ($this->isExtent($object)) {
                $extents[] = $this->extentOf($object);
                continue;
            }
            $located[] = $object;
            $place = $this->placeOf($object);
            $point = $this->pointOf($object);
            if ($place === null && $point === null) {
                continue;
            }
            $entry = array(
                'country' => $this->firstValue($object, self::COUNTRY),
                'code' => $this->firstValue($object, self::CODE),
                'city' => $this->firstValue($object, self::CITY),
                'region' => $this->firstValue($object, self::REGION),
                'module' => $object['module'] ?? null,
                'ran_at' => $object['ran_at'] ?? null,
            );
            if ($point !== null) {
                $entry['lat'] = $point[0];
                $entry['lon'] = $point[1];
                $entry['radius'] = $this->radiusOf($object);
                $entry['reach'] = $this->reachOf($point, $entry['radius']);
                $points[] = $entry;
            }
            /*
             * Deduplicated on the place and not on the object.
             * `mmdb_lookup` answers with one object per database it
             * consulted, so three objects saying *Mountain View, US*
             * are one place three sources agree on — and a count of
             * three would be a claim about the world rather than
             * about how many databases were read.
             */
            if ($place !== null && !isset($places[$place])) {
                $places[$place] = $entry;
            }
        }
        $newest = $this->newest($located);
        return array(
            'points' => $points,
            'places' => array_values($places),
            'extents' => $extents,
            'place' => $newest === null ? null : array(
                'country' => $this->firstValue($newest, self::COUNTRY),
                'code' => $this->firstValue($newest, self::CODE),
                'city' => $this->firstValue($newest, self::CITY),
                'region' => $this->firstValue($newest, self::REGION),
            ),
            'sources' => $this->sources($objects),
            'agreed' => count($places) < 2,
        );
    }

    /**
     * @param array $object
     * @return bool
     */
    private function isExtent(array $object)
    {
        return in_array($object['name'] ?? null, self::EXTENT, true);
    }

    /**
     * A gpx, geojson or uav object as its bounding box. The box is optional
     * in the first two and absent from uav, so `box` is null where any edge
     * is missing.
     *
     * @param array $object
     * @return array
     */
    private function extentOf(array $object)
    {
        $edges = array();
        foreach (array('min-latitude', 'min-longitude', 'max-latitude',
            'max-longitude') as $relation
        ) {
            $edges[] = $this->number($this->value($object, $relation));
        }
        list($minLat, $minLon, $maxLat, $maxLon) = $edges;
        $box = null;
        if (!in_array(null, $edges, true)
            && $minLat >= -90 && $maxLat <= 90 && $minLat <= $maxLat
            && $minLon >= -180 && $maxLon <= 180 && $minLon <= $maxLon
        ) {
            $box = $edges;
        }
        return array(
            'template' => $object['name'],
            'name' => $this->firstValue($object, self::EXTENT_NAME),
            'box' => $box,
            'start' => $this->stamp(
                $this->firstValue($object, self::EXTENT_START)
            ),
            'end' => $this->stamp(
                $this->firstValue($object, self::EXTENT_END)
            ),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }

    /**
     * The place this object names, as a key — country and city
     * together, because a country alone from one source and a city
     * from another are not the same answer.
     *
     * @param array $object
     * @return string|null
     */
    private function placeOf(array $object)
    {
        $parts = array(
            $this->firstValue($object, self::COUNTRY),
            $this->firstValue($object, self::CITY),
        );
        $parts = array_filter($parts, function ($one) {
            return $one !== null && $one !== '';
        });
        return empty($parts) ? null : implode(' / ', $parts);
    }

    /**
     * @param array $object
     * @return array|null `[lat, lon]`
     */
    private function pointOf(array $object)
    {
        $lat = $this->number($this->value($object, 'latitude'));
        $lon = $this->number($this->value($object, 'longitude'));
        if ($lat === null || $lon === null) {
            return null;
        }
        /*
         * A module that could not resolve an address sometimes says so
         * with a zero pair rather than by omitting the relation, and
         * null island is a place no address is in.
         */
        if ($lat === 0.0 && $lon === 0.0) {
            return null;
        }
        if ($lat < -90 || $lat > 90 || $lon < -180 || $lon > 180) {
            return null;
        }
        return array($lat, $lon);
    }

    /**
     * How far from its coordinates the place may be, in kilometres. A
     * country-level answer is placed at the country's centre and says so
     * here, often as 1000.
     *
     * @param array $object
     * @return float|null
     */
    private function radiusOf(array $object)
    {
        $radius = $this->number($this->value($object, 'accuracy-radius'));
        return $radius !== null && $radius > 0 ? $radius : null;
    }

    /**
     * The radius in degrees, `[longitude, latitude]`, which is what the
     * world outline's units are. A degree of longitude shrinks towards
     * the poles, so the same distance spans more of them there.
     *
     * @param array $point `[lat, lon]`
     * @param float|null $radius Kilometres
     * @return array|null
     */
    private function reachOf(array $point, $radius)
    {
        if ($radius === null) {
            return null;
        }
        $lat = min(90, $radius / 111.32);
        $lon = min(180, $lat / max(0.1, cos(deg2rad($point[0]))));
        return array(round($lon, 3), round($lat, 3));
    }
}
