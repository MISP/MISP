<?php
/**
 * The figures of the sightings modal (Overmind Sightings/ajax/advanced): the
 * counts by type, who sighted and when, and the timeline's bins.
 *
 * Both take Sighting::listSightings() rows, which have already been through
 * the sightings policy and the anonymisation.
 */
class SightingDigestTool
{
    /** The sighting types, in the order of their `type` value. */
    const TYPES = [0 => 'sighting', 1 => 'false-positive', 2 => 'expiration'];

    /** Bin widths in seconds, the narrowest that keeps the bins under the cap wins. */
    const BIN_SIZES = [60, 300, 900, 3600, 21600, 86400, 604800, 2592000, 31536000];

    /** A timeline shorter than this is padded with empty bins after its last one. */
    const MIN_BINS = 12;

    /**
     * @param array $sightings Sighting::listSightings() rows
     * @param int $orgId the reader's organisation
     * @return array total, counts (by type value), first, last (timestamps or
     *  null), orgs (distinct organisations), mine (the reader's organisation's)
     */
    public static function summary(array $sightings, $orgId)
    {
        $counts = array_fill_keys(array_keys(self::TYPES), 0);
        $first = null;
        $last = null;
        $orgs = [];
        $mine = 0;
        foreach ($sightings as $sighting) {
            $row = $sighting['Sighting'];
            $type = (int)$row['type'];
            if (isset($counts[$type])) {
                $counts[$type]++;
            }
            $date = (int)$row['date_sighting'];
            $first = $first === null ? $date : min($first, $date);
            $last = $last === null ? $date : max($last, $date);
            $orgs[(int)$row['org_id']] = true;
            if ((int)$row['org_id'] === (int)$orgId) {
                $mine++;
            }
        }
        return [
            'total' => count($sightings),
            'counts' => $counts,
            'first' => $first,
            'last' => $last,
            'orgs' => count($orgs),
            'mine' => $mine,
        ];
    }

    /**
     * @param array $sightings Sighting::listSightings() rows
     * @param int $maxBins
     * @return array|null start, size (seconds), bins (each the counts by type
     *  value) and max (the busiest bin's total); null without sightings
     */
    public static function timeline(array $sightings, $maxBins = 40)
    {
        if (empty($sightings)) {
            return null;
        }
        $dates = array_map(function ($sighting) {
            return (int)$sighting['Sighting']['date_sighting'];
        }, $sightings);
        $first = min($dates);
        $last = max($dates);
        foreach (self::BIN_SIZES as $size) {
            $start = intdiv($first, $size) * $size;
            $count = intdiv($last - $start, $size) + 1;
            if ($count <= $maxBins) {
                break;
            }
        }
        $count = min($maxBins, max($count, self::MIN_BINS));
        $empty = array_fill_keys(array_keys(self::TYPES), 0);
        $bins = array_fill(0, $count, $empty);
        foreach ($sightings as $sighting) {
            $type = (int)$sighting['Sighting']['type'];
            $index = min($count - 1, intdiv((int)$sighting['Sighting']['date_sighting'] - $start, $size));
            if (isset($bins[$index][$type])) {
                $bins[$index][$type]++;
            }
        }
        return [
            'start' => $start,
            'size' => $size,
            'bins' => $bins,
            'max' => max(array_map('array_sum', $bins)),
        ];
    }
}
