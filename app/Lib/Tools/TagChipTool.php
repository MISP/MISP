<?php
/**
 * Pure functions behind the tag chip: parsing a tag name into its parts,
 * deriving a hue from a namespace and judging whether a taxonomy's declared
 * palette carries meaning. app/webroot/js/tag-chips.js mirrors parse() and
 * hue() so a tag lands on the same colour whichever side draws it.
 */
class TagChipTool
{
    /**
     * namespace : predicate [: predicate ...] [= "value"]
     *
     * @param string $raw
     * @return array{raw: string, namespace: ?string, path: string[], above: string[], value: ?string, leaf: string}
     */
    public static function parse($raw)
    {
        $raw = trim((string)$raw);
        $value = null;
        $head = $raw;
        $eq = strpos($raw, '=');
        if ($eq !== false) {
            $head = substr($raw, 0, $eq);
            $value = trim(substr($raw, $eq + 1), '"');
        }
        $segs = explode(':', $head);
        $namespace = count($segs) > 1 ? array_shift($segs) : null;
        if ($namespace === '') {
            $namespace = null;
            $segs = [$head];
        }
        $path = $namespace === null ? [] : $segs;
        if ($value !== null) {
            $leaf = $value;
        } elseif (!empty($path)) {
            $leaf = $path[count($path) - 1];
        } else {
            $leaf = $head;
        }
        if ($leaf === '') {
            $leaf = $raw;
        }
        return [
            'raw' => $raw,
            'namespace' => $namespace,
            'path' => $path,
            // The predicates above the leaf: what a group member prints
            'above' => $value !== null ? $path : array_slice($path, 0, -1),
            'value' => $value,
            'leaf' => $leaf,
        ];
    }

    /**
     * Stable string -> hue, FNV-1a 32-bit. Byte-wise, as is the JS mirror,
     * so non-ASCII namespaces agree too.
     *
     * @param string $str
     * @return int 0..359
     */
    public static function hue($str)
    {
        $str = strtolower((string)$str);
        $h = 2166136261;
        $len = strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $h ^= ord($str[$i]);
            $h = ($h * 16777619) & 0xFFFFFFFF;
        }
        return $h % 360;
    }

    /**
     * @param string $hex #rgb or #rrggbb
     * @return array{h: int, s: int}
     */
    public static function hueSat($hex)
    {
        $c = ltrim((string)$hex, '#');
        if (strlen($c) === 3) {
            $c = $c[0] . $c[0] . $c[1] . $c[1] . $c[2] . $c[2];
        }
        if (!preg_match('/^[0-9a-fA-F]{6}$/', $c)) {
            // Also what keeps an unchecked colour out of a style attribute
            return ['h' => 0, 's' => 0];
        }
        $r = hexdec(substr($c, 0, 2)) / 255;
        $g = hexdec(substr($c, 2, 2)) / 255;
        $b = hexdec(substr($c, 4, 2)) / 255;
        $max = max($r, $g, $b);
        $min = min($r, $g, $b);
        $d = $max - $min;
        if ($d == 0) {
            return ['h' => 0, 's' => 0];
        }
        $l = ($max + $min) / 2;
        $s = $d / (1 - abs(2 * $l - 1));
        if ($max === $r) {
            $h = fmod(($g - $b) / $d, 6);
        } elseif ($max === $g) {
            $h = ($b - $r) / $d + 2;
        } else {
            $h = ($r - $g) / $d + 4;
        }
        $h = (int)round($h * 60);
        return ['h' => ($h % 360 + 360) % 360, 's' => (int)round($s * 100)];
    }

    /**
     * Does a palette mean anything? A hand-picked one spreads around the hue
     * circle (TLP: amber, red, green); a generated one is a lightness ramp on
     * one hue. More than 60% of the saturated weight inside one 50 degree
     * window is decoration.
     *
     * @param array $palette [[hex, count], ...]
     * @return bool
     */
    public static function isSemantic(array $palette)
    {
        $points = [];
        $total = 0;
        foreach ($palette as $row) {
            $c = self::hueSat($row[0]);
            if ($c['s'] >= 15) {
                $points[] = ['h' => $c['h'], 'w' => (int)$row[1]];
                $total += (int)$row[1];
            }
        }
        if (count($points) < 2 || $total === 0) {
            return false;
        }
        $best = 0;
        foreach ($points as $a) {
            $w = 0;
            foreach ($points as $b) {
                $d = abs($a['h'] - $b['h']) % 360;
                if (min($d, 360 - $d) <= 25) {
                    $w += $b['w'];
                }
            }
            $best = max($best, $w);
        }
        return $best / $total < 0.6;
    }
}
