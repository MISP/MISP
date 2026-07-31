<?php

/**
 * Canonical, deterministic colour scheme for MISP galaxies (Overmind theme).
 *
 * A galaxy's colour is derived purely from its *name*, so the same galaxy
 * renders with the same colour family in every context.
 *
 */
class GalaxyColour
{
    /**
     * Deterministic hue (0-359) from a galaxy name. 32-bit rolling hash
     *
     * @param string $name
     * @return int
     */
    public static function hue($name)
    {
        $name = (string)$name;
        $hash = 0;
        $len  = strlen($name);
        for ($i = 0; $i < $len; $i++) {
            $hash = (($hash << 5) - $hash + ord($name[$i])) & 0x7FFFFFFF;
        }
        return $hash % 360;
    }

    /**
     * Full named palette for a galaxy name. Every galaxy view pulls the exact
     * CSS strings it needs from here, so colour *and* shade stay identical
     * across contexts. Keys:
     *   hue            int    raw hue (handy for one-off hsl() tweaks)
     *   badgeBg        pill background (tinted, honours --galaxy-alpha)
     *   badgeText      pill text colour
     *   badgeBorder    pill border colour
     *   headerText     strong title / header text & icon colour
     *   subText        lighter secondary text (e.g. cluster values under a name)
     *   sectionBg      very light section-wrapper background
     *   sectionBorder  section-wrapper border colour
     *   tintBg         light icon-frame background (coloured glyph on top)
     *   tintIcon       icon colour for a tint frame
     *   solidBg        full-colour icon-frame background
     *   solidText      readable colour on solidBg ('black'|'white')
     *
     * @param string $name
     * @return array
     */
    public static function palette($name)
    {
        return self::paletteFromHue(self::hue($name));
    }

    /**
     * Same palette, but for a caller that picks the hue itself.
     *
     * Hashing a name gives no guarantee that a small, fixed set of values lands
     * on distinguishable hues — with a dozen inputs they can all cluster in one
     * band. Callers in that situation spread their own hues and come in here, 
     * so every hsl() string still lives in a single place.
     *
     * @param int $hue 0-359
     * @return array see palette()
     */
    public static function paletteFromHue($hue)
    {
        $hue = ((int)$hue % 360 + 360) % 360;
        return array(
            'hue'           => $hue,
            'badgeBg'       => "hsla($hue,65%,55%,var(--galaxy-alpha,0.12))",
            'badgeText'     => "hsl($hue,65%,28%)",
            'badgeBorder'   => "hsl($hue,55%,65%)",
            'headerText'    => "hsl($hue,65%,26%)",
            'subText'       => "hsl($hue,45%,38%)",
            'sectionBg'     => "hsla($hue,55%,55%,0.08)",
            'sectionBorder' => "hsl($hue,55%,70%)",
            'tintBg'        => "hsla($hue,65%,55%,0.14)",
            'tintIcon'      => "hsl($hue,60%,34%)",
            'solidBg'       => "hsl($hue,58%,46%)",
            'solidText'     => self::solidText($hue, 58, 46),
        );
    }

    /**
     * Metallic sheen overlay shared by every galaxy pill/badge.
     *
     * @return string
     */
    public static function metallic()
    {
        return 'linear-gradient(145deg,rgba(255,255,255,0.15) 0%,'
             . 'rgba(255,255,255,0.04) 40%,rgba(0,0,0,0.04) 100%)';
    }

    /**
     * Ready-to-use inline style for a galaxy/cluster pill/badge.
     *
     * @param string $name
     * @return string
     */
    public static function badgeStyle($name)
    {
        $p = self::palette($name);
        return "background-color:{$p['badgeBg']};color:{$p['badgeText']};"
             . "border:1px solid {$p['badgeBorder']};"
             . 'background-image:' . self::metallic() . ';'
             . 'white-space:normal;word-wrap:break-word;text-align:left;';
    }

    /**
     * 'black'|'white' for readable text on a solid hsl($h,$s%,$l%) background
     *
     * @param int $h
     * @param int $s
     * @param int $l
     * @return string
     */
    public static function solidText($h, $s, $l)
    {
        list($r, $g, $b) = self::hslToRgb($h, $s, $l);
        $average = ((2 * $r) + $b + (3 * $g)) / 6;
        return $average < 127 ? 'white' : 'black';
    }

    /**
     * HSL (h 0-359, s/l in %) -> [r, g, b] each 0-255.
     *
     * @param float $h
     * @param float $s
     * @param float $l
     * @return array{0:int,1:int,2:int}
     */
    private static function hslToRgb($h, $s, $l)
    {
        $h /= 360;
        $s /= 100;
        $l /= 100;
        if ($s == 0) {
            $r = $g = $b = $l;
        } else {
            $q = $l < 0.5 ? $l * (1 + $s) : $l + $s - $l * $s;
            $p = 2 * $l - $q;
            $r = self::hue2rgb($p, $q, $h + 1 / 3);
            $g = self::hue2rgb($p, $q, $h);
            $b = self::hue2rgb($p, $q, $h - 1 / 3);
        }
        return array(
            (int)round($r * 255),
            (int)round($g * 255),
            (int)round($b * 255),
        );
    }

    private static function hue2rgb($p, $q, $t)
    {
        if ($t < 0) {
            $t += 1;
        }
        if ($t > 1) {
            $t -= 1;
        }
        if ($t < 1 / 6) {
            return $p + ($q - $p) * 6 * $t;
        }
        if ($t < 1 / 2) {
            return $q;
        }
        if ($t < 2 / 3) {
            return $p + ($q - $p) * (2 / 3 - $t) * 6;
        }
        return $p;
    }
}
