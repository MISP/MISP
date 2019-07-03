<?php
class ColourGradientTool
{

    // source: https://graphicdesign.stackexchange.com/a/83867
    // $values of the form array(item1: val1, item2: val2, ...)
    public function createGradientFromValues($items)
    {
        $starColor = '#0000FF';
        $endColor = '#FF0000';

        if (count($items) == 0) {
            return array();
        }

        $vals = array_values($items);
        $maxDec = max($vals);
        $minDec = min($vals);

        $interpolation = $this->interpolateColors($starColor, $endColor, $maxDec+1, true);
        $coloursMapping = array();
        foreach ($items as $name => $val) {
           $color = $interpolation[$val];
           $coloursMapping[$name] = '#' . str_pad(dechex($color[0]), 2, '0', STR_PAD_LEFT) . str_pad(dechex($color[1]), 2, '0', STR_PAD_LEFT) . str_pad(dechex($color[2]), 2, '0', STR_PAD_LEFT);
       }
       return array('mapping' => $coloursMapping, 'interpolation' => $interpolation);
    }

    private function hue2rgb($p, $q, $t) {
        if ($t < 0) $t += 1;
        if ($t > 1) $t -= 1;
        if ($t < 1/6) return $p + ($q - $p) * 6 * $t;
        if ($t < 1/2) return $q;
        if ($t < 2/3) return $p + ($q - $p) * (2/3 - $t) * 6;
        return $p;
    }

    private function hsl2rgb($color) {
        $l = $color[2];
        if ($color[1] == 0) {
            $l = round($l*255);
            return array($l, $l, $l);
        } else {
            $s = $color[1];
            $q = ($l < 0.5 ? $l * (1 + $s) : $l + $s - $l * $s);
            $p = 2 * $l - $q;
            $r = $this->hue2rgb($p, $q, $color[0] + 1/3);
            $g = $this->hue2rgb($p, $q, $color[0]);
            $b = $this->hue2rgb($p, $q, $color[0] - 1/3);
            return array(round($r*255), round($g*255), round($b*255));
        }
    }

    private function rgb2hsl($color) {
        $r = $color[0]/255;
        $g = $color[1]/255;
        $b = $color[2]/255;
        $arrRGB = array($r, $g, $b);

        $max = max($arrRGB);
        $min = min($arrRGB);
        $h = ($max - $min) / 2;
        $s = $h;
        $l = $h;

        if ($max == $min) {
            $s = 0; // achromatic
            $h = 0;
        } else {
            $d = $max - $min;
            $s = ($l > 0.5 ? $d / (2 - $max - $min) : $d / ($max + $min) );
            if ($max == $r) {
                $h = ($g - $b) / $d + ($g < $b ? 6 : 0);
            } elseif ($max == $g) {
                $h = ($b - $r) / $d + 2;
            } elseif ($max == $b) {
                $h = ($r - $g) / $d + 4;
            }
            $h = $h / 6;
            return array($h, $s, $l);
        }
    }

    private function interpolateColor($color1, $color2, $factor, $useHSL=false) {
        if ($useHSL) {
            $hsl1 = $this->rgb2hsl($color1);
            $hsl2 = $this->rgb2hsl($color2);
            for ($i=0; $i<3; $i++) {
              $hsl1[$i] += $factor*($hsl2[$i] - $hsl1[$i]);
            }
            $result = $this->hsl2rgb($hsl1);
        } else {
            $result = $color1;
            for ($i = 0; $i < 3; $i++) {
                $result[$i] = round($result[$i] + $factor * ($color2[$i] - $color1[$i]));
            }
        }
        return $result;
    }

    public function interpolateColors($hexColor1, $hexColor2, $steps, $useHSL=false) {
        $stepFactor = 1 / ($steps - 1);
        $interpolatedColorArray = array();
        $color1 = sscanf($hexColor1, "#%02x%02x%02x");
        $color2 = sscanf($hexColor2, "#%02x%02x%02x");

        for($i = 0; $i < $steps; $i++) {
            $interpolatedColorArray[$i] = $this->interpolateColor($color1, $color2, $stepFactor * $i, $useHSL);
        }

        return $interpolatedColorArray;
    }
}
