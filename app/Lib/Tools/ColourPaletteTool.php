<?php
class ColourPaletteTool
{

    // pass the number of distinct colours to receive an array of colours
    public function createColourPalette($count)
    {
        $interval = 1 / $count;
        $colours = array();
        for ($i = 0; $i < $count; $i++) {
            $colours[] = $this->HSVtoRGB(array($interval * $i, 1, 1));
        }
        return $colours;
    }

    public function HSVtoRGB(array $hsv)
    {
        list($H, $S, $V) = $hsv;
        //1
        $H *= 6;
        //2
        $I = floor($H);
        $F = $H - $I;
        //3
        $M = $V * (1 - $S);
        $N = $V * (1 - $S * $F);
        $K = $V * (1 - $S * (1 - $F));
        //4
        switch ($I) {
            case 0:
                list($R, $G, $B) = array($V,$K,$M);
                break;
            case 1:
                list($R, $G, $B) = array($N,$V,$M);
                break;
            case 2:
                list($R, $G, $B) = array($M,$V,$K);
                break;
            case 3:
                list($R, $G, $B) = array($M,$N,$V);
                break;
            case 4:
                list($R, $G, $B) = array($K,$M,$V);
                break;
            case 5:
            case 6: //for when $H=1 is given
                list($R, $G, $B) = array($V,$M,$N);
                break;
        }
        return $this->convertToHex(array($R, $G, $B));
    }

    public function convertToHex($channels)
    {
        $colour = '#';
        foreach ($channels as $channel) {
            $channel = strval(dechex(round($channel*255)));
            if (strlen($channel) == 1) {
                $channel = '0' . $channel;
            }
            $colour .= $channel;
        }
        return $colour;
    }

    // pass the element's id from the list along to get a colour for a single item
    public function generatePaletteFromString($string, $items, $onlySpecific = false)
    {
        $hue = $this->__stringToNumber($string);
        $saturation = 1;
        $steps = 80 / $items;
        $results = array();
        if ($onlySpecific !== false && is_numeric($onlySpecific)) {
            $value = (20 + ($steps * ($onlySpecific + 1))) / 100;
            return $this->HSVtoRGB(array($hue, $saturation, $value));
        }
        for ($i = 0; $i < $items; $i++) {
            $value = (20 + ($steps * ($i + 1))) / 100;
            $rgb = $this->HSVtoRGB(array($hue, $saturation, $value));
            $results[] = $rgb;
        }
        return $results;
    }

    private function __stringToNumber($string)
    {
        $string = mb_convert_encoding($string, 'ASCII');
        $number = 0;
        for ($i = 0; $i < strlen($string); $i++) {
            $number += ord($string[$i]);
        }
        return $number % 100 / 100;
    }
}
