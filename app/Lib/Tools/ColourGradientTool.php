<?php
class ColourGradientTool
{
    public function createGradient($step)
    {
        $stepHex = dechex($step);
        $minHex = 0x0000FF;
        $maxHex = 0xFF0000;
        $intervalHex = ($maxHex-$minHex) / $stepHex;
        $colours = array();
        for ($i=$minHex; $i<$maxHex; $i+=$intervalHex) {
            $colours[] = $i;
        }
        return $colours;
    }

    // $values of the form array(item1: val1, item2: val2, ...)
    public function createGradientFromValues($items)
    {
        if (count($items) == 0) {
            return array();
        }

        $maxColorHex = 0x0000FF;
        $minColorHex = 0xE0E0FF;

        $vals = array_values($items);
        $maxDec = max($vals);
        $minDec = min($vals);

        if ($maxDec == $minDec) {
            $intervalHex = 0x0;
        } else {
            $intervalHex = ($maxColorHex - $minColorHex)/($maxDec-$minDec);
        }

        $coloursMapping = array();
        foreach ($items as $name => $val) {
            $ratio = ($val-$minDec)*($intervalHex);
            $colour = $maxDec == $minDec ? $maxColorHex : $ratio + $minColorHex;
            $coloursMapping[$name] = '#' . str_pad(dechex($colour), 6, '0', STR_PAD_LEFT);
        }
        return $coloursMapping;
    }
}
