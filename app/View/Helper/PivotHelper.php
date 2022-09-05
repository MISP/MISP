<?php
App::uses('AppHelper', 'View/Helper');

class PivotHelper extends AppHelper
{
    public function convertPivotToHTML(array $pivot, $currentEvent)
    {
        $lookingAtRoot = false;
        $pivotType = '';
        if ($pivot['id'] == $currentEvent) {
            $lookingAtRoot = true;
            $pivotType = ' activePivot';
        }
        $temp = $this->__doConvert($pivot, $currentEvent, $lookingAtRoot);
        $height = $this->__findMaxHeight($pivot);
        $height = $height + 50;
        echo '<div class="pivotElement firstPivot ' . $pivotType . '" style="height:' . $height . 'px;">';
        foreach ($temp as $v) {
            echo $v;
        }
        echo '</div>';
    }

    private function __doConvert($pivot, $currentEvent, $activeText=false)
    {
        $data = null;
        $info = h($pivot['info']);
        $text = $pivot['id'] . ': ' . $info;
        $active = '';

        // Colour the text white if it is a highlighted pivot element
        $pivotType = 'pivotText';
        $pivotSpanType = '';
        if ($activeText) {
            $pivotType = 'pivotTextBlue';
            $pivotSpanType = 'pivotSpanBlue';
        }

        $data[] = '<span class="'.$pivotSpanType.'">';
        if ($pivot['deletable']) {
            $data[] = '<a class="pivotDelete fa fa-times" href="' . h(Configure::read('MISP.baseurl')) . '/events/removePivot/' . $pivot['id'] . '/' . $currentEvent . '" title="' . __('Remove pivot') . '"></a>';
        }
        $data[] = '<a class="' . $pivotType . '" href="' . h(Configure::read('MISP.baseurl')) . '/events/view/' . $pivot['id'] . '/1/' . $currentEvent . '" title="' . $info . ' (' . $pivot['date'] . ')">' . $text . '</a>';
        $data[] = '</span>';
        if (!empty($pivot['children'])) {
            foreach ($pivot['children'] as $k => $v) {
                $extra = '';
                if ($v['id'] == $currentEvent) {
                    $active = ' activePivot';
                }
                if ($k > 0) {
                    $pixelDifference = $pivot['children'][$k]['height'] - $pivot['children'][$k-1]['height'];
                    $lineDifference = $pixelDifference / 50;
                    $extra = ' distance' . $lineDifference;
                }
                $data[] = '<div class="pivotElement' . $extra . $active . '" style="top:' . $pivot['children'][$k]['height'] . 'px;">';
                if ($active != '') $temp = $this->__doConvert($v, $currentEvent, true);
                else $temp = $this->__doConvert($v, $currentEvent);
                $data = array_merge($data, $temp);
                $data[] = '</div>';
                $active = '';
            }
        }
        return $data;
    }

    private function __findMaxHeight(array $pivot)
    {
        $height = $pivot['height'];
        $heightToAdd = 0;
        foreach ($pivot['children'] as $v) {
            $temp = $this->__findMaxHeight($v);
            if ($temp > $heightToAdd) $heightToAdd = $temp;
        }
        return $height + $heightToAdd;
    }
}
