<?php
App::uses('AppHelper', 'View/Helper');

class PivotHelper extends AppHelper
{
    /**
     * @param array $pivot
     * @param int $currentEventId
     * @return void
     */
    public function convertPivotToHTML(array $pivot, $currentEventId)
    {
        if ($pivot['id'] == $currentEventId) {
            $lookingAtRoot = true;
            $pivotType = 'activePivot';
        } else {
            $lookingAtRoot = false;
            $pivotType = '';
        }
        $temp = $this->__doConvert($pivot, $currentEventId, $lookingAtRoot);
        $height = $this->__findMaxHeight($pivot);
        $height = $height + 50;
        echo '<div class="pivotElement firstPivot ' . $pivotType . '" style="height:' . $height . 'px;">';
        foreach ($temp as $v) {
            echo $v;
        }
        echo '</div>';
    }

    /**
     * @param array $pivot
     * @param int $currentEventId
     * @param bool $activeText
     * @return array
     */
    private function __doConvert($pivot, $currentEventId, $activeText=false)
    {
        $data = null;
        $info = h($pivot['info']);
        $text = $pivot['id'] . ': ' . $info;
        $active = '';

        // Colour the text white if it is a highlighted pivot element
        if ($activeText) {
            $pivotType = 'pivotTextBlue';
            $pivotSpanType = 'pivotSpanBlue';
        } else {
            $pivotType = 'pivotText';
            $pivotSpanType = '';
        }

        $data[] = '<span class="' . $pivotSpanType . '">';
        if ($pivot['deletable']) {
            $data[] = '<a class="pivotDelete fa fa-times" href="' . h(Configure::read('MISP.baseurl')) . '/events/removePivot/' . $pivot['id'] . '/' . $currentEventId . '" title="' . __('Remove pivot') . '"></a>';
        }
        $data[] = '<a class="' . $pivotType . '" href="' . h(Configure::read('MISP.baseurl')) . '/events/view/' . $pivot['id'] . '/1/' . $currentEventId . '" title="' . $info . ' (' . $pivot['date'] . ')">' . $text . '</a>';
        $data[] = '</span>';
        if (!empty($pivot['children'])) {
            foreach ($pivot['children'] as $k => $v) {
                $extra = '';
                if ($v['id'] == $currentEventId) {
                    $active = ' activePivot';
                }
                if ($k > 0) {
                    $pixelDifference = $pivot['children'][$k]['height'] - $pivot['children'][$k-1]['height'];
                    $lineDifference = $pixelDifference / 50;
                    $extra = ' distance' . $lineDifference;
                }
                $data[] = '<div class="pivotElement' . $extra . $active . '" style="top:' . $pivot['children'][$k]['height'] . 'px;">';
                if ($active != '') {
                    $temp = $this->__doConvert($v, $currentEventId, true);
                } else {
                    $temp = $this->__doConvert($v, $currentEventId);
                }
                $data = array_merge($data, $temp);
                $data[] = '</div>';
                $active = '';
            }
        }
        return $data;
    }

    /**
     * @param array $pivot
     * @return int
     */
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
