<div class="dashboard_element">
    <?php
        echo '<h4 class="blue bold">API info</h4>';
        foreach ($api_info as $key => $value) {
            if (!empty($value)) {
                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        $value[$k] = h($v);
                    }
                    if (isset($value['OR']) || isset($value['AND']) || isset($value['NOT'])) {
                        $temp = array();
                        foreach ($value as $k => $v) {
                            $temp[] = $k . ': ' . implode(', ', $v);
                        }
                        $value = $temp;
                    }
                    $temp = array();
                    foreach ($value as $k => $field) {
                        $fieldName = $field;
                        $infoHtml = '';
                        if ($key === 'mandatory' || $key === 'optional') {
                            if (is_array($field)) {
                                foreach($field as $subfield) {
                                    $infoHtml .= '<i id="infofield-'. $subfield .'" class="fa fa-info restclient-infofield" style="margin-left: 5px; width: 12px; height: 12px;"></i>';
                                }
                                $fieldName = $k;
                            } else {
                                $infoHtml = '<i id="infofield-'. $field .'" class="fa fa-info restclient-infofield" style="margin-left: 5px; width: 12px; height: 12px;"></i>';
                            }
                        }
                        $temp[] = $fieldName . $infoHtml;
                    }
                    $value = implode('<br />', $temp);
                } else {
                    $value = h($value);
                }
                echo sprintf('<span class=blue>%s</span>:<br /><div style="padding-left:10px;">%s</div>', ucfirst(h($key)), $value);
            }
        }
    ?>
</div>
