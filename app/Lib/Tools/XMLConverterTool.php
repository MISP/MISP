<?php

class XMLConverterTool
{
    private $__toEscape = array("&", "<", ">", "\"", "'");
    private $__escapeWith = array('&amp;', '&lt;', '&gt;', '&quot;', '&apos;');

    public function generateTop()
    {
        return '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL . '<response>' . PHP_EOL;
    }

    public function generateBottom()
    {
        return '</response>' . PHP_EOL;
    }

    public function recursiveEcho($array)
    {
        $text = "";
        if (is_array($array)) {
            foreach ($array as $k => $v) {
                if (is_array($v)) {
                    if (empty($v)) {
                        $text .= '<' . $k . '/>';
                    } else {
                        foreach ($v as $element) {
                            $text .= '<' . $k . '>';
                            $text .= $this->recursiveEcho($element);
                            $text .= '</' . $k . '>';
                        }
                    }
                } else {
                    if ($v === false) {
                        $v = 0;
                    }
                    if ($v === "" || $v === null) {
                        $text .= '<' . $k . '/>';
                    } else {
                        $this->__sanitizeField($v);
                        $text .= '<' . $k . '>' . $v . '</' . $k . '>';
                    }
                }
            }
        }
        return $text;
    }

    private function __rearrange($data, $model, $container)
    {
        if (isset($data[$model])) {
            $data[$container][$model] = $data[$model];
            unset($data[$model]);
        }
        return $data;
    }

    private function __rearrangeAttributes($attributes)
    {
        foreach ($attributes as $key => $value) {
            unset($attributes[$key]['value1'], $attributes[$key]['value2'], $attributes[$key]['category_order']);
            if (isset($event['Event']['RelatedAttribute']) && isset($event['Event']['RelatedAttribute'][$value['id']])) {
                $attributes[$key]['RelatedAttribute'] = $event['Event']['RelatedAttribute'][$value['id']];
                foreach ($attributes[$key]['RelatedAttribute'] as &$ra) {
                    $ra = array('Attribute' => array(0 => $ra));
                }
            }
            if (isset($attributes[$key]['ShadowAttribute'])) {
                foreach ($attributes[$key]['ShadowAttribute'] as $skey => $svalue) {
                    $attributes[$key]['ShadowAttribute'][$skey]['Org'] = array(0 => $attributes[$key]['ShadowAttribute'][$skey]['Org']);
                    if (isset($attributes[$key]['ShadowAttribute'][$skey]['EventOrg'])) {
                        $attributes[$key]['ShadowAttribute'][$skey]['EventOrg'] = array(0 => $attributes[$key]['ShadowAttribute'][$skey]['EventOrg']);
                    }
                }
            }
            if (isset($attributes[$key]['SharingGroup']['SharingGroupOrg'])) {
                foreach ($attributes[$key]['SharingGroup']['SharingGroupOrg'] as $k => $sgo) {
                    $attributes[$key]['SharingGroup']['SharingGroupOrg'][$k]['Organisation'] = array(0 => $attributes[$key]['SharingGroup']['SharingGroupOrg'][$k]['Organisation']);
                }
            }
            if (isset($attributes[$key]['SharingGroup']['SharingGroupServer'])) {
                foreach ($attributes[$key]['SharingGroup']['SharingGroupServer'] as $k => $sgs) {
                    $attributes[$key]['SharingGroup']['SharingGroupServer'][$k]['Server'] = array(0 => $attributes[$key]['SharingGroup']['SharingGroupServer'][$k]['Server']);
                }
            }
            if (isset($attributes[$key]['SharingGroup'])) {
                $attributes[$key]['SharingGroup'][0] = $attributes[$key]['SharingGroup'];
                unset($attributes[$key]['SharingGroup']);
            }
            if (isset($attributes[$key]['AttributeTag'])) {
                foreach ($attributes[$key]['AttributeTag'] as $atk => $tag) {
                    unset($tag['Tag']['org_id']);
                    $attributes[$key]['Tag'][$atk] = $tag['Tag'];
                }
                unset($attributes[$key]['AttributeTag']);
            }
        }
        return $attributes;
    }

    public function convertArray($event, $isSiteAdmin=false)
    {
        $event['Event']['Org'][0] = $event['Org'];
        $event['Event']['Orgc'][0] = $event['Orgc'];
        if (isset($event['SharingGroup']['SharingGroupOrg'])) {
            foreach ($event['SharingGroup']['SharingGroupOrg'] as $key => $sgo) {
                $event['SharingGroup']['SharingGroupOrg'][$key]['Organisation'] = array(0 => $event['SharingGroup']['SharingGroupOrg'][$key]['Organisation']);
            }
        }
        if (isset($event['SharingGroup']['SharingGroupServer'])) {
            foreach ($event['SharingGroup']['SharingGroupServer'] as $key => $sgs) {
                $event['SharingGroup']['SharingGroupServer'][$key]['Server'] = array(0 => $event['SharingGroup']['SharingGroupServer'][$key]['Server']);
            }
        }
        if (isset($event['SharingGroup'])) {
            $event['Event']['SharingGroup'][0] = $event['SharingGroup'];
        }
        $event = $this->__rearrange($event, 'Attribute', 'Event');
        $event = $this->__rearrange($event, 'Object', 'Event');
        $event = $this->__rearrange($event, 'ShadowAttribute', 'Event');
        $event = $this->__rearrange($event, 'RelatedEvent', 'Event');
        $event = $this->__rearrange($event, 'RelatedAttribute', 'Event');

        // legacy
        unset($event['Event']['org']);
        unset($event['Event']['orgc']);

        if (isset($event['EventTag'])) {
            foreach ($event['EventTag'] as $k => $tag) {
                unset($tag['Tag']['org_id']);
                $event['Event']['Tag'][$k] = $tag['Tag'];
            }
        }
        unset($event['Event']['RelatedAttribute']);
        //
        // cleanup the array from things we do not want to expose
        //
        unset($event['Event']['user_id'], $event['Event']['proposal_email_lock'], $event['Event']['locked'], $event['Event']['attribute_count']);
        // hide the org field is we are not in showorg mode
        if (!Configure::read('MISP.showorg') && !$isSiteAdmin) {
            unset($event['Event']['Org'], $event['Event']['Orgc'], $event['Event']['from']);
        }

        if (isset($event['Event']['Attribute'])) {
            // remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
            $event['Event']['Attribute'] = $this->__rearrangeAttributes($event['Event']['Attribute']);
        }
        if (!empty($event['Event']['Object'])) {
            foreach ($event['Event']['Object'] as $k => $v) {
                $event['Event']['Object'][$k]['Attribute'] = $this->__rearrangeAttributes($event['Event']['Object'][$k]['Attribute']);
            }
        }
        if (isset($event['Event']['ShadowAttribute'])) {
            // remove invalid utf8 characters for the xml parser
            foreach ($event['Event']['ShadowAttribute'] as $key => $value) {
                $event['Event']['ShadowAttribute'][$key]['Org'] = array(0 => $event['Event']['ShadowAttribute'][$key]['Org']);
                if (isset($event['Event']['ShadowAttribute'][$key]['EventOrg'])) {
                    $event['Event']['ShadowAttribute'][$key]['EventOrg'] = array(0 => $event['Event']['ShadowAttribute'][$key]['EventOrg']);
                }
            }
        }

        if (isset($event['Event']['RelatedEvent'])) {
            foreach ($event['Event']['RelatedEvent'] as $key => $value) {
                $temp = $value['Event'];
                unset($event['Event']['RelatedEvent'][$key]['Event']);
                $event['Event']['RelatedEvent'][$key]['Event'][0] = $temp;
                unset($event['Event']['RelatedEvent'][$key]['Event'][0]['user_id']);
                if (isset($event['Event']['RelatedEvent'][$key]['Event'][0]['Org'])) {
                    $event['Event']['RelatedEvent'][$key]['Event'][0]['Org'] = array(0 => $event['Event']['RelatedEvent'][$key]['Event'][0]['Org']);
                }
                if (isset($event['Event']['RelatedEvent'][$key]['Event'][0]['Orgc'])) {
                    $event['Event']['RelatedEvent'][$key]['Event'][0]['Orgc'] = array(0 => $event['Event']['RelatedEvent'][$key]['Event'][0]['Orgc']);
                }
                unset($temp);
            }
        }
        $result = array('Event' => $event['Event']);
        if (isset($event['errors']) && !empty($event['errors'])) {
            $result['errors'] = $event['errors'];
        }
        return $result;
    }

    public function convert($event, $isSiteAdmin=false)
    {
        $xmlArray = $this->convertArray($event, $isSiteAdmin);
        $result = array('Event' => array(0 => $xmlArray['Event']));
        if (isset($xmlArray['errors']) && !empty($xmlArray['errors'])) {
            $result['errors'] = array($xmlArray['errors']);
        }
        return $this->recursiveEcho($result);
    }

    private function __sanitizeField(&$field)
    {
        $field = preg_replace('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $field);
        $field = str_replace($this->__toEscape, $this->__escapeWith, $field);
    }

    public function eventCollection2Format($events, $isSiteAdmin=false)
    {
        $result = "";
        foreach ($events as $event) {
            $result .= $this->convert($event) . PHP_EOL;
        }
        return $result;
    }

    public function frameCollection($input, $mispVersion = false)
    {
        $result = '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL . '<response>' . PHP_EOL;
        $result .= $input;
        if ($mispVersion) {
            $result .= '<xml_version>' . $mispVersion . '</xml_version>';
        }
        return $result . '</response>' . PHP_EOL;
    }

    private function __prepareAttributes($attributes)
    {
        return $attributes;
    }
}
