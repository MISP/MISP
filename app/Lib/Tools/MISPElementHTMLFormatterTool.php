<?php
class MISPElementHTMLFormatterTool
{

    public function attribute($attribute)
    {
        $html = sprintf(
            '<span
                style="
                    display: inline-block;
                    margin: 3px 3px;
                    border: 1px solid #ddd;
                    font-weight: bold;
                    border-radius: 3px;
                    white-space: nowrap;
                    padding: 0;
                    font-size: 14px;
                    line-height: 23px;
                    "
            >
                <span
                    style="background-color: #f5f5f5; color: #333333;"
                >
                    <span
                        style="
                            margin: 2px 3px;
                            max-width: 300px;
                            overflow: hidden;
                            text-overflow: ellipsis;
                            white-space: nowrap;
                            line-height: 23px;"
                    >domain-ip</span>
                </span>
                <span
                    style=""
                >
                    <span
                        style="margin: 2px 3px; color: #0088cc; line-height: 23px;"
                    >google.com</span>
                </span>
            </span>',
            $attribute['type'], $attribute['value']);
        return $html;
    }

    public function objectAttribute($object, $attribute)
    {
        $html = sprintf(
            '<span
                style="
                    display: inline-block;
                    margin: 3px 3px;
                    border: 1px solid #3465a4;
                    font-weight: bold;
                    border-radius: 3px;
                    white-space: nowrap;
                    padding: 0;
                    font-size: 14px;
                    background-color: #3465a4;"
            >
                <span
                    style="color: #fff; line-height: 23px;"
                >
                    <span
                        style="
                            margin: 2px 3px;
                            max-width: 300px;
                            overflow: hidden;
                            text-overflow: ellipsis;
                            white-space: nowrap;"
                    >%s ↦ <span style="background-color: #f5f5f5; color: #000; padding: 1px 3px; border-radius: 5px; line-height: 18px; font-size: 14px;">%s</span>
                    </span>
                </span>
                <span
                    style=""
                >
                    <span
                        style="margin: 2px 3px; padding:1px 3px; border-top-right-radius: 3px; border-bottom-right-radius: 3px; background-color: #fff;"
                    >%s</span>
                </span>
            </span>',
            $object['name'], $attribute['object_relation'], $attribute['value']);
        return $html;
    }

    public function object($object)
    {
        if (!empty($object['Attribute'][0])) {
            $firstAttributeValue = $object['Attribute'][0]['value'];
        } else {
            $firstAttributeValue = '-- no attributes --';
        }
        $html = sprintf(
            '<span
                style="
                    display: inline-block;
                    margin: 3px 3px;
                    border: 1px solid #3465a4;
                    font-weight: bold;
                    border-radius: 3px;
                    white-space: nowrap;
                    padding: 0;
                    font-size: 14px;
                    background-color: #3465a4;"
            >
                <span
                    style="color: #fff; line-height: 23px;"
                >
                    <span
                        style="
                            margin: 2px 3px;
                            max-width: 300px;
                            overflow: hidden;
                            text-overflow: ellipsis;
                            white-space: nowrap;"
                    >%s</span>
                </span>
                <span
                    style=""
                >
                    <span
                        style="margin: 2px 3px; padding:1px 2px; border-top-right-radius: 3px; border-bottom-right-radius: 3px; background-color: #fff;"
                    >%s</span>
                </span>
            </span>',
            $object['name'], $firstAttributeValue);
        return $html;
    }

    public function tag($tag)
    {
        $tag['text_colour'] = $this->getTextColour($tag['colour']);
        $html = sprintf(
            '<span
                style="background-color: %s;
                    color: rgb(255, 255, 255);
                    box-shadow: rgb(136, 136, 136) 2px 1px 3px 0px;
                    color: %s;
                    padding: 2px 4px;
                    font-weight: bold;
                    display: inline-block;
                    margin-right: 2px;
                    border-radius: 3px;
                    line-height: 14px;
                    font-size: 12px;"
            >%s</span>',
            $tag['colour'], $tag['text_colour'], h($tag['name']));
        return $html;
    }


    private function getTextColour($RGB) {
        $r = hexdec(substr($RGB, 1, 2));
        $g = hexdec(substr($RGB, 3, 2));
        $b = hexdec(substr($RGB, 5, 2));
        $average = ((2 * $r) + $b + (3 * $g))/6;
        if ($average < 127) {
            return 'white';
        } else {
            return 'black';
        }
    }

}