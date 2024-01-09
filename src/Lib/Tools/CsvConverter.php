<?php

namespace App\Lib\Tools;

use Cake\Utility\Hash;


class CsvConverter
{

    /**
     * @param array $data
     * @param array $options
     * @return string
     */
    public static function flattenJSON(array $data, $options=[]): string
    {
        $csv = '';
        $toConvert = [];
        if (!self::array_is_list($data)) {
            $toConvert = [$data];
        } else {
            $toConvert = $data;
        }

        $headers = self::collectHeaders($toConvert);
        $csv .= implode(',', self::quoteArray($headers)) . PHP_EOL;
        foreach ($toConvert as $i => $item) {
            $csv .= self::getRow($headers, $item);
        }

        return $csv;
    }

    private static function collectHeaders(array $items): array
    {
        $allHeaders = [];
        foreach ($items as $item) {
            $headers = Hash::flatten($item);
            foreach ($headers as $head => $value) {
                if (str_starts_with($head, '_')) {
                    continue;
                }
                if (is_array($value) && empty($value)) {
                    continue;
                }
                $allHeaders[$head] = 1;
            }
        }
        return array_keys($allHeaders);
    }

    private static function getRow(array $headers, array $item): string
    {
        $tmp = [];
        foreach ($headers as $header) {
            $value = Hash::get($item, $header);
            if (!isset($value)) {
                $value = '';
            }
            if (is_bool($value)) {
                $value = !empty($value) ? '1' : '0';
            }
            $tmp[] = '"' . $value . '"';
        }
        $row = implode(',', $tmp) . PHP_EOL;
        return $row;
    }

    private static function quoteArray(array $arr): array
    {
        return array_map(function($item) {
            return '"' . $item . '"';
        }, $arr);
    }

    private static function array_is_list(array $arr): bool
    {
        if ($arr === []) {
            return true;
        }
        return array_keys($arr) === range(0, count($arr) - 1);
    }
}