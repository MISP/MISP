<?php
class ArrayFlattenerTool
{
    public function flatten($array)
    {
        return $this->array_flatten($array);
    }

    public function unflatten($array)
    {
        return $this->array_unflatten($array);
    }
    
    /**
     * array_flatten Perform a DFS while flattening the array
     */
    private function array_flatten($toFlatten, $prefix='', $separator='.')
    {
        $result = array();
        foreach ($toFlatten as $k => $v)
        {
            $new_key = $prefix . (empty($prefix) ? '' : '.') . $k;
            if (is_array($v)) {
                $result = array_merge($result, $this->array_flatten($v, $new_key, $separator));
            } else {
                $result[$new_key] = $v;
            }
        }
        return $result;
    }

    private function array_unflatten($toUnflatten, $separator='.')
    {
        $result = array();
        foreach ($toUnflatten as $k => $v)
        {
            $decomposedKey = explode($separator, $k);
            $result = $this->buildMultiDimensionalArrayFromKeypath($decomposedKey, $result, $v);
        }
        return $result;
    }

    private function buildMultiDimensionalArrayFromKeypath($keypath, $result, $value)
    {
        if (empty($keypath)) {
            $result = $value;
        } else {
            foreach ($keypath as $key) {
                array_shift($keypath);
                $result[$key] = $this->buildMultiDimensionalArrayFromKeypath($keypath, $result, $value);
            }
        }
        return $result;
    }
}
