<?php

/**
 * Builds the Analyst Profiles MISP ships from app/files/analyst-profiles/.
 *
 * A profile that names another in `extends` states only what it changes:
 * its `parameters` are a JSON Merge Patch (RFC 7396) over its base's.
 * Objects merge key by key, any other value replaces, and null deletes.
 */
class ShippedProfileTool
{
    /**
     * @param array $documents File slug => document decoded to objects
     * @return array `profiles`, each with `uuid`, `name`, `description`,
     *               `parameters` (stdClass) and `version`; and `errors`,
     *               slug => why that document was skipped
     */
    public static function resolve(array $documents)
    {
        $profiles = array();
        $errors = array();
        foreach ($documents as $slug => $document) {
            $base = null;
            if (isset($document->extends)) {
                $name = (string)$document->extends;
                if (!isset($documents[$name])) {
                    $errors[$slug] = sprintf(
                        'extends %s, which is not a shipped profile',
                        $name
                    );
                    continue;
                }
                $base = $documents[$name];
                if (isset($base->extends)) {
                    $errors[$slug] = sprintf(
                        'extends %s, which extends another profile itself',
                        $name
                    );
                    continue;
                }
            }
            $parameters = $base === null
                ? self::copy($document->parameters)
                : self::mergePatch(
                    self::copy($base->parameters),
                    self::copy($document->parameters)
                );
            // A derived profile must reload when its base moves on too.
            $version = self::version($document)
                + ($base === null ? 0 : self::version($base));
            $profiles[] = array(
                'uuid' => (string)$document->uuid,
                'name' => (string)$document->name,
                'description' => isset($document->description)
                    ? (string)$document->description
                    : null,
                'parameters' => $parameters,
                'version' => $version,
            );
        }
        return array('profiles' => $profiles, 'errors' => $errors);
    }

    /**
     * @param mixed $target
     * @param mixed $patch
     * @return mixed
     */
    public static function mergePatch($target, $patch)
    {
        if (!$patch instanceof stdClass) {
            return $patch;
        }
        if (!$target instanceof stdClass) {
            $target = new stdClass();
        }
        foreach ($patch as $key => $value) {
            if ($value === null) {
                unset($target->{$key});
                continue;
            }
            $target->{$key} = self::mergePatch(
                isset($target->{$key}) ? $target->{$key} : null,
                $value
            );
        }
        return $target;
    }

    /**
     * @param stdClass $document
     * @return int
     */
    private static function version($document)
    {
        return isset($document->version) ? (int)$document->version : 1;
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private static function copy($value)
    {
        return json_decode(json_encode($value, JSON_PRESERVE_ZERO_FRACTION));
    }
}
