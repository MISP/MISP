<?php
/** Version 1 gathering envelope: ordinary MISP feed files transported together. */
class GatheringFeedTool
{
    const MAX_BYTES = 33554432;
    const MAX_EVENTS = 100;

    public static function settings($settings)
    {
        if (is_string($settings)) {
            $settings = json_decode($settings, true);
        }
        $options = $settings['gathering'] ?? null;
        if (!is_array($options) || !isset($options['module']) ||
            !is_string($options['module']) || !preg_match('/\A[a-z][a-z0-9_]*\z/D', $options['module'])) {
            throw new InvalidArgumentException('Select a gathering module.');
        }
        $parameters = $options['parameters'] ?? [];
        if (is_string($parameters)) {
            if ($parameters === '') {
                $parameters = '{}';
            }
            $decoded = json_decode($parameters);
            if (!is_object($decoded) || json_last_error() !== JSON_ERROR_NONE) {
                throw new InvalidArgumentException('Gathering parameters must be a JSON object.');
            }
            $parameters = json_decode($parameters, true);
        }
        if (!is_array($parameters) || ($parameters && array_keys($parameters) === range(0, count($parameters) - 1))) {
            throw new InvalidArgumentException('Gathering parameters must be a JSON object.');
        }
        return ['module' => $options['module'], 'parameters' => $parameters];
    }

    private static function uuid($value)
    {
        return is_string($value) && preg_match('/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/Di', $value);
    }

    public static function validateBundle($bundle)
    {
        if (!is_array($bundle) || !empty($bundle['error']) || !empty($bundle['errors'])) {
            throw new UnexpectedValueException('Gathering module failed; no feed was imported. Check the module logs.');
        }
        if (($bundle['gathering_version'] ?? null) !== 1 || ($bundle['source_format'] ?? null) !== 'misp' ||
            !isset($bundle['manifest'], $bundle['events']) || !is_array($bundle['manifest']) || !is_array($bundle['events'])) {
            throw new UnexpectedValueException('Unsupported gathering feed contract.');
        }
        $encoded = json_encode($bundle);
        if ($encoded === false || strlen($encoded) > self::MAX_BYTES || count($bundle['events']) > self::MAX_EVENTS) {
            throw new UnexpectedValueException('Gathering feed exceeds the supported size; narrow the collection parameters.');
        }
        if (array_diff_key($bundle['manifest'], $bundle['events']) || array_diff_key($bundle['events'], $bundle['manifest'])) {
            throw new UnexpectedValueException('Gathering manifest and event files do not match.');
        }
        $identities = [];
        foreach ($bundle['events'] as $uuid => $wrapped) {
            $event = $wrapped['Event'] ?? null;
            $metadata = $bundle['manifest'][$uuid];
            if (!self::uuid($uuid) || !is_array($event) || !is_array($metadata) || ($event['uuid'] ?? null) !== $uuid ||
                !empty($event['protected'])) {
                throw new UnexpectedValueException('Invalid gathering event identity or unsupported protected event.');
            }
            foreach (['info', 'date', 'timestamp', 'Orgc'] as $field) {
                if (!isset($event[$field], $metadata[$field]) || $metadata[$field] !== $event[$field]) {
                    throw new UnexpectedValueException('Gathering event metadata differs from its manifest.');
                }
            }
            if (!is_string($event['info']) || trim($event['info']) === '' || !is_string($event['date']) ||
                !preg_match('/\A\d{4}-\d{2}-\d{2}\z/D', $event['date'])) {
                throw new UnexpectedValueException('Invalid gathering event title or date.');
            }
            if ((!is_string($event['timestamp']) && !is_int($event['timestamp'])) ||
                !ctype_digit((string)$event['timestamp']) || (int)$event['timestamp'] < 1 ||
                !is_array($event['Orgc']) || !self::uuid($event['Orgc']['uuid'] ?? null)) {
                throw new UnexpectedValueException('Invalid gathering event revision or creator organisation.');
            }
            foreach (['publish_timestamp', 'Tag'] as $field) {
                if (($event[$field] ?? null) !== ($metadata[$field] ?? null)) {
                    throw new UnexpectedValueException('Gathering event metadata differs from its manifest.');
                }
            }
            $entities = [$event];
            foreach (['Attribute', 'Object'] as $field) {
                if (isset($event[$field]) && !is_array($event[$field])) {
                    throw new UnexpectedValueException('Invalid gathering event entities.');
                }
                foreach ($event[$field] ?? [] as $entity) {
                    $entities[] = $entity;
                    if ($field === 'Object') {
                        if (isset($entity['Attribute']) && !is_array($entity['Attribute'])) {
                            throw new UnexpectedValueException('Invalid gathering object attributes.');
                        }
                        foreach ($entity['Attribute'] ?? [] as $attribute) {
                            $entities[] = $attribute;
                        }
                    }
                }
            }
            foreach ($entities as $entity) {
                $identity = $entity['uuid'] ?? null;
                if (!self::uuid($identity) || isset($identities[strtolower($identity)])) {
                    throw new UnexpectedValueException('Gathering entities must have unique stable UUIDs.');
                }
                $identities[strtolower($identity)] = true;
            }
        }
        return $bundle;
    }

    public static function file(array $bundle, $path)
    {
        if ($path === '/manifest.json') {
            return json_encode((object)$bundle['manifest']);
        }
        if (preg_match('/\A\/([0-9a-f-]{36})\.json\z/Di', $path, $match) && isset($bundle['events'][$match[1]])) {
            return json_encode($bundle['events'][$match[1]]);
        }
        throw new NotFoundException('File is not present in this gathering feed snapshot.');
    }
}
