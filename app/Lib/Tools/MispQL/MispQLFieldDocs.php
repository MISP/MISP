<?php

/**
 * What each field of a MispQL table means, in one sentence: shown by the
 * query console and sent with DESCRIBE. A name keeps one sentence on every
 * table where it means the same thing; a table overrides it where it does
 * not. Type, operators and level are described elsewhere.
 */
class MispQLFieldDocs
{
    /** @var array table => field => sentence */
    private static $cache = [];

    /**
     * @param string $table
     * @param string $field as queryDescribe names it, `meta.<key>` for a
     *   wildcard
     * @return string|null
     */
    public static function describe($table, $field)
    {
        if (!isset(self::$cache[$table])) {
            self::$cache[$table] = self::own($table) + self::shared($table);
        }
        return self::$cache[$table][$field] ?? null;
    }

    /**
     * @param string $table
     * @param array $fields as queryDescribe lists them
     * @return array the fields, each with its `description` when it has one
     */
    public static function annotate($table, array $fields)
    {
        foreach ($fields as $name => $def) {
            $sentence = self::describe($table, $name);
            if ($sentence !== null) {
                $fields[$name]['description'] = $sentence;
            }
        }
        return $fields;
    }

    /**
     * @return array the sentences of names meaning the same on every table
     *   that has them
     */
    private static function shared($table)
    {
        $inherits = in_array($table, ['attributes', 'objects', 'event_reports'], true);
        return [
            'id' => __('Its id on this instance; ids differ from one instance to another, UUIDs do not.'),
            'uuid' => __('Its UUID, the same on every instance that holds it.'),
            'distribution' => $inherits
                ? __('Who it is shared with: 0 your organisation only, up to 3 all communities; 4 a sharing group; 5 as its event.')
                : __('Who it is shared with: 0 your organisation only, up to 3 all communities; 4 a sharing group.'),
            'timestamp' => __('When it was last changed.'),
            'locked' => __('Whether it is a copy received through synchronisation, locked against local edits.'),
            'event_id' => __('The id of its event.'),
            'eventinfo' => __("The event's info, its title line."),
            'date' => __("The event's date, as its author set it."),
            'event_timestamp' => __('When the event was last changed.'),
            'publish_timestamp' => __('When the event was last published.'),
            'published' => __('Whether the event is published.'),
            'threat_level_id' => __("The event's threat level: 1 high, 2 medium, 3 low, 4 undefined."),
            'analysis' => __("The event's analysis: 0 initial, 1 ongoing, 2 completed."),
            'org' => __("The event's creator organisation, by name, UUID or id."),
            'org_id' => __('The id of the organisation holding the event on this instance.'),
            'orgc_id' => __("The id of the event's creator organisation."),
            'tags' => __('A tag on the attribute or on its event, by name, or by id when all digits; in a name _ stands for any one character. Negated: neither carries it.'),
            'type' => __("The attribute's type, such as ip-dst or domain."),
            'category' => __("The attribute's category, such as Network activity."),
            'value' => __("The attribute's value; a composite value such as domain|ip matches by either part."),
            'object_relation' => __("The attribute's role in its object, such as ip or domain; != also matches the attributes outside an object."),
            'comment' => __("The attribute's comment."),
            'to_ids' => __('Whether the attribute is flagged for detection (the IDS flag).'),
            'object_id' => __('The id of the object it belongs to; 0 outside an object.'),
            'object_name' => __("The object's template name, such as domain-ip."),
            'object_template_uuid' => __("The UUID of the object's template."),
            'object_type' => __('The type of the record it is attached to, such as Event or Attribute.'),
            'object_uuid' => __('The UUID of the record it is attached to.'),
            'object_sha256' => __('The SHA-256 of the value it is attached to, when it is attached to a value.'),
            'authors' => __('Its authors, as written on it.'),
            'org_uuid' => __('The UUID of the organisation holding it on this instance.'),
            'orgc_uuid' => __('The UUID of its creator organisation.'),
            'created' => __('When it was created; a date is read in UTC.'),
            'modified' => __('When it was last changed; a date is read in UTC.'),
        ];
    }

    /**
     * @return array the sentences of the table's own names, and of names
     *   meaning something else there
     */
    private static function own($table)
    {
        switch ($table) {
            case 'events':
                return [
                    'event_id' => __('The same as id.'),
                    'timestamp' => __('When the event was last changed; the same as event_timestamp.'),
                    'event_timestamp' => __('The same as timestamp.'),
                    'tags' => __('Selects the events carrying the tag or holding an attribute that does, by name or id. Negated, it leaves out the events carrying it and strips the tagged attributes from the others.'),
                ];
            case 'objects':
                return [
                    'object_id' => __('The same as id.'),
                    'tags' => __("Selects the objects whose event carries the tag or holding an attribute that does, by name or id. Negated, it leaves out the objects of events carrying it and strips the tagged attributes."),
                ];
            case 'galaxy_clusters':
                return [
                    'type' => __("The cluster's type, its galaxy's, such as threat-actor."),
                    'value' => __("The cluster's value, the name it goes by, such as APT 28."),
                    'tag_name' => __('The tag attaching the cluster, such as misp-galaxy:threat-actor="APT 28".'),
                    'description' => __("The cluster's description."),
                    'source' => __("Where the cluster's content comes from, as its author wrote it."),
                    'authors' => __("The cluster's authors, as the stored JSON list: match one with LIKE."),
                    'version' => __("The cluster's version number."),
                    'org' => __("The cluster's creator organisation, by name or UUID; 'MISP' selects the clusters the MISP project maintains."),
                    'org_id' => __('The id of the organisation holding the cluster on this instance.'),
                    'orgc_id' => __("The id of the cluster's creator organisation; 0 for the clusters the MISP project maintains."),
                    'galaxy_id' => __("The id of the cluster's galaxy."),
                    'galaxy_uuid' => __("The UUID of the cluster's galaxy."),
                    'galaxy_name' => __("The name of the cluster's galaxy, such as Threat Actor."),
                    'galaxy_namespace' => __("The namespace of the cluster's galaxy, such as misp."),
                    'collection_uuid' => __('The UUID of the cluster file it was shipped in, shared by the clusters of that file.'),
                    'extends_uuid' => __('The UUID of the cluster it extends, when it is a fork of one.'),
                    'extends_version' => __('The version of the cluster it extends.'),
                    'default' => __('Whether it is shipped with MISP, rather than made on an instance.'),
                    'published' => __('Whether the cluster is published.'),
                    'deleted' => __('Whether the cluster is deleted.'),
                    'meta.<key>' => __("One of the cluster's meta values under that key, such as meta.synonyms; a key holding other characters than letters, digits and _ goes in backticks: meta.`cfr-suspected-victims`."),
                ];
            case 'event_reports':
                return [
                    'name' => __("The report's name."),
                    'content' => __("The report's text, as its Markdown; matching it reads every report you can see."),
                    'deleted' => __('Whether the report is deleted; deleted reports are left out unless a condition names deleted.'),
                    'tags' => __('A tag on the report or on its event, by name, or by id when all digits; in a name _ stands for any one character. Negated: neither carries it.'),
                ];
            case 'notes':
            case 'opinions':
            case 'relationships':
                return [
                    'org' => __('Its creator organisation, by name or UUID.'),
                    'note' => __("The note's text."),
                    'language' => __("The note's language, as its author set it."),
                    'opinion' => __('The opinion, from 0 (disagree) to 100 (agree).'),
                    'comment' => __("The opinion's comment."),
                    'relationship_type' => __('The kind of relationship, such as related-to.'),
                    'related_object_type' => __('The type of the record it points to.'),
                    'related_object_uuid' => __('The UUID of the record it points to.'),
                    'related_object_sha256' => __('The SHA-256 of the value it points to, when it points to a value.'),
                ];
            case 'collections':
                return [
                    'name' => __("The collection's name."),
                    'type' => __("The collection's type, such as campaign or research."),
                    'description' => __("The collection's description."),
                    'org' => __("The collection's creator organisation, by name or UUID."),
                    'org_id' => __('The id of the organisation holding the collection on this instance.'),
                    'orgc_id' => __("The id of the collection's creator organisation."),
                    'user_id' => __('The id of the user who created it.'),
                    'created' => __("When it was created; a date is read in the server's time zone."),
                    'modified' => __("When it was last changed, adding or removing an element included; a date is read in the server's time zone."),
                    'element_type' => __('The type of one of its elements, such as Event or AttributeValue; matches when any element does.'),
                    'element_uuid' => __('The UUID of one of its elements; matches when any element does.'),
                    'element_sha256' => __('The SHA-256 of one of its value elements; matches when any element does.'),
                    'element_description' => __('The description of one of its elements; matches when any element does.'),
                ];
            case 'tags':
                return [
                    'name' => __("The tag's name, such as tlp:amber."),
                    'colour' => __("The tag's colour, as #rrggbb."),
                    'exportable' => __('Whether the tag is exported and synchronised; a tag that is not stays on this instance.'),
                    'org_id' => __('The organisation the tag is restricted to; 0 for none.'),
                    'user_id' => __('The user the tag is restricted to; 0 for none.'),
                    'hide_tag' => __('Whether the tag is hidden, so it cannot be picked for tagging.'),
                    'numerical_value' => __("The tag's own numerical value; a user's override is not searched."),
                    'is_galaxy' => __('Whether the tag attaches a galaxy cluster.'),
                    'is_custom_galaxy' => __('Whether the tag attaches a custom cluster, named by its UUID.'),
                    'local_only' => __('Whether the tag can only be attached as a local tag, never synchronised.'),
                ];
            case 'organisations':
                return [
                    'name' => __("The organisation's name."),
                    'type' => __("The organisation's type, as written on it, such as CSIRT."),
                    'nationality' => __("The organisation's country."),
                    'sector' => __("The organisation's sector."),
                    'description' => __("The organisation's description."),
                    'contacts' => __("The organisation's contact details."),
                    'landingpage' => __("The organisation's landing page."),
                    'local' => __('Whether it is an organisation of this instance, rather than one known through sharing.'),
                    'date_created' => __("When it was created on this instance; a date is read in the server's time zone."),
                    'date_modified' => __("When it was last changed; a date is read in the server's time zone."),
                ];
        }
        return [];
    }
}
