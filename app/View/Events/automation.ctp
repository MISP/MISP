<div class="event index">
    <h2><?php echo __('Automation');?></h2>
    <p><?php echo __('Automation functionality is designed to automatically feed other tools and systems with the data in your MISP repository.
    To to make this functionality available for automated tools an authentication key is used.');?><br/>
    <strong><?php echo __('Make sure you keep your API key secret as it gives access to the all of the data that you normally have access to in MISP.');?></strong>
	To view the old MISP automation page, click <a href="<?php echo $baseurl; ?>/events/automation/1">here</a>.
	</p>
    <p><?php echo __('Your current key is: <code>%s</code>.
    You can %s this key.', $me['authkey'], $this->Html->link(__('reset'), array('controller' => 'users', 'action' => 'resetauthkey', 'me')));?>
    </p>
	<?php
		$data = array(
			'description' => array(
				__('It is possible to search the database for attributes based on a list of criteria.'),
				__('To return an event or a list of events in a desired format, use the following syntax'),
				__('Whilst a list of parameters is provided below, it isn\'t necessarily exhaustive, specific export formats could have additional parameters.')
			),
			'parameters' => array(
				"returnFormat" => __('Set the return format of the search (Currently supported: json, xml, openioc, suricata, snort - more formats are being moved to restSearch with the goal being that all searches happen through this API). Can be passed as the first parameter after restSearch or via the JSON payload.'),
				"value" => __('Search for the given value in the attributes\' value field.'),
				"type" => __('The attribute type, any valid MISP attribute type is accepted.'),
				"category" => __('The attribute category, any valid MISP attribute category is accepted.'),
				"org" => __('Search by the creator organisation by supplying the organisation identifier.'),
				"tags" => __('To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a \'!\'.'),
				"quickfilter" => __('Enabling this (by passing "1" as the argument) will make the search ignore all of the other arguments, except for the auth key and value. MISP will return an xml / json (depending on the header sent) of all events that have a sub-string match on value in the event info, event orgc, or any of the attribute value1 / value2 fields, or in the attribute comment.'),
				"from" => __('Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.'),
				"to" => __('Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.'),
				"last" => __('Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.'),
				"eventid" => __('The events that should be included / excluded from the search'),
				"withAttachments" => __('If set, encodes the attachments / zipped malware samples as base64 in the data field within each attribute'),
				"metadata" => __('Only the metadata (event, tags, relations) is returned, attributes and proposals are omitted.'),
				"uuid" => __('Restrict the results by uuid.'),
				"publish_timestamp" => __('Restrict the results by the last publish timestamp (newer than).'),
				"timestamp" => __('Restrict the results by the timestamp (last edit). Any event with a timestamp newer than the given timestamp will be returned. In case you are dealing with /attributes as scope, the attribute\'s timestamp will be used for the lookup.'),
				"published" => __('Set whether published or unpublished events should be returned. Do not set the parameter if you want both.'),
				"enforceWarninglist" => __('Remove any attributes from the result that would cause a hit on a warninglist entry.'),
				"to_ids" => __('By default (0) all attributes are returned that match the other filter parameters, irregardless of their to_ids setting. To restrict the returned data set to to_ids only attributes set this parameter to 1. You can only use the special "exclude" setting to only return attributes that have the to_ids flag disabled.'),
				"deleted" => __('If this parameter is set to 1, it will return soft-deleted attributes along with active ones. By using "only" as a parameter it will limit the returned data set to soft-deleted data only.'),
				"includeEventUuid" => __('Instead of just including the event ID, also include the event UUID in each of the attributes.'),
				"event_timestamp" => __('Only return attributes from events that have received a modification after the given timestamp.'),
				"sgReferenceOnly" => __('If this flag is set, sharing group objects will not be included, instead only the sharing group ID is set.'),
				"eventinfo" => __("Filter on the event's info field."),
				"searchall" => __("Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields.")
			),
			'url' => array(
				$baseurl . '/attributes/restSearch',
				$baseurl . '/events/restSearch'
			)
		);
		echo sprintf('<h3>%s</h3>', __('Search'));
		echo sprintf('<p>%s</p>', implode(" ", $data['description']));
		echo sprintf("<pre>%s</pre>", implode("\n", $data['url']));
		foreach ($data['parameters'] as $k => $v) {
			echo sprintf('<span class="bold">%s</span>: %s<br />', $k, $v);
		}
		$description = 'To export all attributes of types ip-src and ip-dst that have a TLP marking and are not marked TLP:red, use the syntax below. String searches are by default exact lookups, but you can use mysql style "%" wildcards to do substring searches.';
		$url = $baseurl . '/attributes/restSearch';
		$headers = array(
			'Accept: application/json',
			'Content-type: application/json',
			'Authorization: ' . $me['authkey']
		);
		$headers = implode("\n", $headers);
		$body = json_encode(
			array(
				'returnFormat' => 'json',
				'type' => array('OR' => array('ip-src', 'ip-dst')),
				'tags' => array('NOT' => array('tlp:red'), 'OR' => array('tlp:%')),
			), JSON_PRETTY_PRINT);
		echo sprintf('<p>%s</p>URL:<pre>%s</pre>Headers:<pre>%s</pre>Body:<pre class="red">%s</pre>', $description, $url, $headers, $body);
	?>

    <h3><?php echo __('CSV Export');?></h3>
    <p><?php echo __('An automatic export of attributes is available as CSV. Only attributes that are flagged "to_ids" will get exported.');?></p>
    <p><?php echo __('You can configure your tools to automatically download the following file');?>:</p>
    <pre><?php echo $baseurl;?>/events/csv/download/</pre>
    <p><?php echo __('You can specify additional flags for CSV exports as follows');?>:</p>
    <pre><?php echo $baseurl;?>/events/csv/download/[eventid]/[ignore]/[tags]/[category]/[type]/[includeContext]/[from]/[to]/[last]/[headerless]/[enforceWarninglist]</pre>
    <p>
    <b>eventid</b>: <?php echo __('Restrict the download to a single event');?><br />
    <b>ignore</b>: <?php echo __('Setting this flag to true will include attributes that are not marked "to_ids".');?><br />
    <b>tags</b>: <?php echo __('To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a \'!\'.
    You can also chain several tag commands together with the \'&amp;&amp;\' operator. Please be aware the colons (:) cannot be used in the tag search.
    Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use');?>:<br />
    </p>
    <p><?php echo __('For example, to only download a csv generated of the "domain" type and the "Network activity" category attributes all events except for the one and further restricting it to events that are tagged "tag1" or "tag2" but not "tag3", only allowing attributes that are IDS flagged use the following syntax');?>:</p>
    <pre><?php echo $baseurl;?>/events/csv/download/false/false/tag1&amp;&amp;tag2&amp;&amp;!tag3/Network%20activity/domain</pre>
    <p>
    <b>category</b>: <?php echo __('The attribute category, any valid MISP attribute category is accepted.');?><br />
    <b>type</b>: <?php echo __('The attribute type, any valid MISP attribute type is accepted.');?><br />
    <b>includeContext</b>: <?php echo __('Include the event data with each attribute.');?><br />
    <b>from</b>: <?php echo __('Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.');?><br />
    <b>to</b>: <?php echo __('Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.');?><br />
    <b>last</b>: <?php echo __('Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m).This filter will use the published timestamp of the event.');?><br />
    <b>headerless</b>: <?php echo __('The CSV created when this setting is set to true will not contain the header row.
    <b>enforceWarninglist</b>: All attributes that have a hit on a warninglist will be excluded.');?>
    </p>
    <p><?php echo __('The keywords false or null should be used for optional empty parameters in the URL.');?></p>
    <p><?php echo __('To export the attributes of all events that are of the type "domain", use the following syntax');?>:</p>
    <pre><?php echo $baseurl;?>/events/csv/download/false/false/false/false/domain</pre>

    <h3><?php echo __('STIX export');?></h3>
    <p><?php echo __('You can export MISP events in Mitre\'s STIX format (to read more about STIX, click <a href="https://stix.mitre.org/">here</a>). The STIX XML export is currently very slow and can lead to timeouts with larger events or collections of events. The JSON return format does not suffer from this issue. Usage');?>:</p>
    <pre><?php echo $baseurl;?>/events/stix/download</pre>
    <p><?php echo __('Search parameters can be passed to the function via URL parameters or by POSTing an XML or JSON object (depending on the return type). The following parameters can be passed to the STIX export tool: <code>id</code>, <code>withAttachments</code>, <code>tags</code>. Both <code>id</code> and <code>tags</code> can use the <code>&amp;&amp;</code> (and) and <code>!</code> (not) operators to build queries. Using the URL parameters, the syntax is as follows');?>:</p>
    <pre><?php echo $baseurl;?>/events/stix/download/[id]/[withAttachments]/[tags]/[from]/[to]/[last]</pre>
    <p>
    <b>id</b>: <?php echo __('The event\'s ID');?><br />
    <b>withAttachments</b>: <?php echo __('Encode attachments where applicable');?><br />
    <b>tags</b>: <?php echo __('To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a \'!\'.
    You can also chain several tag commands together with the \'&amp;&amp;\' operator. Please be aware the colons (:) cannot be used in the tag search.
    Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use');?>:<br />
    </p>
    <pre><?php echo $baseurl;?>/events/stix/download/false/true/tag1&amp;&amp;tag2&amp;&amp;!tag3</pre>
    <p>
    <b>from</b>: <?php echo __('Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.');?><br />
    <b>to</b>: <?php echo __('Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.');?><br />
    <b>last</b>: <?php echo __('Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.');?><br />
    </p>
    <p><?php echo __('You can post an XML or JSON object containing additional parameters in the following formats');?>:</p>
    <p>JSON:</p>
    <pre><?php echo $baseurl;?>/events/stix/download.json</pre>
    <code>{"request": {"id":["!51","!62"],"withAttachment":false,"tags":["APT1","!OSINT"],"from":false,"to":"2015-02-15"}}</code><br /><br />
    <p>XML:</p>
    <pre><?php echo $baseurl;?>/events/stix/download</pre>
    <code>&lt;request&gt;&lt;id&gt;!51&lt;/id&gt;&lt;id&gt;!62&lt;/id&gt;&lt;withAttachment&gt;false&lt;/withAttachment&gt;&lt;tags&gt;APT1&lt;/tags&gt;&lt;tags&gt;!OSINT&lt;/tags&gt;&lt;from&gt;false&lt;/from&gt;&lt;to&gt;2015-02-15&lt;/to&gt;&lt;/request&gt;</code><br /><br />
    <h4><?php echo __('Various ways to narrow down the search results of the STIX export');?></h4>
    <p><?php echo __('For example, to retrieve all events tagged "APT1" but excluding events tagged "OSINT" and excluding events #51 and #62 without any attachments');?>:
    <pre><?php echo $baseurl;?>/events/stix/download/!51&amp;&amp;!62/false/APT1&amp;&amp;!OSINT/2015-02-15</pre>
    <p><?php echo __('To export the same events using a POST request use');?>:</p>
    <pre><?php echo $baseurl;?>/events/stix/download.json</pre>
    <p><?php echo __('Together with this JSON object in the POST message');?>:</p>
    <code>{"request": {"id":["!51","!62"],"tags":["APT1","!OSINT"],"from":"2015-02-15"}}</code><br /><br />
    <p><?php echo __('XML is automagically assumed when using the stix export');?>:</p>
    <pre><?php echo $baseurl;?>/events/stix/download</pre>
    <p><?php echo __('The same search could be accomplished using the following POSTed XML object (note that ampersands need to be escaped, or alternatively separate id and tag elements can be used)');?>: </p>
    <code>&lt;request&gt;&lt;id&gt;!51&lt;/id&gt;&lt;id&gt;!62&lt;/id&gt;&lt;tags&gt;APT1&lt;/tags&gt;&lt;tags&gt;!OSINT&lt;/tags&gt;&lt;from&gt;2015-02-15&lt;/from&gt;&lt;/request&gt;</code>

    <h3><?php echo __('STIX 2.0 export');?></h3>
    <p><?php echo __('You can export MISP events in STIX 2.0 format (to read more about STIX, click <a href="https://stix2.readthedocs.io/">here</a>). ');?>:</p>
    <pre><?php echo $baseurl;?>/events/stix2/download.json</pre>
    <p><?php echo __('Search parameters can be passed to the function via URL parameters or by POSTing a JSON object. The following parameters can be passed to the STIX 2.0 export tool: <code>id</code>, <code>withAttachments</code>, <code>tags</code>. Both <code>id</code> and <code>tags</code> can use the <code>&amp;&amp;</code> (and) and <code>!</code> (not) operators to build queries. Using the URL parameters, the syntax is as follows');?>:</p>
    <pre><?php echo $baseurl;?>/events/stix2/download/[id]/[withAttachments]/[tags]/[from]/[to]/[last]</pre>
    <p>
    <b>id</b>: <?php echo __('The event\'s ID');?><br />
    <b>withAttachments</b>: <?php echo __('Encode attachments where applicable');?><br />
    <b>tags</b>: <?php echo __('To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a \'!\'.
    You can also chain several tag commands together with the \'&amp;&amp;\' operator. Please be aware the colons (:) cannot be used in the tag search.
    Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use');?>:<br />
    </p>
    <pre><?php echo $baseurl;?>/events/stix2/download/false/true/tag1&amp;&amp;tag2&amp;&amp;!tag3</pre>
    <p>
    <b>from</b>: <?php echo __('Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.');?><br />
    <b>to</b>: <?php echo __('Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.');?><br />
    <b>last</b>: <?php echo __('Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.');?><br />
    </p>
    <p><?php echo __('You can post a JSON object containing additional parameters in the following formats');?>:</p>
    <p>JSON:</p>
    <pre><?php echo $baseurl;?>/events/stix2/download.json</pre>
    <code>{"request": {"id":["!51","!62"],"withAttachment":false,"tags":["APT1","!OSINT"],"from":false,"to":"2015-02-15"}}</code><br /><br />
    <h4><?php echo __('Various ways to narrow down the search results of the STIX 2.0 export');?></h4>
    <p><?php echo __('For example, to retrieve all events tagged "APT1" but excluding events tagged "OSINT" and excluding events #51 and #62 without any attachments');?>:
    <pre><?php echo $baseurl;?>/events/stix2/download/!51&amp;&amp;!62/false/APT1&amp;&amp;!OSINT/2015-02-15</pre>
    <p><?php echo __('To export the same events using a POST request use');?>:</p>
    <pre><?php echo $baseurl;?>/events/stix2/download.json</pre>
    <p><?php echo __('Together with this JSON object in the POST message');?>:</p>
    <code>{"request": {"id":["!51","!62"],"tags":["APT1","!OSINT"],"from":"2015-02-15"}}</code><br /><br />

    <h3><?php echo __('RPZ export');?></h3>
    <p<?php echo __('>You can export RPZ zone files for DNS level firewalling by using the RPZ export functionality of MISP. The file generated will include all of the IDS flagged domain, hostname and IP-src/IP-dst attribute values that you have access to.');?></p>
    <p><?php echo __('It is possible to further restrict the exported values using the following filters');?>:</p>
    <p>
        <b>tags</b>: <?php echo __('To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a \'!\'.
            You can also chain several tag commands together with the \'&amp;&amp;\' operator. Please be aware the colons (:) cannot be used in the tag search when passed through the url.
        ');?>
            <?php echo __('Use semicolons instead (the search will automatically search for colons instead)');?>.<br />
        <b>id</b>: <?php echo __('The event\'s ID');?><br />
        <b>from</b>: <?php echo __('Events with the date set to a date after the one specified in the from field (format: 2015-02-03)');?><br />
        <b>to</b>: <?php echo __('Events with the date set to a date before the one specified in the to field (format: 2015-02-03)');?><br />
        <b>enforceWarninglist</b>: <?php echo __('All attributes that have a hit on a warninglist will be excluded.');?>
    </p>
    <p><?php echo __('MISP will inject header values into the zone file as well as define the action taken for each of the values that can all be overriden. By default these values are either the default values shipped with the application, or ones that are overriden by your site administrator. The values are as follows');?>:</p>
    <?php foreach ($rpzSettings as $k => $v): ?>
    <b><?php echo h($k);?></b>: <?php echo h($v);?><br />
    <?php endforeach; ?>
    <p><?php echo __('To override the above values, either use the url parameters as described below');?>:</p>
    <pre><?php echo $baseurl;?>/attributes/rpz/download/[tags]/[eventId]/[from]/[to]/[policy]/[walled_garden]/[ns]/[email]/[serial]/[refresh]/[retry]/[expiry]/[minimum_ttl]/[ttl]</pre>
    <p><?php echo __('or POST an XML or JSON object with the above listed options');?>: </p>
    <code><?php echo h('<request><tags>OSINT&&!OUTDATED</tags><policy>walled-garden</policy><walled_garden>teamliquid.net</walled_garden><refresh>5h</refresh></request>');?></code><br /><br />
    <code>{"request": {"tags": ["OSINT", "!OUTDATED"], "policy": "walled-garden", "walled_garden": "teamliquid.net", "refresh": "5h"}</code>

    <h3><?php echo __('Bro IDS export');?></h3>
    <p><?php echo __('An export of all attributes of a specific bro type to a formatted plain text file. By default only published and IDS flagged attributes are exported.');?></p>
    <p><?php echo __('You can configure your tools to automatically download a file one of the Bro types.');?></p>
    <pre><?php
        foreach (array_keys($broTypes) as $broType) {
            echo $baseurl.'/attributes/bro/download/'.$broType . "\n";
        }
    ?></pre>
    <p><?php echo __('To restrict the results by tags, use the usual syntax. Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead). To get ip values from events tagged tag1 but not tag2 use');?>:</p>
    <pre><?php echo $baseurl.'/attributes/bro/download/ip/tag1&&!tag2'; ?></pre>

    <p><?php echo __('It is possible to restrict the bro exports on based on a set of filters. POST a JSON object or an XML at the Bro API to filter the results.');?></p>
    <pre><?php echo $baseurl.'/attributes/bro/download'; ?></pre>
    <p>JSON:</p>
    <pre><?php
        echo 'Headers' . PHP_EOL;
        echo 'Authorization: ' . h($me['authkey']) . PHP_EOL;
        echo 'Accept: application/json' . PHP_EOL;
        echo 'Content-type: application/json';
    ?></pre>
    <code>{"request": {"type":"ip", "eventid":["!51","!62"],"withAttachment":false,"tags":["APT1","!OSINT"],"from":false,"to":"2015-02-15"}}</code><br /><br />
    <p>XML:</p>
    <pre><?php
        echo 'Headers' . PHP_EOL;
        echo 'Authorization: ' . h($me['authkey']) . PHP_EOL;
        echo 'Accept: application/json' . PHP_EOL;
        echo 'Content-type: application/json';
    ?></pre>
    <code>&lt;request&gt;&lt;type&gt;ip&lt;/type&gt;&lt;eventid&gt;!51&lt;/eventid&gt;&lt;eventid&gt;!62&lt;/eventid&gt;&lt;withAttachment&gt;false&lt;/withAttachment&gt;&lt;tags&gt;APT1&lt;/tags&gt;&lt;tags&gt;!OSINT&lt;/tags&gt;&lt;from&gt;false&lt;/from&gt;&lt;to&gt;2015-02-15&lt;/to&gt;&lt;/request&gt;</code><br /><br />
    <p><?php echo __('Alternatively, it is also possible to pass the filters via the parameters in the URL, though it is highly advised to use POST requests with JSON objects instead. The format is as described below');?>:</p>
    <pre><?php echo $baseurl.'/attributes/bro/download/[type]/[tags]/[event_id]/[allowNonIDS]/[from]/[to]/[last]'; ?></pre>
    <b>type</b>: <?php echo __('The Bro type, any valid Bro type is accepted. The mapping between Bro and MISP types is as follows');?>:<br />
    <pre><?php
        foreach ($broTypes as $key => $value) {
            echo '<b>' . h($key) . '</b>: ' . h($value) . PHP_EOL;
        }
    ?></pre>
    <p>
    <b>tags</b>: <?php echo __('To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a \'!\'.
    You can also chain several tag commands together with the \'&amp;&amp;\' operator. Please be aware the colons (:) cannot be used in the tag search.
    Use semicolons instead (the search will automatically search for colons instead).');?><br />
    <b>event_id</b>: <?php echo __('Restrict the results to the given event IDs.');?> <br />
    <b>allowNonIDS</b>: <?php echo __('Allow attributes to be exported that are not marked as "to_ids".');?><br />
    <b>from</b>: <?php echo __('Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.');?><br />
    <b>to</b>: <?php echo __('Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.');?><br />
    <b>last</b>: <?php echo __('Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.');?><br />
    <b>enforceWarninglist</b>: <?php echo __('All attributes that have a hit on a warninglist will be excluded.');?><br />
    </p>
    <p><?php echo __('The keywords false or null should be used for optional empty parameters in the URL.');?></p>
    <p><?php echo __('For example, to retrieve all attributes for event #5, including non IDS marked attributes too, use the following line');?>:</p>
    <pre><?php echo $baseurl.'/attributes/text/download/all/null/5/true'; ?></pre>

    <h3><?php echo __('Export attributes of event with specified type as XML');?></h3>
    <p><?php echo __('If you want to export all attributes of a pre-defined type that belong to an event, use the following syntax');?>:</p>
    <pre><?php echo $baseurl.'/attributes/returnAttributes/json/[id]/[type]/[sigOnly]'; ?></pre>
    <p><?php echo __('sigOnly is an optional flag that will block all attributes from being exported that don\'t have the IDS flag turned on.
    It is possible to search for several types with the \'&amp;&amp;\' operator and to exclude values with the \'!\' operator.
    For example, to get all IDS signature attributes of type md5 and sha256, but not filename|md5 and filename|sha256 from event 25, use the following');?>: </p>
    <pre><?php echo $baseurl.'/attributes/returnAttributes/download/25/md5&&sha256&&!filename/true';?></pre>

    <h3><?php echo __('Download attachment or malware sample');?></h3>
    <p><?php echo __('If you know the attribute ID of a malware-sample or an attachment, you can download it with the following syntax');?>:</p>
    <pre><?php  echo $baseurl.'/attributes/downloadAttachment/download/[Attribute_id]';?></pre>
    <h3><?php echo __('Download malware sample by hash');?></h3>
    <p><?php echo __('You can also download samples by knowing its MD5 hash. Simply pass the hash along as a JSON/XML object or in the URL (with the URL having overruling the passed objects) to receive a JSON/XML object back with the zipped sample base64 encoded along with some contextual information.');?></p>
    <p><?php echo __('You can also use this API to get all samples from events that contain the passed hash. For this functionality, just pass the "allSamples" flag along. Note that if you are getting all samples from matching events, you can use all supported hash types (%s) for the lookup.</p>', h(implode(', ', $hashTypes)));?>
    <p><?php echo __('You can also get all the samples from an event with a given event ID, by passing along the eventID parameter. Make sure that either an event ID or a hash is passed along, otherwise an error message will be returned. Also, if no hash is set, the allSamples flag will get set automatically.');?></p>
    <pre><?php echo $baseurl.'/attributes/downloadSample/[hash]/[allSamples]/[eventID]';?></pre>
    <p><?php echo __('POST message payload (XML)');?>:</p>
    <p><code>
    <?php echo h("<request><hash>7c12772809c1c0c3deda6103b10fdfa0</hash><allSamples>1</allSamples><eventID>13</eventID</request>"); ?>
    </code></p>
    <p><?php echo __('POST message payload (json)');?>:</p>
    <p><code>
    {"request": {"hash": "7c12772809c1c0c3deda6103b10fdfa0", "allSamples": 1, "eventID": 13}}
    </code></p>
    <p><?php echo __('A quick description of all the parameters in the passed object');?>:</p>
    <b>hash</b>: <?php echo __('A hash in MD5 format. If allSamples is set, this can be any one of the following: %s', h(implode(', ', $hashTypes)));?><br />
    <b>allSamples</b>: <?php echo __('If set, it will return all samples from events that have a match for the hash provided above.');?><br />
    <b>eventID</b>: <?php echo __('If set, it will only fetch data from the given event ID.');?><br />
    <h3><?php echo __('Upload malware samples using the "Upload Sample" API');?></h3>
    <pre><?php echo $baseurl.'/events/upload_sample/[Event_id]';?></pre>
    <p><?php echo __('This API will allow you to populate an event that you have modify rights to with malware samples (and all related hashes). Alternatively, if you do not supply an event ID, it will create a new event for you.');?><br />
    <?php echo __('The files have to be base64 encoded and POSTed as explained below. All samples will be zipped and password protected (with the password being "infected"). The hashes of the original file will be captured as additional attributes.');?><br />
    <?php echo __('The event ID is optional. MISP will accept either a JSON or an XML object posted to the above URL.');?></p>
    <p><b><?php echo __('The general structure of the expected objects is as follows');?>:</b></p>
    <code>{"request": {"files": [{"filename": filename1, "data": base64encodedfile1}, {"filename": filename2, "data": base64encodedfile2}], "optional_parameter1", "optional_parameter2", "optional_parameter3"}}</code>
    <br /><br />
    <p><b>JSON:</b></p>
    <code>{"request":{"files": [{"filename": "test1.txt", "data": "dGVzdA=="}, {"filename": "test2.txt", "data": "dGVzdDI="}], "distribution": 1, "info" : "test", "event_id": 15}}</code>
    <br /><br />
    <p><b>XML:</b></p>
    <code><?php echo h("<request><files><filename>test3.txt</filename><data>dGVzdA==</data></files><files><filename>test4.txt</filename><data>dGVzdDI=</data></files><info>test</info><distribution>1</distribution><event_id>15</event_id></request>");?></code>
    <br /><br />
    <p><b><?php echo __('The following optional parameters are expected');?>:</b></p>
    <p><b>event_id</b>: <?php echo __('The Event\'s ID is optional. It can be either supplied via the URL or the POSTed object, but the URL has priority if both are provided. Not supplying an event ID will cause MISP to create a single new event for all of the POSTed malware samples. You can define the default settings for the event, otherwise a set of default settings will be used.');?><br />
    <b>distribution</b>: <?php echo __('The distribution setting used for the attributes and for the newly created event, if relevant. [0-3]');?><br />
    <b>to_ids</b>: <?php echo __('You can flag all attributes created during the transaction to be marked as "to_ids" or not.');?><br />
    <b>category</b>: <?php echo __('The category that will be assigned to the uploaded samples. Valid options are: Payload delivery, Artefacts dropped, Payload Installation, External Analysis.');?><br />
    <b>info</b>: <?php echo __('Used to populate the event info field if no event ID supplied. Alternatively, if not set, MISP will simply generate a message showing that it\'s a malware sample collection generated on the given day.');?><br />
    <b>analysis</b>: <?php echo __('The analysis level of the newly created event, if applicable. [0-2]');?><br />
    <b>threat_level_id</b>: <?php echo __('The threat level ID of the newly created event, if applicable. [0-3]');?><br />
    <b>comment</b>: <?php echo __('This will populate the comment field of any attribute created using this API.');?><br />
    <h3><?php echo __('Add or remove tags from events');?></h3>
    <p><?php echo __('You can add or remove an existing tag from an event in the following way');?>:</p>
    <pre><?php echo $baseurl.'/events/addTag'; ?></pre>
    <pre><?php  echo $baseurl.'/events/removeTag'; ?></pre>
    <p><?php echo __('Just POST a json object in the following format (to the appropriate API depending on whether you want to add or delete a tag from an event)');?>:</p>
    <code>{"event":228, "tag":8}</code><br /><br />
    <p><?php echo __('Where "tag" is the ID of the tag. You can also use the name of the tag the following way');?>:</p>
    <code>{"event":228, "tag":"OSINT"}</code>
    <h3><?php echo __('Proposals and the API');?></h3>
    <p><?php echo __('You can interact with the proposals via the API directly since version 2.3.148');?></p>

    <table style="width:900px;">
    <tr>
        <th style="text-align:left;"><?php echo __('HTTP');?></th>
        <th style="text-align:left;"><?php echo __('URL');?></th>
        <th style="text-align:left;"><?php echo __('Explanation');?></th>
        <th style="text-align:left;"><?php echo __('Expected Payload');?></th>
        <th style="text-align:left;"><?php echo __('Response');?></th>
    </tr>
    <tr>
        <td style="width:45px;">GET</td>
        <td style="width:250px;">/shadow_attributes/view/[proposal_id]</td>
        <td><?php echo __('View a proposal');?></td>
        <td><?php echo __('N/A');?></td>
        <td><?php echo __('ShadowAttribute object');?></td>
    </tr>
    <tr>
        <td style="width:45px;">GET</td>
        <td style="width:250px;">/shadow_attributes/index</td>
        <td><?php echo __('View all proposal of my org\'s events');?></td>
        <td><?php echo __('N/A');?></td>
        <td><?php echo __('ShadowAttribute objects');?></td>
    </tr>
    <tr>
        <td style="width:45px;">GET</td>
        <td style="width:250px;">/shadow_attributes/index/[event_id]</td>
        <td><?php echo __('View all proposals of an event');?></td>
        <td><?php echo __('N/A');?></td>
        <td><?php echo __('ShadowAttribute objects');?></td>
    </tr>
    <tr>
        <td style="width:45px;">POST</td>
        <td style="width:250px;">/shadow_attributes/add/[event_id]</td>
        <td style="width:250px;"><?php echo __('Propose a new attribute to an event');?></td>
        <td><?php echo __('ShadowAttribute object');?></td>
        <td><?php echo __('ShadowAttribute object');?></td>
    </tr>
    <tr>
        <td style="width:45px;">POST</td>
        <td style="width:250px;">/shadow_attributes/edit/[attribute_id]</td>
        <td style="width:250px;"><?php echo __('Propose an edit to an attribute');?></td>
        <td><?php echo __('ShadowAttribute object');?></td>
        <td><?php echo __('ShadowAttribute object');?></td>
    </tr>
    <tr>
        <td style="width:45px;">POST</td>
        <td style="width:250px;">/shadow_attributes/accept/[proposal_id]</td>
        <td style="width:250px;"><?php echo __('Accept a proposal');?></td>
        <td><?php echo __('N/A');?></td>
        <td><?php echo __('Message');?></td>
    </tr>
    <tr>
        <td style="width:45px;">POST</td>
        <td style="width:250px;">/shadow_attributes/discard/[proposal_id]</td>
        <td style="width:250px;"><?php echo __('Discard a proposal');?></td>
        <td><?php echo __('N/A');?></td>
        <td><?php echo __('Message');?></td>
    </tr>
    </table><br />
    <p><?php echo __('When posting a shadow attribute object, use the following formats');?></p>
    <p><b>JSON</b></p>
    <code><?php echo h('{"request": {"ShadowAttribute": {"value": "5.5.5.5", "to_ids": false, "type": "ip-dst", "category": "Network activity"}}}');?></code><br /><br />
    <p><b>XML</b></p>
    <code><?php echo h('<request><ShadowAttribute><value>5.5.5.5</value><to_ids>0</to_ids><type>ip-src</type><category>Network activity</category></ShadowAttribute></request>');?></code><br /><br />
    <p><?php echo __('None of the above fields are mandatory, but at least one of them has to be provided.');?></p>

    <h3><?php echo __('Filtering event metadata');?></h3>
    <p><?php echo __('As described in the REST section, it is possible to retrieve a list of events along with their metadata by sending a GET request to the /events API. However, this API in particular is a bit more versatile. You can pass search parameters along to search among the events on various fields and retrieve a list of matching events (along with their metadata). Use the following URL');?>:<br />
    <?php
        echo $baseurl.'/events/index';
    ?>
    <?php echo __('POST a JSON object with the desired lookup fields and values to receive a JSON back.<br />
    An example for a valid lookup');?>:</p>
    <b>URL</b>: <?php echo $baseurl.'/events/index'; ?><br />
    <b>Headers</b>:<br />
    <pre><?php
        echo 'Authorization: ' . $me['authkey'] . PHP_EOL;
        echo 'Accept: application/json' . PHP_EOL;
        echo 'Content-type: application/json';
    ?></pre>
    <b>Body</b>:
    <code>{"searcheventinfo":"Locky", "searchpublished":1, "searchdistribution":!0}</code><br /><br />
    <p><?php echo __('The above would return any event that is published, not restricted to your organisation only that has the term "Locky" in its event description. You can use exclamation marks to negate a value wherever appropriate.');?></p>
    <p><b><?php echo __('The list of valid parameters');?>:</b></p>
    <p><b>searchpublished</b>: <?php echo __('Filters on published or unpublished events [0,1] - negatable');?><br />
    <b>searcheventinfo</b>: <?php echo __('Filters on strings found in the event info - negatable');?><br />
    <b>searchtag</b>: <?php echo __('Filters on attached tag names - negatable');?><br />
    <b>searcheventid</b>: <?php echo __('Filters on specific event IDs - negatable');?><br />
    <b>searchthreatlevel</b>: <?php echo __('Filters on a given event threat level [1,2,3,4] - negatable');?><br />
    <b>searchdistribution</b>: <?php echo __('Filters on the distribution level [0,1,2,3] - negatable');?><br />
    <b>searchanalysis</b>: <?php echo __('Filters on the given analysis phase of the event [0,1,2] - negatable');?><br />
    <b>searchattribute</b>: <?php echo __('Filters on a contained attribute value - negatable');?><br />
    <b>searchorg</b>: <?php echo __('Filters on the creator organisation - negatable');?><br />
    <b>searchemail</b>: <?php echo __('Filters on the creator user\'s email address (admin only) - negatable');?><br />
    <b>searchDatefrom</b>: <?php echo __('Filters on the date, anything newer than the given date in YYYY-MM-DD format is taken - non-negatable');?><br />
    <b>searchDateuntil</b>: <?php echo __('Filters on the date, anything older than the given date in YYYY-MM-DD format is taken - non-negatable');?><br /></p>
    <?php
        foreach ($command_line_functions as $clusterRef => $cluster) {
            echo sprintf('<a id="%s"></a><h3>%s</h3>', $clusterRef, $cluster['header']);
            echo sprintf('<p>%s:<br />', $cluster['description']);
            foreach ($cluster['data'] as $commandName => $command) {
                echo '<b>' . Inflector::humanize($commandName) . '</b>: <code>' . $command . '</code><br />';
            }
        }
    ?>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'automation'));
?>
