<div class="event index">
<h2>Automation</h2>
<p>Automation functionality is designed to automatically generate signatures for intrusion detection systems. To enable signature generation for a given attribute, Signature field of this attribute must be set to Yes.
Note that not all attribute types are applicable for signature generation, currently we only support NIDS signature generation for IP, domains, host names, user agents etc., and hash list generation for MD5/SHA1 values of file artifacts. Support for more attribute types is planned.
To to make this functionality available for automated tools an authentication key is used. This makes it easier for your tools to access the data without further form-based-authentiation.<br/>
<strong>Make sure you keep that key secret as it gives access to the entire database !</strong></p>
<p>Your current key is: <code><?php echo $me['authkey'];?></code>.
You can <?php echo $this->Html->link('reset', array('controller' => 'users', 'action' => 'resetauthkey', 'me'));?> this key.
</p>
<p style="color:red;">Since version 2.2 the usage of the authentication key in the url is deprecated. Instead, pass the auth key in an Authorization header in the request. The legacy option of having the auth key in the url is temporarily still supported but not recommended.</p>
<p>Please use the use the following header:<br />
<code>Authorization: <?php echo $me['authkey']; ?></code></p>
<h3>XML Export</h3>
<p>An automatic export of all events and attributes <small>(except file attachments)</small> is available under a custom XML format.</p>
<p>You can configure your tools to automatically download the following file:</p>
<pre><?php echo $baseurl;?>/events/xml/download</pre>
<p>If you only want to fetch a specific event append the eventid number:</p>
<pre><?php echo $baseurl;?>/events/xml/download/1</pre>
<p>You can post an XML or JSON object containing additional parameters in the following formats:</p>
<p>JSON:</p>
<pre><?php echo $baseurl;?>/events/xml/download.json</pre>
<code>{"request": {"eventid":["!51","!62"],"withAttachment":false,"tags":["APT1","!OSINT"],"from":false,"to":"2015-02-15"}}</code><br /><br />
<p>XML:</p>
<pre><?php echo $baseurl;?>/events/xml/download</pre>
<code>&lt;request&gt;&lt;eventid&gt;!51&lt;/eventid&gt;&lt;eventid&gt;!62&lt;/eventid&gt;&lt;withAttachment&gt;false&lt;/withAttachment&gt;&lt;tags&gt;APT1&lt;/tags&gt;&lt;tags&gt;!OSINT&lt;/tags&gt;&lt;from&gt;false&lt;/from&gt;&lt;to&gt;2015-02-15&lt;/to&gt;&lt;/request&gt;</code><br /><br />
<p>The xml download also accepts two additional the following optional parameters in the url: </p>
<pre><?php echo $baseurl;?>/events/xml/download/[eventid]/[withattachments]/[tags]/[from]/[to]/[last]</pre>
<p>
<b>eventid</b>: Restrict the download to a single event<br />
<b>withattachments</b>: A boolean field that determines whether attachments should be encoded and a second parameter that controls the eligible tags. <br />
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use:<br />
</p>
<pre><?php echo $baseurl;?>/events/xml/download/false/true/tag1&amp;&amp;tag2&amp;&amp;!tag3</pre>
<p>
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.<br />
</p>
<p>The keywords false or null should be used for optional empty parameters in the URL.</p>
<p>Also check out the <a href="<?php echo $baseurl;?>/pages/display/doc/using_the_system#rest">User Guide</a> to read about the REST API.</p>
<p></p>
<h3>CSV Export</h3>
<p>An automatic export of attributes is available as CSV. Only attributes that are flagged "to_ids" will get exported.</p>
<p>You can configure your tools to automatically download the following file:</p>
<pre><?php echo $baseurl;?>/events/csv/download/</pre>
<p>You can specify additional flags for CSV exports as follows::</p>
<pre><?php echo $baseurl;?>/events/csv/download/[eventid]/[ignore]/[tags]/[category]/[type]/[includeContext]/[from]/[to]/[last]/[headerless]/[enforceWarninglist]</pre>
<p>
<b>eventid</b>: Restrict the download to a single event<br />
<b>ignore</b>: Setting this flag to true will include attributes that are not marked "to_ids".<br />
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use:<br />
</p>
<p>For example, to only download a csv generated of the "domain" type and the "Network activity" category attributes all events except for the one and further restricting it to events that are tagged "tag1" or "tag2" but not "tag3", only allowing attributes that are IDS flagged use the following syntax:</p>
<pre><?php echo $baseurl;?>/events/csv/download/false/false/tag1&amp;&amp;tag2&amp;&amp;!tag3/Network%20activity/domain</pre>
<p>
<b>category</b>: The attribute category, any valid MISP attribute category is accepted.<br />
<b>type</b>: The attribute type, any valid MISP attribute type is accepted.<br />
<b>includeContext</b>: Include the event data with each attribute.<br />
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m).This filter will use the published timestamp of the event.<br />
<b>headerless</b>: The CSV created when this setting is set to true will not contain the header row.
<b>enforceWarninglist</b>: All attributes that have a hit on a warninglist will be excluded.
</p>
<p>The keywords false or null should be used for optional empty parameters in the URL.</p>
<p>To export the attributes of all events that are of the type "domain", use the following syntax:</p>
<pre><?php echo $baseurl;?>/events/csv/download/false/false/false/false/domain</pre>

<h3>NIDS rules export</h3>
<p>Automatic export of all network related attributes is available under the Snort rule format. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported.</p>
<p>You can configure your tools to automatically download the following file:</p>
<pre><?php echo $baseurl;?>/events/nids/suricata/download
<?php echo $baseurl;?>/events/nids/snort/download</pre>
<p>The full API syntax is as follows:</p>
<pre><?php echo $baseurl;?>/events/nids/[format]/download/[eventid]/[frame]/[tags]/[from]/[to]/[last]/[type]/[enforceWarninglist]/[includeAllTags]</pre>
<p>
<b>format</b>: The export format, can be "suricata" or "snort"<br />
<b>eventid</b>: Restrict the download to a single event<br />
<b>frame</b>: Some commented out explanation framing the data. The reason to disable this would be if you would like to concatenate a list of exports from various select events in order to avoid unnecasary duplication of the comments.<br />
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use:<br />
<pre><?php echo $baseurl;?>/events/nids/snort/download/false/false/tag1&amp;&amp;tag2&amp;&amp;!tag3</pre>
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 6d or 12h or 30m). This filter will use the published timestamp of the event.<br />
<b>type</b>: Restrict the export to only use the given types.<br />
<b>enforceWarninglist</b>: All attributes that have a hit on a warninglist will be excluded.<br />
<b>includeAllTags</b>: All tags will be included even if not exportable.<br />
<p>The keywords false or null should be used for optional empty parameters in the URL.</p>
<p>An example for a suricata export for all events excluding those tagged tag1, without all of the commented information at the start of the file would look like this:</p>
<pre><?php echo $baseurl;?>/events/nids/suricata/download/null/true/!tag1</pre>
<p>Administration is able to maintain a white-list containing host, domain name and IP numbers to exclude from the NIDS export.</p>

<h3>Hash database export</h3>
<p>Automatic export of MD5/SHA1 checksums contained in file-related attributes. This list can be used to feed forensic software when searching for suspicious files. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported.</p>
<p>You can configure your tools to automatically download the following files:</p>
<h4>md5</h4>
<pre><?php echo $baseurl;?>/events/hids/md5/download</pre>
<h4>sha1</h4>
<pre><?php echo $baseurl;?>/events/hids/sha1/download</pre>
<p>The API's full format is as follows: </p>
<pre><?php echo $baseurl;?>/events/hids/[format]/download/[tags]/[from]/[to]/[last]/[enforceWarninglist]</pre>
<b>format</b>: The export format, can be "md5" or "sha1"<br />
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use:<br />
<pre><?php echo $baseurl;?>/events/hids/md5/download/tag1&amp;&amp;tag2&amp;&amp;!tag3</pre>
<p>
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event. <br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.<br />
<b>enforceWarninglist</b>: All attributes that have a hit on a warninglist will be excluded.<br />
</p>
<p>The keywords false or null should be used for optional empty parameters in the URL.</p>
<p>For example, to only show sha1 values from events tagged tag1, use:</p>
<pre><?php echo $baseurl;?>/events/hids/sha1/download/tag1</pre>

<h3>STIX export</h3>
<p>You can export MISP events in Mitre's STIX format (to read more about STIX, click <a href="https://stix.mitre.org/">here</a>). The STIX XML export is currently very slow and can lead to timeouts with larger events or collections of events. The JSON return format does not suffer from this issue. Usage:</p>
<pre><?php echo $baseurl;?>/events/stix/download</pre>
<p>Search parameters can be passed to the function via url parameters or by POSTing an xml or json object (depending on the return type). The following parameters can be passed to the STIX export tool: <code>id</code>, <code>withAttachments</code>, <code>tags</code>. Both <code>id</code> and <code>tags</code> can use the <code>&amp;&amp;</code> (and) and <code>!</code> (not) operators to build queries. Using the url parameters, the syntax is as follows:</p>
<pre><?php echo $baseurl;?>/events/stix/download/[id]/[withAttachments]/[tags]/[from]/[to]/[last]</pre>
<p>
<b>id</b>: The event's ID<br />
<b>withAttachments</b>: Encode attachments where applicable<br />
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use:<br />
</p>
<pre><?php echo $baseurl;?>/events/stix/download/false/true/tag1&amp;&amp;tag2&amp;&amp;!tag3</pre>
<p>
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.<br />
</p>
<p>You can post an XML or JSON object containing additional parameters in the following formats:</p>
<p>JSON:</p>
<pre><?php echo $baseurl;?>/events/stix/download.json</pre>
<code>{"request": {"id":["!51","!62"],"withAttachment":false,"tags":["APT1","!OSINT"],"from":false,"to":"2015-02-15"}}</code><br /><br />
<p>XML:</p>
<pre><?php echo $baseurl;?>/events/stix/download</pre>
<code>&lt;request&gt;&lt;id&gt;!51&lt;/id&gt;&lt;id&gt;!62&lt;/id&gt;&lt;withAttachment&gt;false&lt;/withAttachment&gt;&lt;tags&gt;APT1&lt;/tags&gt;&lt;tags&gt;!OSINT&lt;/tags&gt;&lt;from&gt;false&lt;/from&gt;&lt;to&gt;2015-02-15&lt;/to&gt;&lt;/request&gt;</code><br /><br />
<h4>Various ways to narrow down the search results of the STIX export</h4>
<p>For example, to retrieve all events tagged "APT1" but excluding events tagged "OSINT" and excluding events #51 and #62 without any attachments:
<pre><?php echo $baseurl;?>/events/stix/download/!51&amp;&amp;!62/false/APT1&amp;&amp;!OSINT/2015-02-15</pre>
<p>To export the same events using a POST request use:</p>
<pre><?php echo $baseurl;?>/events/stix/download.json</pre>
<p>Together with this JSON object in the POST message:</p>
<code>{"request": {"id":["!51","!62"],"tags":["APT1","!OSINT"],"from":"2015-02-15"}}</code><br /><br />
<p>XML is automatically assumed when using the stix export:</p>
<pre><?php echo $baseurl;?>/events/stix/download</pre>
<p>The same search could be accomplished using the following POSTed XML object (note that ampersands need to be escaped, or alternatively separate id and tag elements can be used): </p>
<code>&lt;request&gt;&lt;id&gt;!51&lt;/id&gt;&lt;id&gt;!62&lt;/id&gt;&lt;tags&gt;APT1&lt;/tags&gt;&lt;tags&gt;!OSINT&lt;/tags&gt;&lt;from&gt;2015-02-15&lt;/from&gt;&lt;/request&gt;</code>

<h3>RPZ export</h3>
<p>You can export RPZ zone files for DNS level firewalling by using the RPZ export functionality of MISP. The file generated will include all of the IDS flagged domain, hostname and IP-src/IP-dst attribute values that you have access to.</p>
<p>It is possible to further restrict the exported values using the following filters:</p>
<p>
	<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
	You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search when passed through the url.
	Use semicolons instead (the search will automatically search for colons instead).<br />
	<b>id</b>: The event's ID<br />
	<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-03)<br />
	<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-03)<br />
	<b>enforceWarninglist</b>: All attributes that have a hit on a warninglist will be excluded.
</p>
<p>MISP will inject header values into the zone file as well as define the action taken for each of the values that can all be overriden. By default these values are either the default values shipped with the application, or ones that are overriden by your site administrator. The values are as follows:</p>
<?php foreach ($rpzSettings as $k => $v): ?>
<b><?php echo h($k);?></b>: <?php echo h($v);?><br />
<?php endforeach; ?>
<p>To override the above values, either use the url parameters as described below:</p>
<pre><?php echo $baseurl;?>/attributes/rpz/download/[tags]/[eventId]/[from]/[to]/[policy]/[walled_garden]/[ns]/[email]/[serial]/[refresh]/[retry]/[expiry]/[minimum_ttl]/[ttl]</pre>
<p>or POST an XML or JSON object with the above listed options: </p>
<code><?php echo h('<request><tags>OSINT&&!OUTDATED</tags><policy>walled-garden</policy><walled_garden>teamliquid.net</walled_garden><refresh>5h</refresh></request>');?></code><br /><br />
<code>{"request": {"tags": ["OSINT", "!OUTDATED"], "policy": "walled-garden", "walled_garden": "teamliquid.net", "refresh": "5h"}</code>

<h3>Text export</h3>
<p>An export of all attributes of a specific type to a plain text file. By default only published and IDS flagged attributes are exported.</p>
<p>You can configure your tools to automatically download the following files:</p>
<pre>
<?php
foreach ($sigTypes as $sigType) {
	echo $baseurl.'/attributes/text/download/'.$sigType . "\n";
}
?>
</pre>
<p>To restrict the results by tags, use the usual syntax. Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead). To get ip-src values from events tagged tag1 but not tag2 use:</p>
<pre>
<?php
	echo $baseurl.'/attributes/text/download/ip-src/tag1&&!tag2';
?>
</pre>

<p>As of version 2.3.38, it is possible to restrict the text exports on two additional flags. The first allows the user to restrict based on event ID, whilst the second is a boolean switch allowing non IDS flagged attributes to be exported. Additionally, choosing "all" in the type field will return all eligible attributes. </p>
<pre>
<?php
	echo $baseurl.'/attributes/text/download/[type]/[tags]/[event_id]/[allowNonIDS]/[from]/[to]/[last]/[enforceWarninglist]/[allowNotPublished]';
?>
</pre>
<b>type</b>: The attribute type, any valid MISP attribute type is accepted.<br />
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
<b>eventId</b>: Only export the attributes of the given event ID<br />
<b>allowNonIDS</b>: Include attributes that are not marked to_ids, even if they would normally be excluded. Also overrides the whitelist functionality.<br />
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event. <br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.<br />
<b>enforceWarninglist</b>: All attributes that have a hit on a warninglist will be excluded.<br />
<b>allowNotPublished</b>: Include not published Events.</b>
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use:<br />
<pre>
<?php
	echo $baseurl.'/attributes/text/download/all/tag1&amp;&amp;tag2&amp;&amp;!tag3';
?>
</pre>
<h3>Bro IDS export</h3>
<p>An export of all attributes of a specific bro type to a formatted plain text file. By default only published and IDS flagged attributes are exported.</p>
<p>You can configure your tools to automatically download a file one of the Bro types.</p>
<pre>
<?php
foreach (array_keys($broTypes) as $broType) {
	echo $baseurl.'/attributes/bro/download/'.$broType . "\n";
}
?>
</pre>
<p>To restrict the results by tags, use the usual syntax. Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead). To get ip values from events tagged tag1 but not tag2 use:</p>
<pre>
<?php
	echo $baseurl.'/attributes/bro/download/ip/tag1&&!tag2';
?>
</pre>

<p>It is possible to restrict the bro exports on based on a set of filters. POST a JSON object or an XML at the Bro API to filter the results.</p>
<pre>
<?php
	echo $baseurl.'/attributes/bro/download';
?>
</pre>
<p>JSON:</p>
<pre>Headers
Authorization: [your API key]
Accept: application/json
Content-type: application/json
</pre>
<code>{"request": {"type":"ip", "eventid":["!51","!62"],"withAttachment":false,"tags":["APT1","!OSINT"],"from":false,"to":"2015-02-15"}}</code><br /><br />
<p>XML:</p>
<pre>Headers
Authorization: [your API key]
Accept: application/json
Content-type: application/json
</pre>
<code>&lt;request&gt;&lt;type&gt;ip&lt;/type&gt;&lt;eventid&gt;!51&lt;/eventid&gt;&lt;eventid&gt;!62&lt;/eventid&gt;&lt;withAttachment&gt;false&lt;/withAttachment&gt;&lt;tags&gt;APT1&lt;/tags&gt;&lt;tags&gt;!OSINT&lt;/tags&gt;&lt;from&gt;false&lt;/from&gt;&lt;to&gt;2015-02-15&lt;/to&gt;&lt;/request&gt;</code><br /><br />
<p>Alternatively, it is also possible to pass the filters via the parameters in the URL, though it is highly advised to use POST requests with JSON objects instead. The format is as described below:</p>
<pre>
<?php
	echo $baseurl.'/attributes/bro/download/[type]/[tags]/[event_id]/[allowNonIDS]/[from]/[to]/[last]';
?>
</pre>
<b>type</b>: The Bro type, any valid Bro type is accepted. The mapping between Bro and MISP types is as follows:<br />
<pre>
<?php
	foreach ($broTypes as $key => $value) {
		echo '<b>' . h($key) . '</b>: ' . h($value) . PHP_EOL;
	}
?>
</pre>
<p>
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead).<br />
<b>event_id</b>: Restrict the results to the given event IDs. <br />
<b>allowNonIDS</b>: Allow attributes to be exported that are not marked as "to_ids".<br />
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.<br />
<b>enforceWarninglist</b>: All attributes that have a hit on a warninglist will be excluded.<br />
</p>
<p>The keywords false or null should be used for optional empty parameters in the URL.</p>
<p>For example, to retrieve all attributes for event #5, including non IDS marked attributes too, use the following line:</p>
<pre>
<?php
	echo $baseurl.'/attributes/text/download/all/null/5/true';
?>
</pre>

<h3>Searches with JSON/XML/OpenIOC results</h3>
<p>It is possible to search the database for attributes based on a list of criteria. </p>
<p>To return an event or a list of events in a desired format, use the following syntax:</p>
<pre>
<?php
	echo $baseurl.'/events/restSearch/[format]/[value]/[type]/[category]/[org]/[tag]/[quickfilter]/[from]/[to]/[last]/[event_id]/[withAttachments]/[metadata]/[uuid]/[publish_timestamp]/[timestamp]/[published]/[enforceWarninglist]';
?>
</pre>
<b>format</b>: Set the return format of the search (Currently supported: json, xml, openioc - more formats coming soon).<br />
<b>value</b>: Search for the given value in the attributes' value field.<br />
<b>type</b>: The attribute type, any valid MISP attribute type is accepted.<br />
<b>category</b>: The attribute category, any valid MISP attribute category is accepted.<br />
<b>org</b>: Search by the creator organisation by supplying the organisation idenfitier. <br />
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
To filter on several values for the same parameter, simply use arrays, such as in the following example: <br />
<code>{"value":["tag1", "tag2", "!tag3"]}</code><br />
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead). For example, to include tag1 and tag2 but exclude tag3 you would use:<br />
<pre>
<?php
	echo $baseurl.'/events/restSearch/json/null/null/null/null/tag1&amp;&amp;tag2&amp;&amp;!tag3';
?>
</pre>
<b>quickfilter</b>: Enabling this (by passing "1" as the argument) will make the search ignore all of the other arguments, except for the auth key and value. MISP will return an xml / json (depending on the header sent) of all events that have a sub-string match on value in the event info, event orgc, or any of the attribute value1 / value2 fields, or in the attribute comment. <br />
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.<br />
<b>eventid</b>: The events that should be included / excluded from the search<br />
<b>withAttachments</b>: If set, encodes the attachments / zipped malware samples as base64 in the data field within each attribute<br />
<b>metadata</b>: Only the metadata (event, tags, relations) is returned, attributes and proposals are omitted.<br />
<b>uuid</b>: Restrict the results by uuid.<br />
<b>publish_timestamp</b>: Restrict the results by the last publish timestamp (newer than).<br />
<b>timestamp</b>: Restrict the results by the timestamp (last edit). Any event with a timestamp newer than the given timestamp will be returned.<br />
<b>published</b>: Set whether published or unpublished events should be returned. Do not set the parameter if you want both.<br />
<b>enforceWarninglist</b>: Remove any attributes from the result that would cause a hit on a warninglist entry.<br />
<p>The keywords false or null should be used for optional empty parameters in the URL.</p>
<p>For example, to find any event with the term "red october" mentioned, use the following syntax (the example is shown as a POST request instead of a GET, which is highly recommended. GET requests are problematic and deprecated.):</p>
<p>POST to:</p>
<pre>
<?php
	echo $baseurl.'/events/restSearch/json';
?>
</pre>
<p>POST message payload (XML):</p>
<p><code><?php echo h('<request><value>red october</value><searchall>1</searchall><eventid>!15</eventid></request>'); ?></code></p>
<p>POST message payload (json):</p>
<p><code>{"request": {"value":"red october","searchall":1,"eventid":"!15"}}</code></p>
<p>To just return a list of attributes, use the following syntax:</p>
<b>value</b>: Search for the given value in the attributes' value field.<br />
<b>type</b>: The attribute type, any valid MISP attribute type is accepted.<br />
<b>category</b>: The attribute category, any valid MISP attribute category is accepted.<br />
<b>org</b>: Search by the creator organisation by supplying the organisation idenfitier. <br />
<b>tags</b>: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'.
You can also chain several tag commands together with the '&amp;&amp;' operator. Please be aware the colons (:) cannot be used in the tag search.
Use semicolons instead (the search will automatically search for colons instead).<br />
<b>from</b>: Events with the date set to a date after the one specified in the from field (format: 2015-02-15)<br />
<b>to</b>: Events with the date set to a date before the one specified in the to field (format: 2015-02-15)<br />
<b>last</b>: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.<br />
<b>eventid</b>: The events that should be included / excluded from the search<br />
<b>withAttachments</b>: If set, encodes the attachments / zipped malware samples as base64 in the data field within each attribute<br />
<b>uuid</b>: Restrict the results by uuid.<br />
<b>publish_timestamp</b>: Restrict the results by the last publish timestamp (newer than).<br />
<b>published</b>: Set whether published or unpublished events should be returned. Do not set the parameter if you want both.<br />
<b>timestamp</b>: Restrict the results by the timestamp (of the attribute). Any attributes with a timestamp newer than the given timestamp will be returned.<br />
<b>enforceWarninglist</b>: Remove any attributes from the result that would cause a hit on a warninglist entry.<br /><br />
<p>The keywords false or null should be used for optional empty parameters in the URL. Keep in mind, this is only needed if you use the deprecated URL parameters.</p>
<pre>
<?php
	echo $baseurl.'/attributes/restSearch/json/[value]/[type]/[category]/[org]/[tag]/[from]/[to]/[last]/[eventid]/[withAttachments]';
?>
</pre>
<p>value, type, category and org are optional. It is possible to search for several terms in each category by joining them with the '&amp;&amp;' operator. It is also possible to negate a term with the '!' operator. Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead).
For example, in order to search for all attributes created by your organisation that contain 192.168 or 127.0 but not 0.1 and are of the type ip-src, excluding the events that were tagged tag1 use the following syntax:</p>
<pre><?php echo $baseurl.'/attributes/restSearch/download/192.168&&127.0&&!0.1/ip-src/false/' . $me['Organisation']['name'] . '/!tag1';?></pre>
<p>You can also use search for IP addresses using CIDR. Make sure that you use '|' (pipe) instead of '/' (slashes). Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead). See below for an example: </p>
<pre>
<?php
	echo $baseurl.'/attributes/restSearch/openioc/192.168.1.1|16/ip-src/null/' . $me['Organisation']['name'];
?>
</pre>
<h3>Export attributes of event with specified type as XML</h3>
<p>If you want to export all attributes of a pre-defined type that belong to an event, use the following syntax:</p>
<pre>
<?php
	echo $baseurl.'/attributes/returnAttributes/json/[id]/[type]/[sigOnly]';
?>
</pre>
<p>sigOnly is an optional flag that will block all attributes from being exported that don't have the IDS flag turned on.
It is possible to search for several types with the '&amp;&amp;' operator and to exclude values with the '!' operator.
For example, to get all IDS signature attributes of type md5 and sha256, but not filename|md5 and filename|sha256 from event 25, use the following: </p>
<pre>
<?php
	echo $baseurl.'/attributes/returnAttributes/download/25/md5&&sha256&&!filename/true';
?>
</pre>

<h3>Download attachment or malware sample</h3>
<p>If you know the attribute ID of a malware-sample or an attachment, you can download it with the following syntax:</p>
<pre>
<?php
	echo $baseurl.'/attributes/downloadAttachment/download/[Attribute_id]';
?>
</pre>
<h3>Download malware sample by hash</h3>
<p>You can also download samples by knowing its MD5 hash. Simply pass the hash along as a JSON/XML object or in the URL (with the URL having overruling the passed objects) to receive a JSON/XML object back with the zipped sample base64 encoded along with some contextual information.</p>
<p>You can also use this API to get all samples from events that contain the passed hash. For this functionality, just pass the "allSamples" flag along. Note that if you are getting all samples from matching events, you can use all supported hash types (<?php echo h(implode(', ', $hashTypes)); ?>) for the lookup.</p>
<p>You can also get all the samples from an event with a given event ID, by passing along the eventID parameter. Make sure that either an event ID or a hash is passed along, otherwise an error message will be returned. Also, if no hash is set, the allSamples flag will get set automatically.</p>
<pre>
<?php
	echo $baseurl.'/attributes/downloadSample/[hash]/[allSamples]/[eventID]';
?>
</pre>
<p>POST message payload (XML):</p>
<p><code>
<?php echo h("<request><hash>7c12772809c1c0c3deda6103b10fdfa0</hash><allSamples>1</allSamples><eventID>13</eventID</request>"); ?>
</code></p>
<p>POST message payload (json):</p>
<p><code>
{"request": {"hash": "7c12772809c1c0c3deda6103b10fdfa0", "allSamples": 1, "eventID": 13}}
</code></p>
<p>A quick description of all the parameters in the passed object:</p>
<b>hash</b>: A hash in MD5 format. If allSamples is set, this can be any one of the following: <?php echo h(implode(', ', $hashTypes)); ?><br />
<b>allSamples</b>: If set, it will return all samples from events that have a match for the hash provided above.<br />
<b>eventID</b>: If set, it will only fetch data from the given event ID.<br />
<h3>Upload malware samples using the "Upload Sample" API</h3>
<pre>
<?php
	echo $baseurl.'/events/upload_sample/[Event_id]';
?>
</pre>
<p>This API will allow you to populate an event that you have modify rights to with malware samples (and all related hashes). Alternatively, if you do not supply an event ID, it will create a new event for you. <br />
The files have to be base64 encoded and POSTed as explained below. All samples will be zipped and password protected (with the password being "infected"). The hashes of the original file will be captured as additional attributes.<br />
The event ID is optional. MISP will accept either a JSON or an XML object posted to the above URL.</p>
<p><b>The general structure of the expected objects is as follows:</b></p>
<code>{"request": {"files": [{"filename": filename1, "data": base64encodedfile1}, {"filename": filename2, "data": base64encodedfile2}], "optional_parameter1", "optional_parameter2", "optional_parameter3"}}</code>
<br /><br />
<p><b>JSON:</b></p>
<code>{"request":{"files": [{"filename": "test1.txt", "data": "dGVzdA=="}, {"filename": "test2.txt", "data": "dGVzdDI="}], "distribution": 1, "info" : "test", "event_id": 15}}</code>
<br /><br />
<p><b>XML:</b></p>
<code><?php echo h("<request><files><filename>test3.txt</filename><data>dGVzdA==</data></files><files><filename>test4.txt</filename><data>dGVzdDI=</data></files><info>test</info><distribution>1</distribution><event_id>15</event_id></request>");?></code>
<br /><br />
<p><b>The following optional parameters are expected:</b></p>
<p><b>event_id</b>: The Event's ID is optional. It can be either supplied via the URL or the POSTed object, but the URL has priority if both are provided. Not supplying an event ID will cause MISP to create a single new event for all of the POSTed malware samples. You can define the default settings for the event, otherwise a set of default settings will be used.<br />
<b>distribution</b>: The distribution setting used for the attributes and for the newly created event, if relevant. [0-3]<br />
<b>to_ids</b>: You can flag all attributes created during the transaction to be marked as "to_ids" or not.<br />
<b>category</b>: The category that will be assigned to the uploaded samples. Valid options are: Payload delivery, Artifacts dropped, Payload Installation, External Analysis.<br />
<b>info</b>: Used to populate the event info field if no event ID supplied. Alternatively, if not set, MISP will simply generate a message showing that it's a malware sample collection generated on the given day.<br />
<b>analysis</b>: The analysis level of the newly created event, if applicatble. [0-2]<br />
<b>threat_level_id</b>: The threat level ID of the newly created event, if applicatble. [0-3]<br />
<b>comment</b>: This will populate the comment field of any attribute created using this API.<br />
<h3>Add or remove tags from events</h3>
<p>You can add or remove an existing tag from an event in the following way:</p>
<pre>
<?php echo $baseurl.'/events/addTag'; ?>
</pre>
<pre>
<?php  echo $baseurl.'/events/removeTag'; ?>
</pre>
<p>Just POST a json object in the following format (to the appropriate API depending on whether you want to add or delete a tag from an event):</p>
<code>{"event":228, "tag":8}</code><br /><br />
<p>Where "tag" is the ID of the tag. You can also use the name of the tag the following way:</p>
<code>{"event":228, "tag":"OSINT"}</code>
<h3>Proposals and the API</h3>
<p>You can interact with the proposals via the API directly since version 2.3.148</p>

<table style="width:900px;">
<tr>
	<th style="text-align:left;">HTTP</th>
	<th style="text-align:left;">URL</th>
	<th style="text-align:left;">Explanation</th>
	<th style="text-align:left;">Expected Payload</th>
	<th style="text-align:left;">Response</th>
</tr>
<tr>
	<td style="width:45px;">GET</td>
	<td style="width:250px;">/shadow_attributes/view/[proposal_id]</td>
	<td>View a proposal</td>
	<td>N/A</td>
	<td>ShadowAttribute object</td>
</tr>
<tr>
	<td style="width:45px;">GET</td>
	<td style="width:250px;">/shadow_attributes/index</td>
	<td>View all proposal of my org's events</td>
	<td>N/A</td>
	<td>ShadowAttribute objects</td>
</tr>
<tr>
	<td style="width:45px;">GET</td>
	<td style="width:250px;">/shadow_attributes/index/[event_id]</td>
	<td>View all proposals of an event</td>
	<td>N/A</td>
	<td>ShadowAttribute objects</td>
</tr>
<tr>
	<td style="width:45px;">POST</td>
	<td style="width:250px;">/shadow_attributes/add/[event_id]</td>
	<td style="width:250px;">Propose a new attribute to an event</td>
	<td>ShadowAttribute object</td>
	<td>ShadowAttribute object</td>
</tr>
<tr>
	<td style="width:45px;">POST</td>
	<td style="width:250px;">/shadow_attributes/edit/[attribute_id]</td>
	<td style="width:250px;">Propose an edit to an attribute</td>
	<td>ShadowAttribute object</td>
	<td>ShadowAttribute object</td>
</tr>
<tr>
	<td style="width:45px;">POST</td>
	<td style="width:250px;">/shadow_attributes/accept/[proposal_id]</td>
	<td style="width:250px;">Accept a proposal</td>
	<td>N/A</td>
	<td>Message</td>
</tr>
<tr>
	<td style="width:45px;">POST</td>
	<td style="width:250px;">/shadow_attributes/discard/[proposal_id]</td>
	<td style="width:250px;">Discard a proposal</td>
	<td>N/A</td>
	<td>Message</td>
</tr>
</table><br />
<p>When posting a shadow attribute object, use the following formats</p>
<p><b>JSON</b></p>
<code><?php echo h('{"request": {"ShadowAttribute": {"value": "5.5.5.5", "to_ids": false, "type": "ip-dst", "category": "Network activity"}}}');?></code><br /><br />
<p><b>XML</b></p>
<code><?php echo h('<request><ShadowAttribute><value>5.5.5.5</value><to_ids>0</to_ids><type>ip-src</type><category>Network activity</category></ShadowAttribute></request>');?></code><br /><br />
<p>None of the above fields are mandatory, but at least one of them has to be provided.</p>

<h3>Filtering event metadata</h3>
<p>As described in the REST section, it is possible to retrieve a list of events along with their metadata by sending a GET request to the /events API. However, this API in particular is a bit more versatile. You can pass search parameters along to search among the events on various fields and retrieve a list of matching events (along with their metadata). Use the following URL:<br />
<?php
	echo $baseurl.'/events/index';
?>
POST a JSON object with the desired lookup fields and values to receive a JSON back.<br />
An example for a valid lookup:</p>
<b>URL</b>: <?php echo $baseurl.'/events/index'; ?><br />
<b>Headers</b>:<br />
<pre>Authorization: [your API key]
Accept: application/json
Content-type: application/json
</pre>
<b>Body</b>:
<code>{"searcheventinfo":"Locky", "searchpublished":1, "searchdistribution":!0}</code><br /><br />
<p>The above would return any event that is published, not restricted to your organisation only that has the term "Locky" in its event description. You can use exclamation marks to negate a value wherever appropriate.</p>
<p><b>The list of valid parameters:</b></p>
<p><b>searchpublished</b>: Filters on published or unpulished events [0,1] - negatable<br />
<b>searcheventinfo</b>: Filters on strings found in the event info - negatable<br />
<b>searchtag</b>: Filters on attached tag names - negatable<br />
<b>searcheventid</b>: Filters on specific event IDs - negatable<br />
<b>searchthreatlevel</b>: Filters on a given event threat level [1,2,3,4] - negatable<br />
<b>searchdistribution</b>: Filters on the distribution level [0,1,2,3] - negatable<br />
<b>searchanalysis</b>: Filters on the given analysis phase of the event [0,1,2] - negatable<br />
<b>searchattribute</b>: Filters on a contained attribute value - negatable<br />
<b>searchorg</b>: Filters on the creator organisation - negatable<br />
<b>searchemail</b>: Filters on the creator user's email address (admin only) - negatable<br />
<b>searchDatefrom</b>: Filters on the date, anything newer than the given date in YYYY-MM-DD format is taken - non-negatable<br />
<b>searchDateuntil</b>: Filters on the date, anything older than the given date in YYYY-MM-DD format is taken - non-negatable<br /></p>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'automation'));
?>
