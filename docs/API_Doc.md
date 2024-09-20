# API Documentation
The following API documentation is derived directly from [MISP RestResponseComponent's source code](app/Controller/Component/RestResponseComponent.php)
# Attributes
## Add
POST a MISP Attribute JSON to this API to create an Attribute.
```
/attributes/add/[event_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| event_id | | |

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| value |string | |
| type |string |The type of the attribute |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| category |string | |
| to_ids |integer |The state of the `to_ids` flag |
| uuid |string | |
| distribution |integer | |
| sharing_group_id |integer | |
| timestamp |integer | |
| comment |string | |
| data |string |Base64 encoded file contents |
| encrypt |integer |When uploading malicious samples, set this flag to tell MISP to encrypt the sample and extract the file hashes. This will create a MISP object with the appropriate attributes. |
| first_seen |string |A valid ISO 8601 datetime format, up to milli-seconds. i.e.: 2019-06-13T15:56:56.856074+02:00 |
| last_seen |string |A valid ISO 8601 datetime format, up to milli-seconds. i.e.: 2019-06-13T15:56:56.856074+02:00 |

## Edit
POST a MISP Attribute JSON to this API to update an Attribute. If the timestamp is set, it has to be newer than the existing Attribute.
```
/attributes/edit/[attribute_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| attribute_id | | |

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| value |string | |
| type |string |The type of the attribute |
| category |string | |
| to_ids |integer |The state of the `to_ids` flag |
| uuid |string | |
| distribution |integer | |
| sharing_group_id |integer | |
| timestamp |integer | |
| comment |string | |
| date |date |The user set date field on the event level. If you are using restSearch, you can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.) |
| encrypt |integer |When uploading malicious samples, set this flag to tell MISP to encrypt the sample and extract the file hashes. This will create a MISP object with the appropriate attributes. |
| first_seen |string |A valid ISO 8601 datetime format, up to milli-seconds. i.e.: 2019-06-13T15:56:56.856074+02:00 |
| last_seen |string |A valid ISO 8601 datetime format, up to milli-seconds. i.e.: 2019-06-13T15:56:56.856074+02:00 |

## DeleteSelected
POST a list of attribute IDs in JSON format to this API to delete the given attributes. This API also expects an event ID passed via the URL or via the event_id key. The id key also takes 'all' as a parameter for a wildcard search to mass delete attributes. If you want the function to also hard-delete already soft-deleted attributes, pass the allow_hard_delete key.
```
/attributes/deleteSelected/[event_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| event_id |integer | |

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| id |integer | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| event_id |integer | |
| allow_hard_delete |integer |hard-delete already soft-deleted attributes |

## RestSearch
Search MISP using a list of filter parameters and return the data in the selected format. The search is available on an event and an attribute level, just select the scope via the URL (/events/restSearch vs /attributes/restSearch). Besides the parameters listed, other, format specific ones can be passed along (for example: requested_attributes and includeContext for the CSV export). This API allows pagination via the page and limit parameters.
```
/attributes/restSearch
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| returnFormat |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| page |integer |Page number for the pagination |
| limit |integer |Limit on the pagination |
| value |string | |
| type |string |The type of the attribute |
| category |string | |
| org |string |Can be either the ORG_ID or the ORG_NAME |
| tags |string | |
| date |date |The user set date field on the event level. If you are using restSearch, you can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.) |
| last |string |Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m) |
| eventid |integer | |
| withAttachments |integer | |
| uuid |string | |
| publish_timestamp |integer | |
| timestamp |integer | |
| attribute_timestamp |integer |The timestamp at which the attribute was last modified |
| enforceWarninglist |integer |Should the warning list be enforced. Adds `blocked` field for matching attributes |
| to_ids |integer |The state of the `to_ids` flag |
| deleted |integer |Include deleted elements |
| includeEventUuid |integer |Include matching eventUuids in the response |
| includeEventTags |integer |Include tags of matching events in the response |
| event_timestamp |integer |The timestamp at which the event was last modified |
| threat_level_id |integer | |
| eventinfo |string |Quick event description |
| includeProposals |integer |Include proposals of matching events in the response |
| includeDecayScore |integer |Include all enabled decaying score |
| includeFullModel |integer |Include all model information of matching events in the response |
| decayingModel |string |Specify the decaying model from which the decaying score should be calculated |
| excludeDecayed |integer |Should the decayed elements by excluded |
| score |integer |An alias to override on-the-fly the threshold of the decaying model |
| first_seen |string |Seen within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m) |
| last_seen |string |Seen within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m) |

## AddTag
Add a tag or a tag collection to an attribute.
```
/attributes/addTag
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| attribute |string |Attribute id |
| tag |string | |


## RemoveTag
Remove a tag from an attribute.
```
/attributes/removeTag
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| attribute |string |Attribute id |
| tag |string | |


# Communities
## RequestAccess
POST a request object describing yourself and your organisation to request access to the desired community.
```
/communities/requestAccess/[uuid]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| uuid | | |

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| org_name |string |Organisation identifier (name) |
| org_uuid |string |Globally used uuid of an organisation |
| sync |integer | |
| org_description |string |Describe the organisation |
| email |string |Filter on user email |
| message |string |Message to be included |
| anonymise |integer |Anonymise the information regarding the server on which the request was issued |
| gpgkey |string |A valid GPG key |
| mock |integer |Mock the query |

# Events
## Add
POST a MISP Event JSON to this API to create an Event. Contained objects can also be included (such as attributes, objects, tags, etc).
```
/events/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| info |string |Quick event description |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| threat_level_id |integer | |
| analysis |integer |Maturity of the event |
| distribution |integer | |
| sharing_group_id |integer | |
| uuid |string | |
| published |integer | |
| timestamp |integer | |
| date |date |The user set date field on the event level. If you are using restSearch, you can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.) |
| Attribute |string |Not supported |
| Object |string |Not supported |
| Shadow_Attribute |string |Not supported |
| EventTag |string | |

## Edit
POST a MISP Event JSON to this API to update an Event. Contained objects can also be included (such as attributes, objects, tags, etc). If the timestamp is set, it has to be newer than the existing Attribute.
```
/events/edit/[event_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| event_id | | |

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| info |string |Quick event description |
| threat_level_id |integer | |
| analysis |integer |Maturity of the event |
| distribution |integer | |
| sharing_group_id |integer | |
| uuid |string | |
| published |integer | |
| timestamp |integer | |
| date |date |The user set date field on the event level. If you are using restSearch, you can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.) |
| Attribute |string |Not supported |
| Object |string |Not supported |
| Shadow_Attribute |string |Not supported |
| EventTag |string | |

## Index
POST a JSON filter object to this API to get the meta-data about matching events.
```
/events/index
```
### URL Parameters

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| all |string |Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields |
| attribute |string |Filter on attribute value |
| published |integer | |
| eventid |integer | |
| datefrom |date | |
| dateuntil |date | |
| org |string |Can be either the ORG_ID or the ORG_NAME |
| eventinfo |string |Quick event description |
| tag |string | |
| tags |string | |
| distribution |integer | |
| sharinggroup |integer |Sharing group ID |
| analysis |integer |Maturity of the event |
| threatlevel |integer | |
| email |string |Filter on user email |
| hasproposal |integer |The event contains proposals |
| timestamp |integer | |
| publishtimestamp |integer | |
| publish_timestamp |integer | |
| minimal |integer |Will only return  id, timestamp, published and uuid |

## RestSearch
Search MISP using a list of filter parameters and return the data in the selected format. The search is available on an event and an attribute level, just select the scope via the URL (/events/restSearch vs /attributes/restSearch). Besides the parameters listed, other, format specific ones can be passed along (for example: requested_attributes and includeContext for the CSV export). This API allows pagination via the page and limit parameters.
```
/events/restSearch
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| returnFormat |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| page |integer |Page number for the pagination |
| limit |integer |Limit on the pagination |
| value |string | |
| type |string |The type of the attribute |
| category |string | |
| org |string |Can be either the ORG_ID or the ORG_NAME |
| tag |string | |
| tags |string | |
| searchall |integer |Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields |
| date |date |The user set date field on the event level. If you are using restSearch, you can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.) |
| last |string |Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m) |
| eventid |integer | |
| withAttachments |integer | |
| metadata |integer |Will only return the metadata of the given query scope, contained data is omitted. |
| uuid |string | |
| published |integer | |
| publish_timestamp |integer | |
| timestamp |integer | |
| enforceWarninglist |integer |Should the warning list be enforced. Adds `blocked` field for matching attributes |
| sgReferenceOnly |integer |Will only return the sharing group ID |
| eventinfo |string |Quick event description |
| excludeLocalTags |integer |Exclude local tags from the export |
| threat_level_id |integer | |

## AddTag
Add a tag or a tag collection to an event.
```
/events/addTag
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| event |integer |Event id |
| tag |string | |


## RemoveTag
Remove a tag from an event.
```
/events/removeTag
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| event |integer |Event id |
| tag |string | |


# Event Graph
## Add
POST a network in JSON format to this API to to keep an history of it
```
/event_graph/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| event_id |integer | |
| network_json |string |Not supported |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| network_name |string |Not supported |

# Event Reports
## Add
POST a report in JSON format to create a report for the provided event
```
/event_reports/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| name |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| distribution |integer | |
| content | | |

## Edit
POST a report in JSON format to update the report
```
/event_reports/edit
```
### URL Parameters

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| name |string | |
| distribution |integer | |
| content | | |

# Feeds
## Add
POST a MISP Feed descriptor JSON to this API to add a Feed.
```
/feeds/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| source_format |string | |
| url |string | |
| name |string | |
| input_source |string |Specify whether the source (url field) is a directory (local) or an geniun url (network) |
| provider |string |The name of the feed provider |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| enabled |integer | |
| caching_enabled |integer |The feed is cached |
| lookup_visible |integer |The lookup will not be visible in the feed correlation |
| delete_local_file |integer |Remove file after ingestion |
| headers |string |Headers to be passed with the requests. All separated by `\n` |
| fixed_event |integer |target_event option might be considered |
| target_event |integer |The provided ID will be reused as an existing event |
| settings |string |Not supported |
| publish |integer |The event will be published |
| override_ids |integer |The IDS flags will be set to off for this feed |
| delta_merge |integer |Merge attributes (only add new attribute, remove revoked attributes) |
| distribution |integer | |
| sharing_group_id |integer | |
| tag_id |integer |A tag ID to attach to created events |
| pull_rules |string |Not supported |
| rules |string |Not supported |
| event_id |integer | |

## Edit
POST a MISP Feed descriptor JSON to this API to edit a Feed.
```
/feeds/edit/[feed_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| feed_id | | |

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| source_format |string | |
| url |string | |
| name |string | |
| enabled |integer | |
| caching_enabled |integer |The feed is cached |
| lookup_visible |integer |The lookup will not be visible in the feed correlation |
| provider |string |The name of the feed provider |
| input_source |string |Specify whether the source (url field) is a directory (local) or an geniun url (network) |
| delete_local_file |integer |Remove file after ingestion |
| headers |string |Headers to be passed with the requests. All separated by `\n` |
| fixed_event |integer |target_event option might be considered |
| target_event |integer |The provided ID will be reused as an existing event |
| settings |string |Not supported |
| publish |integer |The event will be published |
| override_ids |integer |The IDS flags will be set to off for this feed |
| delta_merge |integer |Merge attributes (only add new attribute, remove revoked attributes) |
| distribution |integer | |
| sharing_group_id |integer | |
| tag_id |integer |A tag ID to attach to created events |
| pull_rules |string |Not supported |
| rules |string |Not supported |
| event_id |integer | |

## PreviewIndex
Sending a GET request to this endpoint will show the parsed feed in JSON format.
```
/feeds/previewIndex/[feed_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| feed_id | | |

### Parameters

# Galaxy Clusters
## Add
POST a MISP GalaxyCluster JSON to this API to create a GalaxyCluster. Contained objects can also be included (such as relations, elements, tags, etc).
```
/galaxy_clusters/add/[galaxy_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| galaxy_id | | |

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| value |string | |
| description |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| distribution |integer | |
| sharing_group_id |integer | |
| uuid |string | |
| version | | |
| extends_uuid | | |
| extends_version | | |
| elements | | |
| GalaxyClusterRelation | | |

## Edit
POST a MISP GalaxyCluster JSON to this API to edit a GalaxyCluster
```
/galaxy_clusters/edit/[cluster_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| cluster_id | | |

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| value |string | |
| description |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| distribution |integer | |
| sharing_group_id |integer | |
| uuid |string | |
| version | | |
| extends_uuid | | |
| extends_version | | |
| elements | | |

## RestSearch
Search MISP using a list of filter parameters and return the data in the selected format. This API allows pagination via the page and limit parameters.
```
/galaxy_clusters/restSearch
```
### URL Parameters

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| page |integer |Page number for the pagination |
| limit |integer |Limit on the pagination |
| id |integer | |
| uuid |string | |
| galaxy_id | | |
| galaxy_uuid | | |
| version | | |
| distribution |integer | |
| org_id |integer | |
| orgc_id | | |
| tag_name | | |
| custom | | |
| minimal |integer |Will only return  id, timestamp, published and uuid |
| published |integer | |
| value |string | |
| extends_uuid | | |

# Galaxy Cluster Relations
## Add
POST a MISP GalaxyClusterRelation JSON to this API to create a GalaxyCluster relation. Contained objects can also be included (such as tags).
```
/galaxy_cluster_relations/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| galaxy_cluster_uuid |string |Source galaxy cluster UUID |
| referenced_galaxy_cluster_uuid |string |Destination galaxy cluster UUID |
| referenced_galaxy_cluster_type |string |The type of the relation. Example: `is`, `related-to`, ... |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| distribution |integer | |
| sharing_group_id |integer | |
| tags |string | |

## Edit
POST a MISP GalaxyClusterRelation JSON to this API to edit a GalaxyCluster relation. Contained objects can also be included (such as tags).
```
/galaxy_cluster_relations/edit/[relation_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| relation_id | | |

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| galaxy_cluster_uuid |string |Source galaxy cluster UUID |
| referenced_galaxy_cluster_uuid |string |Destination galaxy cluster UUID |
| referenced_galaxy_cluster_type |string |The type of the relation. Example: `is`, `related-to`, ... |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| distribution |integer | |
| sharing_group_id |integer | |
| tags |string | |

# Logs
## Index
POST a filter object to receive a JSON with the log entries matching the query. A simple get request will return the entire DB. You can use the filter parameters as url parameters with a GET request such as: https://path.to.my.misp/admin/logs/page:1/limit:200 - to run substring queries simply append/prepend/encapsulate the search term with %. All restSearch rules apply.
```
/admin/logs/index
```
### URL Parameters

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| id |integer | |
| title |string |The title of the log |
| created |date | |
| model |string | |
| model_id |integer | |
| action |string |The action that the user performed |
| user_id |integer | |
| change |string |The text contained in the change field |
| email |string |Filter on user email |
| org |string |Can be either the ORG_ID or the ORG_NAME |
| description |string | |
| ip |string |The IP of a login attempt |

## Event Index
Simply run a get request on this endpoint to get the relevant log entries for a given event. This functionality is open to any user having access to a given event.
```
/logs/event_index
```
### URL Parameters

### Parameters

# Organisations
## Add
POST an Organisation object in JSON format to this API to create a new organisation.
```
/admin/organisations/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| name |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| description |string | |
| type |string |The type of the attribute |
| nationality |string | |
| sector |string |The sector of the organisation |
| uuid |string | |
| contacts |string |Contact details for the organisation |
| local |integer |If the organisation should have access to this instance, make sure that the Local organisation setting is checked. If you would only like to add a known external organisation for inclusion in sharing groups, uncheck the Local organisation setting. |

## Edit
POST an Organisation object in JSON format to this API to create a new organisation.
```
/admin/organisations/edit
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| name |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| description |string | |
| type |string |The type of the attribute |
| nationality |string | |
| sector |string |The sector of the organisation |
| uuid |string | |
| contacts |string |Contact details for the organisation |
| local |integer |If the organisation should have access to this instance, make sure that the Local organisation setting is checked. If you would only like to add a known external organisation for inclusion in sharing groups, uncheck the Local organisation setting. |

# Roles
## Add
POST a Role object in JSON format to this API to create a new role. 'permission' sets the data access permission (0 => read only, 1 => add/edit own, 2 => add/edit org, 3 => publish)
```
/admin/roles/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| name |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| perm_delegate |integer | |
| perm_sync |integer | |
| perm_admin |integer | |
| perm_audit |integer | |
| perm_auth |integer | |
| perm_site_admin |integer | |
| perm_regexp_access |integer | |
| perm_tagger |integer | |
| perm_galaxy_editor |integer | |
| perm_template |integer | |
| perm_sharing_group |integer | |
| perm_tag_editor |integer | |
| default_role |integer |The role is a default role (selected by default) |
| perm_sighting |integer | |
| permission |string | |

## Edit
POST a Role object in JSON format to this API to edit a role. 'permission' sets the data access permission (0 => read only, 1 => add/edit own, 2 => add/edit org, 3 => publish)
```
/admin/roles/edit
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| name |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| perm_delegate |integer | |
| perm_sync |integer | |
| perm_admin |integer | |
| perm_audit |integer | |
| perm_auth |integer | |
| perm_site_admin |integer | |
| perm_regexp_access |integer | |
| perm_tagger |integer | |
| perm_galaxy_editor |integer | |
| perm_template |integer | |
| perm_sharing_group |integer | |
| perm_tag_editor |integer | |
| default_role |integer |The role is a default role (selected by default) |
| perm_sighting |integer | |
| permission |string | |

# Servers
## Add
POST an Server object in JSON format to this API to add a server.
```
/servers/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| url |string | |
| name |string | |
| remote_org_id |integer | |
| authkey |string |The authorisation key found on the external server |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| push |integer |Allow the upload of events and their attribute to the server |
| pull |integer |Allow the download of events and their attribute from the server |
| push_sightings |integer |Allow the upload of sightings to the server |
| push_rules |string |Not supported |
| pull_rules |string |Not supported |
| submitted_cert |string |Base64 encoded certificate |
| submitted_client_cert |string |Base64 encoded certificate |
| json |string |JSON containing ID, UUID and name |

## Edit
POST an Server object in JSON format to this API to edit a server.
```
/servers/edit
```
### URL Parameters

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| url |string | |
| name |string | |
| authkey |string |The authorisation key found on the external server |
| json |string |JSON containing ID, UUID and name |
| push |integer |Allow the upload of events and their attribute to the server |
| pull |integer |Allow the download of events and their attribute from the server |
| push_sightings |integer |Allow the upload of sightings to the server |
| push_rules |string |Not supported |
| pull_rules |string |Not supported |
| submitted_cert |string |Base64 encoded certificate |
| submitted_client_cert |string |Base64 encoded certificate |
| remote_org_id |integer | |

## ServerSettings
Send a GET request to this endpoint to get a full diagnostic along with all currently set settings of the current instance. This will also include the worker status
```
/servers/serverSettings
```
### URL Parameters

### Parameters

# Sightings
## Add
POST a simplified sighting object in JSON format to this API to add a or a list of sightings. Pass either value(s) or attribute IDs (can be uuids) to identify the target sightings.
```
/sightings/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| ["values","id"] |Object |["values","id"] |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| type |string |The type of the attribute |
| source |string |The source of the Sighting (e.g. honeypot_1) |
| timestamp |integer | |
| date |date |The user set date field on the event level. If you are using restSearch, you can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.) |
| time |string |Time of the sighting with the form `h:i:s` |

## RestSearch
Search MISP sightings using a list of filter parameters and return the data in the JSON format. The search is available on an event, attribute or instance level, just select the scope via the URL (/sighting/restSearch/event vs /sighting/restSearch/attribute vs /sighting/restSearch/). id or uuid MUST be provided if context is set.
```
/sightings/restSearch/[context]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| context | | |

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| returnFormat |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| id |integer | |
| uuid |string | |
| type |string |The type of the attribute |
| from |date |The date from which the event was published |
| to |date |The date to which the event was published |
| last |string |Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m) |
| org_id |integer | |
| source |string |The source of the Sighting (e.g. honeypot_1) |
| includeAttribute |integer |Include matching attributes in the response |
| includeEvent |integer |Include matching events in the response |

# Sharing Groups
## Add
POST a Sharing Group object in JSON format to this API to add a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.
```
/sharing_groups/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| name |string | |
| releasability |string |Concise summary for who this sharing group is releasable to |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| description |string | |
| uuid |string | |
| organisation_uuid |string |Globally used uuid of an organisation |
| active |integer |Is the sharing group selectable (active) when choosing distribution |
| created |date | |
| modified |date |The last time the sharing group was modified |
| roaming |integer |Pass the event to any connected instance where the sync connection is tied to an organisation contained in the SG organisation list |
| ["url","name","all_orgs"] |Object |["url","name","all_orgs"] |
| ["uuid","name","extend"] |Object |["uuid","name","extend"] |

## Edit
POST a Sharing Group object in JSON format to this API to edit a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.
```
/sharing_groups/edit
```
### URL Parameters

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| name |string | |
| releasability |string |Concise summary for who this sharing group is releasable to |
| description |string | |
| uuid |string | |
| organisation_uuid |string |Globally used uuid of an organisation |
| active |integer |Is the sharing group selectable (active) when choosing distribution |
| created |date | |
| modified |date |The last time the sharing group was modified |
| roaming |integer |Pass the event to any connected instance where the sync connection is tied to an organisation contained in the SG organisation list |
| ["url","name","all_orgs"] |Object |["url","name","all_orgs"] |
| ["uuid","name","extend"] |Object |["uuid","name","extend"] |

# Tags
## Add
POST a Tag object in JSON format to this API to create a new tag.
```
/tags/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| name |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| colour |string |A valid hexadecimal colour `#ffffff` |
| exportable |integer |The tag is exported when synchronising with other instances |
| hide_tag |integer |The tag is hidden (not selectable) |
| org_id |integer | |
| user_id |integer | |

## Edit
POST or PUT a Tag object in JSON format to this API to create a edit an existing tag.
```
/tags/edit/[tag_id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| tag_id | | |

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| name |string | |
| colour |string |A valid hexadecimal colour `#ffffff` |
| exportable |integer |The tag is exported when synchronising with other instances |
| hide_tag |integer |The tag is hidden (not selectable) |
| org_id |integer | |
| user_id |integer | |

## RemoveTagFromObject
Untag an event or attribute. Tag can be the id or the name.
```
/tags/removeTagFromObject
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| uuid |string | |
| tag |string | |


## AttachTagToObject
Attach a Tag to an object, referenced by an UUID. Tag can either be a tag id or a tag name.
```
/tags/attachTagToObject
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| uuid |string | |
| tag |string |Also supports array of tags |


## Search
GET or POST the tags to search for as a raw string or as a list. The strict_tag_name_only parameter only returns tags matching exactly the tag name (thus, skipping synonyms and cluster's value)
```
/tags/search/[tag_name]/[strict_tag_name_only]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| tag_name | | |
| strict_tag_name_only | | |

### Parameters

# Users
## Add
POST a User object in JSON format to this API to create a new user.
```
/admin/users/add
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| email |string |Filter on user email |
| org_id |integer | |
| role_id |integer | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| password |string |The hardcoded password |
| external_auth_required |integer |An external authorisation is required for this user |
| external_auth_key |string |A valid external auth key |
| enable_password |integer |Set the password manually |
| nids_sid |integer |The unique Signature Identification |
| server_id |integer | |
| gpgkey |string |A valid GPG key |
| certif_public |string |A valid x509 certificate  |
| autoalert |integer |The user receive alerts when events are published |
| contactalert |integer |The user receive alerts from `contact reporter` requests |
| disabled |integer |Disable the user account |
| change_pw |integer |The user will be prompted the change the password |
| termsaccepted |integer | |
| newsread |integer |The news are read |

## Edit
POST a User object in JSON format to this API to edit a user.
```
/admin/users/edit
```
### URL Parameters

### Parameters
#### Optional
| Name |Type |Description |
| -- |-- |-- |
| email |string |Filter on user email |
| org_id |integer | |
| role_id |integer | |
| password |string |The hardcoded password |
| external_auth_required |integer |An external authorisation is required for this user |
| external_auth_key |string |A valid external auth key |
| enable_password |integer |Set the password manually |
| nids_sid |integer |The unique Signature Identification |
| server_id |integer | |
| gpgkey |string |A valid GPG key |
| certif_public |string |A valid x509 certificate  |
| autoalert |integer |The user receive alerts when events are published |
| contactalert |integer |The user receive alerts from `contact reporter` requests |
| disabled |integer |Disable the user account |
| change_pw |integer |The user will be prompted the change the password |
| termsaccepted |integer | |
| newsread |integer |The news are read |

## QuickEmail
POST a body and a subject in a JSON to send an e-mail through MISP to the user ID given in the URL
```
/admin/users/quickEmail
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| subject |string |The email's subject |
| body |string |The email's body |


## Change Pw
POST a password via a JSON object containing the password key to reset the given user\'s password.
```
/users/change_pw
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| password |string |The hardcoded password |


## Statistics
Simply GET the url endpoint to view the API output of the statistics API. Additional statistics are available via the following tab-options similar to the UI: data, orgs, users, tags, attributehistogram, sightings, attackMatrix
```
/users/statistics/[tab]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| tab | | |

### Parameters

# User Settings
## SetSetting
POST a User setting object in JSON format to this API to create a new setting or update the equivalent existing setting. Admins/site admins can specify a user ID besides their own.
```
/user_settings/setSetting
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| setting | | |
| value |string | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| user_id |integer | |

## Delete
POST or DELETE to this API to delete an existing setting.
```
/user_settings/delete/[id]
```
### URL Parameters
| Name |Type |Description |
| -- |-- |-- |
| id | | |

### Parameters

# Warninglists
## CheckValue
POST a JSON list with value(s) to check against the warninglists to get a JSON dictionary as a response with any hits, if there are any (with the key being the passed value triggering a warning).
```
/warninglists/checkValue
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| [] |string |Not supported (warninglist->checkvalues) expect an array |


## ToggleEnable
POST a json object with a single or a list of warninglist IDsIDs, or alternatively a (list of) substring(s) that match the names of warninglist(s) to toggle whether they're enabled or disabled. Specify the optional enabled boolean flag if you would like to enforce the outcome state. Not setting this flag will just toggle the current state.
```
/warninglists/toggleEnable
```
### URL Parameters

### Parameters
#### Mandatory
| Name |Type |Description |
| -- |-- |-- |
| id |integer | |

#### Optional
| Name |Type |Description |
| -- |-- |-- |
| id |integer | |
| name |string | |
| enabled |integer | |

