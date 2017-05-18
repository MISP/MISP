<?php

class IOCImportComponent extends Component {

	// rework of handling composite attributes
	// each entry is only triggered if an "AND" branch contains the exact list of parsed attribute types that are set in the components field
	// Note that some indicators are not immediately discarded by the parser even if they cannot be turned into an attribute
	// The reason for this is that they might not be convertable to an attribute, but they might be converted into a part of a composite attribute
	// For example: There is no Registry value type in MISP, but there is a regkey|value type. Meaning that a Registry value can be turned into an attribute
	// as long as a registry key is "AND"ed with the value in the OpenIOC file.

	// notes about the format for the composition:
	// - components have to be in alphabetical order
	// - returnFormat has to be a valid MISP type
	// - returnCategory has to be a valid MISP category
	// - replace: passed attribute values will replace the $[component position] substring to form the final attribute value
	private $attributeComposition = array(
		array(
				'components' => array('filename', 'md5'),
				'returnFormat' => 'filename|md5',
				'returnCategory' => 'Payload installation',
				'replace'=> '$0|$1'
		),
		array(
				'components' => array('filename', 'sha1'),
				'returnFormat' => 'filename|sha1',
				'returnCategory' => 'Payload installation',
				'replace'=> '$0|$1'
		),
		array(
				'components' => array('filename', 'sha256'),
				'returnFormat' => 'filename|sha256',
				'returnCategory' => 'Payload installation',
				'replace'=> '$0|$1'
		),
		array(
				'components' => array('regkey', 'tempRegValue'),
				'returnFormat' => 'regkey|value',
				'returnCategory' => 'Persistence mechanism',
				'replace'=> '$0|$1'
		),
		array(
				'components' => array('filename', 'tempCertificateSubject'),
				'returnFormat' => 'filename',
				'returnCategory' => 'Payload installation',
				'replace'=> '$0'
		),
		array(
				'components' => array('filename', 'tempExtension'),
				'returnFormat' => 'filename',
				'returnCategory' => 'Payload installation',
				'replace'=> '$0.$1'
		),
		array(
				'components' => array('regkey', 'tempRegName', 'tempRegValue'),
				'returnFormat' => 'regkey|value',
				'returnCategory' => 'Persistence mechanism',
				'replace'=> '$0$1|$2'
		),
	);

	// Indicators that we can safely remove if they pop up within an AND branch
	private $discardableIndicators = array(
			//'FileItem/PEInfo/Exports/NumberOfFunctions',
			//'FileItem/PEInfo/Exports/ExportedFunctions/string',
			//'FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string',
			//'FileItem/SizeInBytes',
			//'FileItem/PEInfo/PETimeStamp',
			//'FileItem/PEInfo/DigitalSignature/SignatureExists',
			//'FileItem/PEInfo/DigitalSignature/CertificateSubject',
			);

	// the default settings for the IDS flag / type
	private $typeToIdsSettings = array(
			'filename' => true,
			'md5' => true,
			'sha1' => true,
			'sha256' => true,
			'ip-src' => true,
			'ip-dst' => true,
			'domain' => true,
			'hostname' => true,
			'email-dst' => true,
			'email-src' => true,
			'email-subject' => true,
			'email-attachment' => true,
			'url' => true,
			'user-agent' => false,
			'regkey' => true,
			'snort' => true,
			'pattern-in-file' => true,
			'comment' => false,
			'other' => false,
			'filename|md5' => true,
			'filename|sha1' => true,
			'filename|sha256' => true,
			'regkey|value' => true,
	);

	// Set up the data that you would like to fetch from the ioc's root and add as comments.
	private $iocinfo = array('info', 'uuid', 'date', 'long_info');

	// The maximum number of combinations that the AND branch resolver should allow
	// Basically, AND branches with several OR sub branches can be converted into OR branches with many AND sub branches, so that we can try to eliminate the AND-s
	// by omitting the discardable indicators and by grouping the remaining indicators into valid attribute pairs.
	// The number of possible combinations that will be tested can be calculated by multiplying each of the leaves in the OR sub-branches.
	// AND: 1,2,OR(3,4), OR(5,6) where the AND branch contains leaves 1 and 2 and the 2 OR sub-branches contain leaves 3,4 and 5,6 respectively.
	// In this case we have 2*2 combinations:
	// OR: AND(1,2,3,5), AND(1,2,3,6), AND(1,2,4,5), AND(1,2,4,6)
	// $hardLimit sets the maximum number of combinations allowed
	private $hardLimit = 10000;

	// tracks the failed indicatorItems
	private $fails = array();
	// uuids of successfully added indicatoritems and indicators, used for the creation of the graph
	private $saved_uuids = array();

	private $tempLeaves = array();

	// used to store the event id and the distribution, so that they can be added to attribtes during the conversion
	private $event_id = null;
	private $distribution = array();

	// stores the graph that will be passed back along with the event and attributes
	private $graph = array();

	private $filename = "";

	public function readXML($data, $id, $dist, $filename) {
		$this->Attribute = ClassRegistry::init('Attribute');
		$this->filename = $filename;
		$this->fails = array();
		$this->distribution = $dist;
		$this->event_id = $id;
		// import XML class
		App::uses('Xml', 'Utility');

		// now parse it
		$xmlArray['ioc'] = json_decode(json_encode((array) simplexml_load_string($data)), 1);

		// Since the tree created by simplexml is a bit of a pain to traverse (partially because of branches with 1 leaves and with several leaves ending up in a different format -
		// $branch['leaf'] vs $branch[0]['leaf'] we convert it to an easier to deal with tree structure
		// This tree also only contains the information that we care about.
		$tree = array(
				'type' => 'OR',
				'branches' => array(),
				'leaves' => array()
		);
		if (isset($xmlArray['ioc']['@attributes']['id'])) $tree['uuid'] = $xmlArray['ioc']['@attributes']['id'];
		$temp = '';
		if (isset($xmlArray['ioc']['short_description'])) {
			$temp = $xmlArray['ioc']['short_description'];
			if (isset($xmlArray['ioc']['authored_by'])) $temp .= PHP_EOL . 'by ' . $xmlArray['ioc']['authored_by'];
		}
		if ($temp !== '') $tree['info'] = $temp;
		if (isset($xmlArray['ioc']['description'])) $tree['longinfo'] = $xmlArray['ioc']['description'];
		if (isset($xmlArray['ioc']['authored_date'])) $tree['date'] = $xmlArray['ioc']['authored_date'];

		$tree['branches'] = $this->__createRootNode($xmlArray);

		// Once we're done, let's back the tree up for later use, so we can start shuffling things around and converting it to our own attribute format
		$oldTree = $tree;
		// Let's start analysing and altering the tree so that we can keep as much data as possible
		$tree = $this->__traverseAndAnalyse($tree);
		$tree = $this->__resolveBranch($tree, $tree['uuid'], 'OR', $tree['leaves'], true);
		$attributes = null;
		if (isset($tree['branches'][0]['leaves'])) $attributes = $tree['branches'][0]['leaves'];
		if (isset($tree['leaves'])) $attributes = $tree['leaves'];
		unset($tree['branches'], $tree['leaves'], $tree['type']);
		// set the basic info the event in case we want to populate the uuid, info and date fields
		$event = $tree;
		// attach the attributes to the event
		$event['Attribute'] = $attributes;

		$duplicateFilter = array();
		// check if we have any attributes, if yes, add their UUIDs to our list of success-array
		if (count ($event['Attribute']) > 0) {
			foreach ($event['Attribute'] as $k => $attribute) {
				$condensed = strtolower($attribute['value']) . $attribute['category'] . $attribute['type'];
				if (!in_array($condensed, $duplicateFilter)) {
					$this->saved_uuids[] = $attribute['uuid'];
					$duplicateFilter[] = $condensed;
					$event['Attribute'][$k]['uuid'] = CakeText::uuid();
				} else unset($event['Attribute'][$k]);
			}
		}

		// using the previously populated array, set a flag on each branch and leaf indicating whether they were successfully added or not, to colour the graph
		$oldTree = $this->__setSuccesses($oldTree);
		$this->__graphBranches($oldTree, 0);

		// Add a special attribute that captures the basic data about the .ioc such as the ioc-s uuid, info, long info, author, etc.
		// Define the fields used in the global iocinfo variable.
		foreach ($this->iocinfo as $k => $v) {
			if (isset($event[$v])) $event['Attribute'][] = array('uuid' => CakeText::uuid(), 'category' => 'Other', 'type' => 'comment', 'event_id' => $id, 'value' => $v . ': ' . $event[$v], 'to_ids' => $this->typeToIdsSettings['comment'], 'distribution' => $this->distribution, 'comment' => 'OpenIOC import from file ' . $filename);
		}

		// attach the graph to the event
		$event['Graph'] = $this->graph;
		// attach the failures to the event
		$event['Fails'] = $this->fails;
		// Set the initual OR branch to being successful (= green on the graph)
		if (count($this->saved_uuids) > 1)	$event['Graph'][0][1] = true;
		// return the whole package and let the eventscontroller dissect it
		return $event;
	}

	// traverse the oldTree and set the successful branches and leaves to "success true" if they got added to the attribute tree. Otherwise set false.
	private function __setSuccesses($branch) {
		foreach ($branch['leaves'] as $key => $value) {
			$branch['leaves'][$key]['success'] = (in_array($value['uuid'], $this->saved_uuids) ? true : false);
			if (!array_key_exists('success', $value) || !$value['success']) $this->fails[] = $value;
		}
		foreach ($branch['branches'] as $key => $value) {
			$branch['branches'][$key] = $this->__setSuccesses($value);
		}
		$branch['success'] = (in_array($branch['uuid'], $this->saved_uuids) ? true : false);
		return $branch;
	}

	private function __traverseAndAnalyse($array) {
		if (count($array['leaves']) > 0) {
			foreach ($array['leaves'] as $key => $leaf) {
				$array['leaves'][$key] = $this->__analyseIndicator($leaf);
			}
		}
		if (count($array['branches']) > 0) {
			foreach ($array['branches'] as $key => $branch) {
				$array['branches'][$key] = $this->__traverseAndAnalyse($branch);
			}
		}
		return $array;
	}

	// dissect the indicator and convert it into an attribute
	private function __analyseIndicator($attribute) {
		$attribute['distribution'] = $this->distribution;
		$temp = $this->__checkType($attribute['search'], $attribute['type']);
		if ($attribute['condition'] !== 'containsnot') {
			if (!$temp) return false;
			$attribute['category'] = $temp[0];
			$attribute['type'] = $temp[1];
		} else {
			$attribute['category'] = 'Other';
			$attribute['type'] = 'other';
			$attribute['value'] = 'containsnot: ' . $attribute['value'];
		}
		if (isset($this->typeToIdsSettings[$attribute['type']])) $attribute['to_ids'] = $this->typeToIdsSettings[$attribute['type']];
		// If we couldn't figure out the category / type and got Other/other, append the search term in the value
		if ($temp[0] == 'Other' && $temp[1] == 'other') {
			$attribute['value'] = $attribute['search'] . ': ' . $attribute['value'];
		}
		$attribute['comment'] = 'OpenIOC import from file ' . $this->filename . PHP_EOL . 'Original UUID: ' . $attribute['uuid'];
		return $attribute;
	}

	private function __createRootNode($xmlArray) {
		$array = array();
		if ($this->__isAssoc($xmlArray['ioc']['definition']['Indicator'])) {
			foreach ($xmlArray['ioc']['definition'] as $key => $value) {
				$array[] = $this->__createBranchNode($value);
			}
		}
		return $array;
	}

	private function __createBranchNode($array) {
		$node = array('leaves' => array(), 'branches' => array());
		foreach ($array as $key => $value) {
			if ($key === '@attributes') {
				$node['type'] = $value['operator'];
				$node['uuid'] = $value['id'];
			}
			if ($key === 'IndicatorItem') {
				if ($this->__isAssoc($value)) {
					$temp = $value;
					$value = array();
					$value[0] = $temp;
				}
				foreach ($value as $ii) {
					$leaf = array('uuid' => $ii['@attributes']['id'], 'condition' => $ii['@attributes']['condition'], 'search' => $ii['Context']['@attributes']['search'], 'value' => $ii['Content']);
					array_push($node['leaves'], $leaf);
				}
			}
			if ($key === 'Indicator') {
				if ($this->__isAssoc($value)) {
					$temp = $value;
					$value = array();
					$value[0] = $temp;
				}
				foreach ($value as $k => $v) {
					array_push($node['branches'], $this->__createBranchNode($v));
				}
			}
		}
		return $node;
	}

	// Neat way of checking whether an array is associative or not - during the conversion from XML, if a Node has 1 child it will be represented as $node['child'] instead of $node[0]['child']
	// By figuring out whether we're dealing with a numerical or an associative array, we can avoid this issue
	private function __isAssoc($array) {
		return (bool)count(array_filter(array_keys($array), 'is_string'));
	}

	private function __checkType($search, $type) {
		// Here we have to figure out how to best map the indicator to an attribute. This is an initial mapping, needs lots of tweaks still
		// Keep in mind: names starting with "temp" will only be used for composite types, then changed to Other -> other.
		switch ($search) {
			case 'FileItem/FileName':
			case 'DriverItem/DriverName':
			case 'FileItem/FullPath':
				return array('Payload installation', 'filename', true);
				break;
			case 'FileItem/Md5sum':
				return array('Payload installation', 'md5', true);
				break;
			case 'TaskItem/sha1sum':
			case 'FileItem/Sha1sum':
				return array('Payload installation', 'sha1', true);
				break;
			case 'FileItem/Sha256sum':
				return array('Payload installation', 'sha256', true);
				break;
			case 'PortItem/remoteIP':
				return array('Network activity', 'ip-src', true);
				break;
			case 'RouteEntryItem/Gateway':
			case 'RouteEntryItem/Destination':
				if ( $type === 'IP') {
					return array('Network activity', 'ip-dst', true);
					break;
				}
				if ( $type === 'string' or $type === 'String' ) {
					return array('Network activity', 'domain', true);
					break;
				}
			case 'Network/DNS':
				return array('Network activity', 'domain', true);
				break;
			case 'Email/To':
				return array('Payload delivery', 'email-dst', true);
				break;
			case 'Email/From':
				return array('Payload delivery', 'email-src', true);
				break;
			case 'Email/Subject':
				return array('Payload delivery', 'email-subject', true);
				break;
			case 'Email/Attachment/Na':
				return array('Payload delivery', 'email-attachment', true);
				break;
			case 'UrlHistoryItem/URL':
			case 'UrlHistoryItem/VisitFrom':
			case 'FileDownloadHistoryItem/SourceURL':
			case 'FormHistoryItem/FormSubmitURL':
				return array('Network activity', 'url', true);
				break;
			case 'Network/UserAgent':
				return array('Network activity', 'user-agent', false);
				break;
			case 'RegistryItem/KeyPath':
			case 'RegistryItem/Modified':
			case 'RegistryItem/Path':
				return array('Persistence mechanism', 'regkey', true);
				break;
			case 'RegistryItem/ValueName':
				return array('Persistence mechanism', 'tempRegName', false);
			case 'Snort/Snort':
				return array('Network activity', 'snort', true);
				break;
			case 'TaskItem/Comment':
				return array('Other', 'comment', false);
				break;
			case 'CookieHistoryItem/HostName':
			case 'FormHistoryItem/HostName':
			case 'SystemInfoItem/Hostname':
			case 'UrlHistoryItem/HostName':
			case 'DnsEntryItem/RecordName':
			case 'DnsEntryItem/Host':
				return array('Network activity', 'hostname', true);
				break;
			case 'RegistryItem/Text':
			case 'RegistryItem/Value':
				return array('Persistence mechanism', 'tempRegValue', false);
				break;
				// We don't keep the following, they are often used with AND and a filename. We'll only keep the filename in those cases.
			case 'FileItem/PEInfo/DigitalSignature/CertificateSubject':
			case 'FileItem/PEInfo/DigitalSignature/SignatureExists':
				return array('Payload delivery', 'tempCertificateSubject', false);
				break;
			case 'FileItem/PEInfo/DetectedAnomalies/string':
				return array('Payload delivery', 'pattern-in-file', true);
				break;
		}
		return array('Other', 'other', false);
	}

	// Create the array used in the visualisation of the original ioc file
	private function __graphBranches($array, $level) {
		$level++;
		$spaces = '';
		for ($i = 1; $i < $level; $i++) {
			$spaces .= '     ';
		}
		foreach ($array['leaves'] as $leaf) {
			$this->graph[] = array(($spaces . '|__' . $leaf['search'] . ': ' . $leaf['condition'] . ': ' . $leaf['value']), $leaf['success']);
		}
		foreach ($array['branches'] as $branch) {
			$this->graph[] = array (($spaces . '|__' . $branch['type']), $branch['success']);
			$this->__graphBranches($branch, $level);
		}
	}

	private function __resolveBranch($branch, $uuid, $type, &$leaves, $root = false) {
		// Resolve any deeper branching before we attempt to resolve this, as we might be able to turn it into a single attribute
		foreach ($branch['branches'] as $key => $value) {
			$r = $this->__resolveBranch($value, $branch['uuid'], $branch['type'], $branch['leaves']);
			if ($r === 'getFromTemp') {
				unset($branch['branches'][$key]);
				foreach ($this->tempLeaves as $tempLeaf) {
					$branch['leaves'][] = $tempLeaf;
				}
				$this->tempLeaves = array();
			} else {
				$branch['branches'][$key] = $r;
				if (!$branch['branches'][$key]) {
					unset($branch['branches'][$key]);
				}
			}
		}
		// if marked for rebasing the indices:
		$branch['branches'] = array_values($branch['branches']);
		// First, let's see if we can get rid of some of the indicators in here
		foreach ($branch['leaves'] as $key => $value) {
			if ($this->__checkOmit($value)) {
				unset($branch['leaves'][$key]);
			}
		}
		// try to reverse AND-OR
		// If we are in an AND branch that only has 1 level of extra branching, consisting of only OR branches
		if ($branch['type'] === 'AND' && ((count($branch['branches']) > 1) || (count($branch['branches']) > 0 && count($branch['leaves']) > 0))) {
			// There's hope to be able to resolve the branch
			$hope = true;
			$combinations = 1;
			$ors = 0;
			$uuid = $branch['uuid'];
			// go through each of the branches contained in the AND branch
			foreach ($branch['branches'] as $bk => $bv) {
				// if the branch is an AND branch or if the branch further branches out - lose hope
				if ($bv['type'] === 'AND' || count($bv['branches']) > 0) $hope = false;
				$combinations = $combinations * count($bv['leaves']);
				$ors++;
			}

			// if the number of possible combinations is higher than the hard limit, don't even attempt trying to resolve the AND branch
			if ($combinations > $this->hardLimit) $hope = false;

			if ($hope && count($branch['branches']) > 0) {
				$combinations = $this->__findCombinations($branch['branches']);
				$current['branches'] = array('type' => 'AND', 'branches' => array());
				$temp = array();
				foreach ($combinations as $key => $current) {
					foreach ($branch['leaves'] as $leaf) {
						array_push($combinations[$key], $leaf);
					}
					$temp[] = array('type' => 'AND', 'leaves' => $current, 'branches' => array(), 'uuid' => $uuid);
				}
				$branch['type'] = 'OR';
				$branch['leaves'] = array();
				$branch['branches'] = $temp;
				// Try to resolve all the branches again now that they've been altered
				foreach ($branch['branches'] as $key => $value) {
					$branch['branches'][$key] = $this->__resolveBranch($value, $branch['uuid'], $branch['type'], $branch['leaves']);
					if ($branch['branches'][$key] == null) {
						unset($branch['branches'][$key]);
					}
				}
			}
		}


		// Resolve any AND branches without any further branching
		if (count($branch['leaves']) != 0 && count($branch['branches']) == 0 && $branch['type'] === 'AND') {
			$branch['leaves'] = array($this->__resolveAndBranch($branch['leaves'], $uuid));
			if ($branch['leaves'][0] == null) {
				unset($branch['leaves']);
			} else {
				$this->saved_uuids[] = $branch['uuid'];
			}
		}
		if (isset($branch['leaves']) && count($branch['leaves']) == 1 && count($branch['branches']) == 0) {
			$leaves[] = $branch['leaves'][0];
			$branch['leaves'] = $leaves;
		}

		if (($branch['type'] == 'OR') && count($branch['branches']) == 0 && count($branch['leaves']) != 0) {
			if (!$root) {
				$this->tempLeaves = $branch['leaves'];
				$this->saved_uuids[] = $uuid;
				return 'getFromTemp';
			}
		}
		// If we have no branches and no leaves left after all of this, return nothing and unset this branch
		if ((!isset($branch['leaves']) || count($branch['leaves']) == 0) && count($branch['branches']) == 0 && !isset($branch['long_info'])) {
			return;
		}
		return $branch;
	}

	// Find the possible combinations of several OR branches within an AND branch
	private function __findCombinations($arrays, $i = 0) {
		if (!isset($arrays[$i]['leaves'])) {
			return array();
		}

		// If there's only 1 OR branch, return the indicatorItems in the same format as if there were more. It can still get ANDed with the leaves of the parent branch
		if ($i == count($arrays) - 1) {
			$temp = array();
			foreach ($arrays[$i]['leaves'] as $current) {
				$temp[] = array($current);
			}
			return $temp;
		}

		// get combinations from subsequent arrays
		$tmp = $this->__findCombinations($arrays, $i + 1);

		$result = array();
		// Build an array of AND-ed combinations
		foreach ($arrays[$i]['leaves'] as $v) {
			foreach ($tmp as $t) {
				// Watch out for associative vs non associative arrays, we want each indicator to be assigned enclosed in a numerical array instead of just merging all of its associative values into the AND array
				if ($this->__isAssoc($t)) {
					$result[] = is_array($t) ?
					array_merge(array($v), array($t)) :
					array($v, $t);
				} else {
					$result[] = is_array($t) ?
					array_merge(array($v), $t) :
					array($v, $t);
				}
			}
		}
		return $result;
	}

	private function __resolveAndBranch($array, $id) {
		// Let's see how many indicators we have left and take action accordingly
		$count = count($array);
		if ($count == 0) {
			return null;
		} else if ($count == 1) {
			return $array[0];
		} else {
			$att = array();
			for ($i=0; $i < $count; $i++) {
				$att[$i] = $this->__analyseIndicator($array[$i]);
			}
			$attempt = $this->__convertToCompositeAttribute($att, $id);
			if ($attempt) {
				$attempt['uuid'] = $att[0]['uuid'];
				$this->saved_uuids[] = $id;
				foreach ($att as $temp) {
					$this->saved_uuids[] = $temp['uuid'];
				}
				return $attempt;
			}
			return null;
		}
	}

	// We have a list of attributes that we can omit in nested logical branches - the idea is to always make sure that we don't insert attributes
	// that in the source were specified to be taken together with another indicator only.
	private function __checkOmit($leaf) {
		foreach ($this->discardableIndicators as $current) {
			// check if search is set - if not, it's already a composite attribute
			if (isset($leaf['search']) && $leaf['search'] === $current) {
				return true;
			}
		}
		return false;
	}

	// Attempt to convert the two attributes retrieved from an AND indicator into a single attribute, if they are eligible to be converted. If not, add it to the array of failures.
	private function __convertToCompositeAttribute($att, $uuid) {
		// check if the current attribute is one of the known pairs saved in the array $attributePairs
		$tempArray = $values = $uuids = array();
		foreach ($att as $temp) $tempArray[$temp['type']] = $temp;
		ksort($tempArray);
		$keys = array_keys($tempArray);
		$att = array_values($tempArray);
		foreach ($att as $temp) {
			$values[] = $temp['value'];
			$uuids[] = $temp['uuid'];
		}

		foreach ($this->attributeComposition as $composition) {
			if (count($composition['components']) != count($att)) continue;
			if ($keys === $composition['components']) {
				$value = $composition['replace'];
				foreach ($values as $k => $v) {
					$value = str_replace('$' . $k, $v, $value);
				}
				return array(
						'type' => $composition['returnFormat'],
						'category' => $composition['returnCategory'],
						'value' => $value,
						'to_ids' => $this->typeToIdsSettings[$composition['returnFormat']],
						'distribution' => $this->distribution,
						'comment' => 'OpenIOC import from file ' . $this->filename . ' - Original UUIDs:' . PHP_EOL . implode(PHP_EOL, $uuids),
				);
			}
		}
		// If no match found, return false, it's not a valid composite attribute for MISP
		return false;
	}
}
?>
