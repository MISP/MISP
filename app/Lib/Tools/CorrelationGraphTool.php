<?php
  class CorrelationGraphTool {

    private $__lookupTables = array();
    private $__related_events = array();
    private $__related_attributes = array();
    private $__eventModel = false;
    private $__taxonomyModel = false;
    private $__galaxyClusterModel = false;
    private $__user = false;
    private $__json = array();

    public function construct($eventModel, $taxonomyModel, $galaxyClusterModel, $user, $json) {
      $this->__eventModel = $eventModel;
      $this->__taxonomyModel = $taxonomyModel;
      $this->__galaxyClusterModel = $galaxyClusterModel;
      $this->__user = $user;
      $this->__json = $json;
      $this->__lookupTables = array(
        'analysisLevels' => $this->__eventModel->analysisLevels,
        'distributionLevels' => $this->__eventModel->Attribute->distributionLevels
      );
      return true;
    }

    private function __expandEvent($id) {
      $event = $this->__eventModel->fetchEvent($this->__user, array('eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1, 'includeGalaxy' => 1));
      if (empty($event)) return $this->__json;
      $this->cleanLinks();
      $event[0]['Event']['Orgc'] = $event[0]['Orgc'];
      $current_event_id = $this->__createNode('event', $event[0]['Event'], true);
      if (!empty($event[0]['RelatedEvent'])) {
        foreach ($event[0]['RelatedEvent'] as $re) {
          $this->__related_events[$re['Event']['id']] = $re['Event'];
        }
      }
      if (!empty($event[0]['RelatedAttribute'])) $this->__related_attributes = $event[0]['RelatedAttribute'];
      if (!empty($event[0]['EventTag'])) {
        $tags = array();
        foreach ($event[0]['EventTag'] as $et) {
          $tags[] = $et['Tag'];
        }
        $this->__handleTags($tags, $current_event_id);
      }

      if (!empty($event[0]['Galaxy'])) {
        $this->__handleGalaxies($event[0]['Galaxy'], $current_event_id);
      }

      if (!empty($event[0]['Object'])) {
        $this->__handleObjects($event[0]['Object'], $current_event_id);
      }

      if (!empty($event[0]['Attribute'])) {
        $this->__handleAttributes($event[0]['Attribute'], $current_event_id);
      }
    }

    public function buildGraphJson($id, $type = 'event', $action = 'create') {
      if ($action == 'delete') {
        return $this->__json;
      }
  		switch ($type) {
        case 'event':
          $this->__expandEvent($id);
          break;
        case 'galaxy':
          $this->__expandGalaxy($id);
          break;
        case 'tag':
          $this->__expandTag($id);
          break;
      }
  		return $this->__json;
  	}

    private function __deleteObject($id) {
      $this->cleanLinks();
      return $this->__json;
    }

    private function __handleObjects($objects, $anchor_id, $full = false) {
      foreach ($objects as $k => $object) {
        $include = $full;
        if (!$include) {
          foreach ($object['Attribute'] as $attribute) {
            if (isset($this->__related_attributes[$attribute['id']])) {
              $include = true;
              continue;
            }
          }
        }
        if ($include) {
          $current_object_id = $this->__createNode('object', $object);
          $this->__addLink($anchor_id, $current_object_id);
          $this->__handleAttributes($object['Attribute'], $current_object_id, true, 50);
        }
      }
    }

    private function __handleAttributes($attributes, $anchor_id, $full = false, $linkDistance = 150) {
      foreach ($attributes as $k => $attribute) {
        if ($full || isset($this->__related_attributes[$attribute['id']])) {
          $current_attribute_id = $this->__createNode('attribute', $attribute);
          $this->__addLink($anchor_id, $current_attribute_id, $linkDistance);
          if (isset($this->__related_attributes[$attribute['id']])) {
            foreach ($this->__related_attributes[$attribute['id']] as $relation) {
              $found = $this->graphJsonContains('event', $relation);
              if ($found !== false) {
                $this->__addLink($found, $current_attribute_id);
              } else {
                $current_relation_id = $this->__createNode('event', $this->__related_events[$relation['id']]);
                $this->__addLink($current_attribute_id, $current_relation_id);
              }
            }
          }
        }
      }
    }

    private function __addTag($id) {
      $tag = $this->__eventModel->EventTag->Tag->find('first', array(
        'conditions' => array('Tag.id' => $id),
        'recursive' => -1
      ));
      return $this->__createNode('tag', $tag['Tag']);
    }

    private function __handleTags($tags, $anchor_id) {
      foreach ($tags as $tag) {
        if (strpos($tag['name'], 'misp-galaxy:') === 0) {
          continue;
        }
        $taxonomy = $this->__taxonomyModel->getTaxonomyForTag($tag['name']);
        if (!empty($taxonomy)) {
          $tag['taxonomy'] = $taxonomy['Taxonomy']['namespace'];
          $tag['taxonomy_description'] = $taxonomy['Taxonomy']['description'];
          if (isset($taxonomy['TaxonomyEntry'])) {
            $tag['description'] = empty($taxonomy['TaxonomyEntry']['expanded']) ? '' : $taxonomy['TaxonomyEntry']['expanded'];
          } else {
            $tag['description'] = empty($taxonomy['TaxonomyPredicate']['expanded']) ? '' : $taxonomy['TaxonomyPredicate']['expanded'];
          }
        }
        $current_tag_id = $this->__createNode('tag', $tag);
        $this->__addLink($anchor_id, $current_tag_id, 100);
      }
    }

    private function __expandTag($id) {
      $current_tag_id = $this->graphJsonContains('tag', array('id' => $id));
      if (empty($current_tag_id)) {
        $current_tag_id = $this->__addTag($id);
      }
      $this->cleanLinks();
      $events = $this->__eventModel->EventTag->Tag->fetchSimpleEventsForTag($id, $this->__user);
      foreach ($events as $event) {
        $current_event_id = $this->__createNode('event', $event);
        $this->__addLink($current_tag_id, $current_event_id, 100);
      }
      $this->_json['nodes'][$current_tag_id]['expanded'] = 1;
    }

    private function __handleGalaxies($galaxies, $anchor_id) {
      foreach ($galaxies as $galaxy) {
        $current_galaxy_id = $this->__createNode('galaxy', $galaxy);
        $this->__addLink($anchor_id, $current_galaxy_id);
      }
    }

    private function __expandGalaxy($id) {
      if (!empty($this->__json['nodes'])) {
        foreach ($this->__json['nodes'] as $k => $node) {
          if ($node['type'] == 'galaxy' && $node['id'] == $id) {
            $current_galaxy_id = $k;
            $tag_name = $node['tag_name'];
          }
        }
      }
      if (empty($current_galaxy_id)) {
        $current_galaxy_id = $this->__addGalaxy($id);
      }
      $this->cleanLinks();
      $events = $this->__eventModel->EventTag->Tag->fetchSimpleEventsForTag($this->__json['nodes'][$current_galaxy_id]['tag_name'], $this->__user, true);
      foreach ($events as $event) {
        $current_event_id = $this->__createNode('event', $event);
        $this->__addLink($current_event_id, $current_galaxy_id);
      }
      $this->_json['nodes'][$current_galaxy_id]['expanded'] = 1;
    }

    private function __addGalaxy($id) {
      $temp = $this->__galaxyClusterModel->getCluster($id);
      // move stuff around to resemble the galaxies attached to events
      $galaxy = $temp['GalaxyCluster']['Galaxy'];
      unset($temp['GalaxyCluster']['Galaxy']);
      $galaxy['GalaxyCluster'][0] = $temp['GalaxyCluster'];
      return $this->__createNode('galaxy', $galaxy);
    }

    private function __addLink($from_id, $to_id, $linkDistance = 150) {
      $link = $this->graphJsonContainsLink($from_id, $to_id);
      if ($link === false) $this->__json['links'][] = array('source' => $from_id, 'target' => $to_id, 'linkDistance' => $linkDistance);
    }

    private function __addLinkByUuid($from_uuid, $to_uuid) {
      $from_id = false;
      $to_id = false;
      if ($from_uuid == $to_uuid) {
        return false;
      }
      foreach ($this->__json['nodes'] as $k => $node) {
        if ($node['uuid'] === $from_uuid) {
          $from_id = $k;
        }
        if ($node['uuid'] === $to_uuid) {
          $to_id = $k;
        }
      }
      if (!empty($from_id) && !empty($to_id)) {
        return $this->__addLink($from_id, $to_id);
      }
      return false;
    }

    private function __createNode($type, $data, $expand = false) {
      $current_id = $this->graphJsonContains($type, $data);
      if ($current_id === false) {
        $node = false;
        switch ($type) {
          case 'galaxy':
            $node = array(
              'unique_id' => 'galaxy-' . $data['GalaxyCluster'][0]['id'],
              'name' => $data['GalaxyCluster'][0]['value'],
              'galaxy' => $data['name'],
              'type' => 'galaxy',
              'expanded' => $expand,
              'id' => $data['GalaxyCluster'][0]['id'],
              'source' => $data['GalaxyCluster'][0]['source'],
              'tag_name' => $data['GalaxyCluster'][0]['tag_name'],
              'description' => $data['GalaxyCluster'][0]['description'],
              'imgClass' => empty($data['icon']) ? 'globe' : $data['icon'],
              'authors' => !empty($data['GalaxyCluster'][0]['authors']) ? implode(',', $data['GalaxyCluster'][0]['authors']) : '',
              'synonyms' => !empty($data['GalaxyCluster'][0]['meta']['synonyms']) ? implode(',', $data['GalaxyCluster'][0]['meta']['synonyms']) : ''
            );
            break;
          case 'event':
            if ($this->orgImgExists($data['Orgc']['name'])) {
              $image = Configure::read('MISP.baseurl') . '/img/orgs/' . h($data['Orgc']['name']) . '.png';
            } else {
              $image = Configure::read('MISP.baseurl') . '/img/orgs/MISP.png';
            }
            $node = array(
              'unique_id' => 'event-' . $data['id'],
              'name' => '(' . $data['id'] . ') ' . (strlen($data['info']) > 32 ? substr($data['info'], 0, 31) . '...' : $data['info']),
              'type' => 'event',
              'id' => $data['id'],
              'expanded' => $expand,
              'uuid' => $data['uuid'],
              'image' => $image,
              'info' => $data['info'],
              'org' => $data['Orgc']['name'],
              'analysis' => $this->__lookupTables['analysisLevels'][$data['analysis']],
              'distribution' => $this->__lookupTables['distributionLevels'][$data['distribution']],
              'date' => $data['date']
            );
            break;
          case 'tag':
            $node = array(
              'unique_id' => 'tag-' . $data['id'],
              'name' => $data['name'],
              'type' => 'tag',
              'expanded' => $expand,
              'id' => $data['id'],
              'colour' => $data['colour'],
              'imgClass' => empty($data['taxonomy']) ? 'tag' : 'tags',
            );
            if (!empty($data['taxonomy'])) $node['taxonomy'] = $data['taxonomy'];
            if (!empty($data['taxonomy'])) $node['description'] = $data['description'];
            if (!empty($data['taxonomy'])) $node['taxonomy_description'] = $data['taxonomy_description'];
            break;
          case 'attribute':
            $node = array(
              'unique_id' => 'attribute-' . $data['id'],
              'name' => $data['value'],
              'type' => 'attribute',
              'id' => $data['id'],
              'uuid' => $data['uuid'],
              'att_category' => $data['category'],
              'att_type' => $data['type'],
              'image' => '/img/indicator.png',
              'att_ids' => $data['to_ids'],
              'comment' => $data['comment']
            );
            break;
          case 'object':
            $node = array(
              'unique_id' => 'object-' . $data['id'],
              'name' => $data['name'],
              'type' => 'object',
              'id' => $data['id'],
              'uuid' => $data['uuid'],
              'metacategory' => $data['meta-category'],
              'description' => $data['description'],
              'comment' => $data['comment'],
              'imgClass' => 'th-list',
            );
            break;
        }
        $this->__json['nodes'][] = $node;
        $current_id = count($this->__json['nodes'])-1;
      } else {
        if ($expand) {
          $this->__json['nodes'][$current_id]['expanded'] = 1;
        }
      }
      return $current_id;
    }

  	public function cleanLinks() {
  		if (isset($this->__json['nodes']) && isset($this->__json['links'])) {
  			$links = array();
  			foreach ($this->__json['links'] as $link) {
  				$temp = array();
  				foreach ($this->__json['nodes'] as $k => $node) {
  					if ($link['source'] == $node) $temp['source'] = $k;
  					if ($link['target'] == $node) $temp['target'] = $k;
  				}
          $temp['linkDistance'] = $link['linkDistance'];
  				$links[] = $temp;
  			}
  			$this->__json['links'] = $links;
  		} else {
  			if (!isset($this->__json['links'])) {
  				$this->__json['links'] = array();
  			}
  			if (!isset($this->__json['nodes'])) {
  				$this->__json['nodes'] = array();
  			}
  		}
  		return true;
  	}

  	public function orgImgExists($org) {
  		if (file_exists(APP . 'webroot' . DS . 'img' . DS . 'orgs' . DS . $org . '.png')) {
  			return true;
  		}
  		return false;
  	}

  	public function graphJsonContains($type, $element) {
  		if (!isset($this->__json['nodes'])) return false;
  		foreach ($this->__json['nodes'] as $k => $node) {
  			if ($type == 'event' && $node['type'] == 'event' && $node['id'] == $element['id']) {
  				return $k;
  			}
  			if ($type == 'attribute' &&	$node['type'] == 'attribute' &&	$node['name'] == $element['value']) {
  				return $k;
  			}
        if ($type == 'tag' && $node['type'] == 'tag' && $node['id'] == $element['id']) {
          return $k;
        }
        if ($type == 'galaxy' && $node['type'] == 'galaxy' && $node['id'] == $element['GalaxyCluster'][0]['id']) {
          return $k;
        }
        if ($type == 'object' && $node['type'] == 'object' && $node['id'] == $element['id']) {
          return $k;
        }
  		}
  		return false;
  	}
  	public function graphJsonContainsLink($id1, $id2) {
  		if (!isset($this->__json['links'])) return false;
  		foreach ($this->__json['links'] as $k => $link) {
  			if (($link['source'] == $id1 && $link['target'] == $id2) || ($link['source'] == $id2 && $link['target'] == $id1)) {
  				return $k;
  			}
  		}
  		return false;
  	}

  }
