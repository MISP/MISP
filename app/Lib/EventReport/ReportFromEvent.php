<?php
    class ReportFromEvent
    {
        public $acceptedOptions = [
            'raw' => false, // if set to true, MISP elements will be put verbatim into the report instead of their reference
            'include_event_metadata' => true,
            'include_correlations' => true,
            'include_attack_matrix' => true,
        ];

        public function construct($eventModel, $user, $options)
        {
            $this->__eventModel = $eventModel;
            $this->__user = $user;
            $this->__options = array_merge($this->acceptedOptions, $options);
            return true;
        }

        private function getEvent()
        {
            $options = [
                'eventid' => $this->__options['event_id'],
                'metadata' => true,
            ];
            $this->event = $this->__eventModel->fetchEvent($this->__user, $options);
            if (empty($this->event)) {
                throw new NotFoundException(__('Invalid event'));
            }
            $this->event = $this->event[0];
            $this->__eventModel->removeGalaxyClusterTags($this->event);
        }

        private function getAttributes()
        {
            $filterConditions = $this->__eventModel->Attribute->buildFilterConditions($this->__user, $this->__options['conditions']);
            $options = [
                'includeWarninglistHits' => true,
                'includeSightings' => true,
                'includeCorrelations' => true,
                'conditions' => [
                    'Attribute.event_id' => $this->__options['event_id'],
                    $filterConditions
                ]
            ];
            $this->attributes = $this->__eventModel->Attribute->fetchAttributes($this->__user, $options);
        }

        private function getObjects()
        {
            $options = [
                'includeWarninglistHits' => true,
                'includeSightings' => true,
                'includeCorrelations' => true,
            ];
            $filters = [
                'eventid' => $this->__options['event_id'],
            ];
            $filters = array_merge($filters, $this->__options['conditions']);
            $conditions = $this->__eventModel->Object->buildFilterConditions($filters);
            $options['conditions'] = $conditions;
            $this->objects = $this->__eventModel->Object->fetchObjects($this->__user, $options);
        }

        public function generate()
        {
            $this->getEvent();
            $this->getAttributes();
            $this->getObjects();
            $report = '';
            if ($this->__options['include_event_metadata']) {
                $report .= $this->getMarkdownForEventMetadata();
            }
            if ($this->__options['include_correlations']) {
                $report .= $this->mdHeader('4', __('Correlations'));
                $report .= $this->getMarkdownForEventCorrelations();
            }
            $report .= $this->mdHeader('3', __('Objects'));
            $report .= $this->getMarkdownForObjects();
            $report .= $this->mdHeader('3', __('Attributes'));
            $report .= $this->getMarkdownForAttributes();
            if ($this->__options['include_attack_matrix']) {
                $report .= $this->mdHeader('3', __('ATT&CK Matrix'));
                $report .= $this->getMarkdownForAttackMatrix();
            }
            return $report;
        }

        private function getMarkdownForEventMetadata()
        {
            $markdown = $this->mdHeader('2', $this->event['Event']['info']);
            $markdown .= $this->mdList([
                __('Date') => $this->event['Event']['date'],
                __('Last update') => date('Y-m-d H:i:s', $this->event['Event']['timestamp']),
                __('Threat level') => $this->event['ThreatLevel']['name'],
                __('Attribute count') => $this->event['Event']['attribute_count'],
            ], 'key');
            $markdown .= $this->mdHeader('4', __('Tags'));
            $markdown .= $this->getMarkdownForTags(Hash::extract($this->event['EventTag'], '{n}.Tag.name'));
            $markdown .= $this->mdHeader('4', __('Galaxies'));
            $markdown .= $this->getMarkdownForGalaxy($this->event['Galaxy']);
            
            return $markdown;
        }

        private function getMarkdownForTags($tags, $level=1)
        {
            if ($this->__options['raw']) {
                $markdown = $this->mdList($tags, false, $level);
            } else {
                $markdown = $this->mdList(array_map(function ($tag) {
                    return sprintf('@[tag](%s)', $tag);
                }, $tags), false, $level);
            }
            return $markdown;
        }

        private function getMarkdownForGalaxy($galaxies)
        {
            $markdown = '';
            foreach ($galaxies as $galaxy) {
                $markdown .= $this->mdList([
                    __('Name') => $galaxy['name'],
                    __('Description') => $galaxy['description'],
                ], 'key');
                if ($this->__options['raw']) {
                    foreach ($galaxy['GalaxyCluster'] as $cluster) {
                        $markdown .= $this->mdList([
                            __('Name') => $cluster['value'],
                            __('Description') => $cluster['description'],
                        ], 'key', 2);
                    }
                } else {
                    $markdown .= $this->getMarkdownForTags(Hash::extract($galaxy['GalaxyCluster'], '{n}.tag_name'), 2);
                }
            }
            return $markdown;
        }

        private function getMarkdownForObjects()
        {
            $markdown = $this->mdList(array_map(function ($uuid) {
                return sprintf('@[object](%s)', $uuid);
            }, Hash::extract($this->objects, '{n}.Object.uuid')), false);
            return $markdown;
        }

        private function getMarkdownForAttributes()
        {
            $markdown = $this->mdList(array_map(function ($uuid) {
                return sprintf('@[attribute](%s)', $uuid);
            }, Hash::extract($this->attributes, '{n}.Attribute.uuid')), false);
            return $markdown;
        }

        private function getMarkdownForEventCorrelations()
        {
            $correlations = !empty($this->event['RelatedEvent']) ? $this->event['RelatedEvent'] : [];
            $markdown = $this->mdList(Hash::extract($correlations, '{n}.Event.info'), false, 1);
            return $markdown;
        }

        private function getMarkdownForAttackMatrix()
        {
            return '@[galaxymatrix](c4e851fa-775f-11e7-8163-b774922098cd)';
        }

        private function mdHeader($level, $content)
        {
            return str_repeat('#', $level) . ' ' . $content . PHP_EOL;
        }

        private function mdTable($headers, $rows)
        {
            $table = '| ' . implode(' | ', $headers) . ' |' . PHP_EOL;
            $table .= '----------';
            foreach ($rows as $row) {
                $table = '| ' . implode(' | ', $row) . ' |' . PHP_EOL;
            }
            return $table;
        }

        private function mdList($items, $prefix=false, $level=1)
        {
            $list = '';
            foreach ($items as $k => $item) {
                if ($prefix == 'index') {
                    $list .= sprintf('%s%s. %s' . PHP_EOL, str_repeat('  ', $level), $k, $item);
                } elseif ($prefix == 'key') {
                    $list .= sprintf('%s- *%s*: %s' . PHP_EOL, str_repeat('  ', $level), $k, $item);
                } else {
                    $list .= sprintf('%s- %s' . PHP_EOL, str_repeat('  ', $level), $item);
                }
            }
            return $list;
        }
    }