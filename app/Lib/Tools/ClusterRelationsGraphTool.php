<?php
    class ClusterRelationsGraphTool
    {
        private $GalaxyCluster = false;
        private $user = false;
        private $lookup = array();

        public function construct($user, $GalaxyCluster)
        {
            $this->GalaxyCluster = $GalaxyCluster;
            $this->user = $user;
            return true;
        }

        public function getNetwork($clusters, $rootNodeIds=array(), $keepNotLinkedClusters=false, $includeReferencingRelation=false)
        {
            $nodes = array();
            $links = array();
            foreach ($clusters as $cluster) {
                $this->lookup[$cluster['GalaxyCluster']['id']] = $cluster;
            }
            foreach ($clusters as $cluster) {
                $cluster = $this->attachOwnerInsideCluster($cluster);
                if (!empty($cluster['GalaxyClusterRelation'])) {
                    foreach($cluster['GalaxyClusterRelation'] as $relation) {
                        $referencedClusterId = $relation['referenced_galaxy_cluster_id'];
                        if (!isset($this->lookup[$referencedClusterId])) {
                            $referencedCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->user, array(
                                'conditions' => array('GalaxyCluster.id' => $referencedClusterId),
                                'contain' => array('Org', 'Orgc', 'SharingGroup'),
                            ));
                            if (!empty($referencedCluster)) {
                                $referencedCluster[0] = $this->attachOwnerInsideCluster($referencedCluster[0]);
                                $this->lookup[$referencedClusterId] = $referencedCluster[0];
                            } else {
                                $this->lookup[$referencedClusterId] = array();
                            }
                        }
                        $referencedCluster = $this->lookup[$referencedClusterId];
                        if (!empty($referencedCluster)) {
                            $nodes[$referencedClusterId] = $referencedCluster['GalaxyCluster'];
                            $nodes[$referencedClusterId]['group'] = $referencedCluster['GalaxyCluster']['type'];
                            $nodes[$relation['galaxy_cluster_id']] = $cluster['GalaxyCluster'];
                            $nodes[$relation['galaxy_cluster_id']]['group'] = $cluster['GalaxyCluster']['type'];
                            if (isset($rootNodeIds[$relation['galaxy_cluster_id']])) {
                                $nodes[$relation['galaxy_cluster_id']]['isRoot'] = true;
                            }
                            $links[] = array(
                                'source' => $relation['galaxy_cluster_id'],
                                'target' =>   $referencedClusterId,
                                'type' => $relation['referenced_galaxy_cluster_type'],
                                'tag' =>  isset($relation['Tag']) ? $relation['Tag'] : array(),
                            );
                        }
                    }
                } elseif ($keepNotLinkedClusters) {
                    if (!isset($nodes[$cluster['GalaxyCluster']['id']])) {
                        $nodes[$cluster['GalaxyCluster']['id']] = $cluster['GalaxyCluster'];
                        $nodes[$cluster['GalaxyCluster']['id']]['group'] = $cluster['GalaxyCluster']['type'];
                        if (isset($rootNodeIds[$cluster['GalaxyCluster']['id']])) {
                            $nodes[$cluster['GalaxyCluster']['id']]['isRoot'] = true;
                        }
                    }
                }

                if ($includeReferencingRelation) { // fetch and add clusters referrencing the current graph
                    $referencingRelations = $this->GalaxyCluster->GalaxyClusterRelation->fetchRelations($this->user, array(
                        'conditions' => array(
                            'referenced_galaxy_cluster_id' => $cluster['GalaxyCluster']['id']
                        )
                    ));
                    if (!empty($referencingRelations)) {
                        foreach($referencingRelations as $relation) {
                            $referencingClusterId = $relation['GalaxyClusterRelation']['galaxy_cluster_id'];
                            if (!isset($this->lookup[$referencingClusterId])) {
                                $referencedCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->user, array(
                                    'conditions' => array('GalaxyCluster.id' => $referencingClusterId)
                                ));
                                $this->lookup[$referencingClusterId] = !empty($referencedCluster) ? $referencedCluster[0] : array();
                            }
                            $referencingCluster = $this->lookup[$referencingClusterId];
                            if (!empty($referencingCluster)) {
                                $referencingCluster = $this->attachOwnerInsideCluster($referencingCluster);
                                $nodes[$referencingClusterId] = $referencingCluster['GalaxyCluster'];
                                $nodes[$referencingClusterId]['group'] = $referencingCluster['GalaxyCluster']['type'];
                                $links[] = array(
                                    'source' => $referencingClusterId,
                                    'target' =>   $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_id'],
                                    'type' => $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_type'],
                                    'tag' =>  isset($relation['Tag']) ? $relation['Tag'] : array(),
                                );
                            }
                        }
                    }
                }
            }
            return array('nodes' => array_values($nodes), 'links' => $links);
        }

        private function attachOwnerInsideCluster($cluster)
        {
            if (!empty($cluster['Org']) && !isset($cluster['GalaxyCluster']['Org'])) {
                $cluster['GalaxyCluster']['Org'] = array(
                    'id' => $cluster['Org']['id'],
                    'name' => $cluster['Org']['name'],
                );
            }
            if (!empty($cluster['Orgc']) && !isset($cluster['GalaxyCluster']['Orgc'])) {
                $cluster['GalaxyCluster']['Orgc'] = array(
                    'id' => $cluster['Orgc']['id'],
                    'name' => $cluster['Orgc']['name'],
                );
            }
            if (!empty($cluster['SharingGroup']) && !isset($cluster['GalaxyCluster']['SharingGroup'])) {
                $cluster['GalaxyCluster']['SharingGroup'] = array(
                    'id' => $cluster['SharingGroup']['id'],
                    'name' => $cluster['SharingGroup']['name'],
                    'description' => $cluster['SharingGroup']['description'],
                );
            }
            return $cluster;
        }
    }
