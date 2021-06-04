<?php
    class ClusterRelationsGraphTool
    {
        private $GalaxyCluster;
        private $user;
        private $lookup = array();

        public function __construct(array $user, GalaxyCluster $GalaxyCluster)
        {
            $this->GalaxyCluster = $GalaxyCluster;
            $this->user = $user;
        }
        
        /**
         * getNetwork Returns the network for the provided clusters
         *
         * @param  array $clusters
         * @param  bool $keepNotLinkedClusters If true, includes nodes not linked to others
         * @param  bool $includeReferencingRelation If true, fetch and includes nodes referencing the $clusters passed
         * @return array The constructed network with nodes and links as keys
         */
        public function getNetwork(array $clusters, $keepNotLinkedClusters=false, $includeReferencingRelation=false)
        {
            $rootNodeIds = Hash::extract($clusters, '{n}.GalaxyCluster.id');
            $nodes = array();
            $links = array();
            foreach ($clusters as $cluster) {
                $this->lookup[$cluster['GalaxyCluster']['uuid']] = $cluster;
            }
            foreach ($clusters as $cluster) {
                if (!empty($cluster['GalaxyCluster']['GalaxyClusterRelation'])) {
                    foreach ($cluster['GalaxyCluster']['GalaxyClusterRelation'] as $relation) {
                        $referencedClusterUuid = $relation['referenced_galaxy_cluster_uuid'];
                        if (!isset($this->lookup[$referencedClusterUuid])) {
                            $referencedCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->user, array(
                                'conditions' => array('GalaxyCluster.uuid' => $referencedClusterUuid),
                                'contain' => array('Org', 'Orgc', 'SharingGroup'),
                            ));
                            if (!empty($referencedCluster)) {
                                $this->lookup[$referencedClusterUuid] = $referencedCluster[0];
                            } else {
                                $this->lookup[$referencedClusterUuid] = array();
                            }
                        }
                        $referencedCluster = $this->lookup[$referencedClusterUuid];
                        if (!empty($referencedCluster)) {
                            $nodes[$referencedClusterUuid] = $referencedCluster['GalaxyCluster'];
                            $nodes[$referencedClusterUuid]['group'] = $referencedCluster['GalaxyCluster']['type'];
                            $nodes[$relation['galaxy_cluster_uuid']] = $cluster['GalaxyCluster'];
                            $nodes[$relation['galaxy_cluster_uuid']]['group'] = $cluster['GalaxyCluster']['type'];
                            if (isset($rootNodeIds[$relation['galaxy_cluster_uuid']])) {
                                $nodes[$relation['galaxy_cluster_uuid']]['isRoot'] = true;
                            }
                            $links[] = array(
                                'source' => $relation['galaxy_cluster_uuid'],
                                'target' =>   $referencedClusterUuid,
                                'type' => $relation['referenced_galaxy_cluster_type'],
                                'tag' =>  isset($relation['Tag']) ? $relation['Tag'] : array(),
                            );
                        }
                    }
                } elseif ($keepNotLinkedClusters) {
                    if (!isset($nodes[$cluster['GalaxyCluster']['uuid']])) {
                        $nodes[$cluster['GalaxyCluster']['uuid']] = $cluster['GalaxyCluster'];
                        $nodes[$cluster['GalaxyCluster']['uuid']]['group'] = $cluster['GalaxyCluster']['type'];
                        if (isset($rootNodeIds[$cluster['GalaxyCluster']['uuid']])) {
                            $nodes[$cluster['GalaxyCluster']['uuid']]['isRoot'] = true;
                        }
                    }
                }

                if ($includeReferencingRelation) { // fetch and add clusters referrencing the current graph
                    $referencingRelations = $this->GalaxyCluster->GalaxyClusterRelation->fetchRelations($this->user, array(
                        'conditions' => array(
                            'referenced_galaxy_cluster_uuid' => $cluster['GalaxyCluster']['uuid']
                        ),
                        'contain' => array('SharingGroup'),
                    ));
                    if (!empty($referencingRelations)) {
                        foreach ($referencingRelations as $relation) {
                            $referencingClusterUuid = $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'];
                            if (!isset($this->lookup[$referencingClusterUuid])) {
                                $referencedCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->user, array(
                                    'conditions' => array('GalaxyCluster.uuid' => $referencingClusterUuid),
                                    'contain' => array('Org', 'Orgc', 'SharingGroup'),
                                ));
                                $this->lookup[$referencingClusterUuid] = !empty($referencedCluster) ? $referencedCluster[0] : array();
                            }
                            $referencingCluster = $this->lookup[$referencingClusterUuid];
                            if (!empty($referencingCluster)) {
                                $nodes[$referencingClusterUuid] = $referencingCluster['GalaxyCluster'];
                                $nodes[$referencingClusterUuid]['group'] = $referencingCluster['GalaxyCluster']['type'];
                                $links[] = array(
                                    'source' => $referencingClusterUuid,
                                    'target' =>   $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'],
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
    }
