<?php
    class ClusterRelationsTreeTool
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
        
        /**
         * getTree Creates the relation tree with referencing clusters (left) and referenced clusters (right) for the given cluster
         *
         * @param  array $cluster
         * @return array
         */
        public function getTree(array $cluster)
        {
            $relationCache = []; // Needed as some default clusters have the same UUID
            $treeRight = array(array(
                'GalaxyCluster' => $cluster['GalaxyCluster'],
                'children' => array()
            ));
            // add relation info between the two clusters
            foreach ($cluster['GalaxyCluster']['GalaxyClusterRelation'] as $relation) {
                if (empty($relation['GalaxyCluster'])) { // unkown cluster, create placeholder
                    $relation['GalaxyCluster'] = array(
                        'uuid' => $relation['referenced_galaxy_cluster_uuid'],
                        'type' => 'unkown galaxy',
                        'value' => $relation['referenced_galaxy_cluster_uuid'],
                    );
                }
                $tmp = array(
                    'Relation' => array_diff_key($relation, array_flip(array('GalaxyCluster'))),
                    'children' => array(
                        array('GalaxyCluster' => $relation['GalaxyCluster']),
                    )
                );
                $treeRight[0]['children'][] = $tmp;
            }
    
            $treeLeft = array(array(
                'GalaxyCluster' => $cluster['GalaxyCluster'],
                'children' => array()
            ));
            if (!empty($cluster['GalaxyCluster']['TargetingClusterRelation'])) {
                foreach ($cluster['GalaxyCluster']['TargetingClusterRelation'] as $relation) {
                    if (isset($relation['GalaxyCluster']) && !isset($relationCache[$relation['GalaxyCluster']['uuid']])) { // not set if cluster is unkown
                        $relationCache[$relation['GalaxyCluster']['uuid']] = true;
                        $tmp = array(
                            'Relation' => array_diff_key($relation, array_flip(array('GalaxyCluster'))),
                            'children' => array(
                                array('GalaxyCluster' => $relation['GalaxyCluster']),
                            )
                        );
                        $treeLeft[0]['children'][] = $tmp;
                    }
                }
            }
    
            $tree = array(
                'right' => $treeRight,
                'left' => $treeLeft,
            );
            return $tree;
        }
    }
