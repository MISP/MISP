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

        public function getTree($cluster)
        {
            $treeRight = array(array(
                'GalaxyCluster' => $cluster['GalaxyCluster'],
                'children' => array()
            ));
            // add relation info between the two clusters
            foreach($cluster['GalaxyClusterRelation'] as $relation) {
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
            if (!empty($cluster['TargettingClusterRelation'])) {
                foreach($cluster['TargettingClusterRelation'] as $relation) {
                    if (isset($relation['GalaxyCluster'])) { // not set if Cluster is unkown
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
