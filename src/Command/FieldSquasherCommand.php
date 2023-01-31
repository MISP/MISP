<?php

namespace App\Command;

use Cake\Console\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use Cake\Filesystem\File;
use Cake\Utility\Hash;
use Cake\Utility\Text;
use Cake\Validation\Validator;
use Cake\Http\Client;

class FieldSquasherCommand extends Command
{
    protected $modelClass = 'Organisations';
    private $targetModel = 'Organisations';

    protected function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        $parser->setDescription('Squash field value from external data source');
        $parser->addArgument('config', [
            'help' => 'JSON configuration file path for the importer.',
            'required' => true
        ]);
        return $parser;
    }

    public function execute(Arguments $args, ConsoleIo $io)
    {
        $this->io = $io;
        $configPath = $args->getArgument('config');
        $config = $this->getConfigFromFile($configPath);
        $this->processConfig($config);
        $this->modelClass = $config['target']['model'];
        $source = $config['source'];

        $table = $this->modelClass;
        $this->loadModel($table);
        $sourceData = $this->getDataFromSource($source);
        $candidateResult = $this->findCanditates($this->{$table}, $config, $sourceData);
        $entitiesSample = array_slice($candidateResult['candidates'], 0, min(10, count($candidateResult['candidates'])));
        $entitiesSample = array_slice($candidateResult['candidates'], 0, min(100, count($candidateResult['candidates'])));
        $noCandidatesSample = array_slice($candidateResult['noCandidatesFound'], 0, min(10, count($candidateResult['noCandidatesFound'])));
        $notExactCandidates = array_slice($candidateResult['notExactCandidates'], 0, min(10, count($candidateResult['notExactCandidates'])));
        $totalNotFound = count($candidateResult['noCandidatesFound']);
        $totalClosestFound = count($candidateResult['notExactCandidates']);
        $totalFound = count($candidateResult['candidates']);

        $this->io->out("Sample of no candidates found (total: {$totalNotFound}):");
        $ioTable = $this->transformEntitiesIntoTable($noCandidatesSample);
        $io->helper('Table')->output($ioTable);
        $filename = 'no_candidates_found_' . time() . '.json';
        $selection = $io->askChoice("Would you like to save these entries on the disk as `{$filename}`", ['Y', 'N'], 'Y');
        if ($selection == 'Y') {
            $this->saveDataOnDisk($filename, $candidateResult['noCandidatesFound']);
        }
        $this->io->out('');

        if (!empty($notExactCandidates)) {
            $this->io->out("Sample of closest candidates found (total not strictly matching: {$totalClosestFound}):");
            $ioTable = $this->transformEntitiesIntoTable($notExactCandidates);
            $io->helper('Table')->output($ioTable);
            $filename = 'closest_candidates_found_' . time() . '.json';
            $selection = $io->askChoice("Would you like to save these entries on the disk as `{$filename}`", ['Y', 'N'], 'Y');
            if ($selection == 'Y') {
                $this->saveDataOnDisk($filename, $candidateResult['notExactCandidates']);
            }
            $this->io->out('');
        }

        $this->io->out("Sample of exact candidates found (total striclty matching: {$totalFound}):");
        $ioTable = $this->transformEntitiesIntoTable($entitiesSample, [
            'id',
            $config['finder']['joinFields']['squashed'],
            $config['target']['squashedField'],
            "{$config['target']['squashedField']}_original_value",
            'based_on_best_match',
            'best_candidates_found',
            'match_score'
            
        ]);
        $io->helper('Table')->output($ioTable);
        $filename = 'replacement_done_' . time() . '.json';
        $selection = $io->askChoice("Would you like to save these entries on the disk as `{$filename}`", ['Y', 'N'], 'Y');
        if ($selection == 'Y') {
            $this->saveDataOnDisk($filename, $candidateResult['candidates']);
        }
        die(1);

        $selection = $io->askChoice('A sample of the data you about to be saved is provided above. Would you like to proceed?', ['Y', 'N'], 'N');
        if ($selection == 'Y') {
            // $this->saveData($this->{$table}, $entities);
        }
    }

    private function saveData($table, $entities)
    {
        $this->loadModel('MetaFields');
        $this->io->verbose('Saving data');
        $progress = $this->io->helper('Progress');
        
        $entities = $table->saveMany($entities);
        if ($entities === false) {
            $this->io->error('Error while saving data');
        }
    }

    private function findCanditates($table, $config, $source)
    {
        $this->io->verbose('Finding candidates');
        if ($config['finder']['type'] == 'exact') {
            $candidateResult = $this->findCanditatesByStrictMatching($table, $config, $source);
        } else if ($config['finder']['type'] == 'closest') {
            $candidateResult = $this->findCanditatesByClosestMatch($table, $config, $source);
        } else {
            $this->io->error('Unsupported search type');
            die(1);
        }
        return $candidateResult;
    }

    private function findCanditatesByStrictMatching($table, $config, $source)
    {
        $squashingObjects = Hash::extract($source, $config['finder']['path']);
        if (empty($squashingObjects)) {
            $this->io->error('finder.path returned nothing');
            return [];
        }
        $values = Hash::extract($squashingObjects, "{n}.{$config['finder']['joinFields']['squashing']}");
        $query = $table->find('list', [
            'keyField' => $config['finder']['joinFields']['squashed'],
            'valueField' => function ($entry) {
                return $entry;
            }
        ])->where([
            "{$config['finder']['joinFields']['squashed']} IN" => $values
        ]);
        $potentialCanditates = $query->toArray();
        $candidates = [];
        $noCandidatesFound = [];

        foreach ($squashingObjects as $squashingObject) {
            $squashingJoinField = Hash::get($squashingObject, $config['finder']['joinFields']['squashing']);
            if (empty($potentialCanditates[$squashingJoinField])) {
                $noCandidatesFound[] = $squashingObject;
            } else {
                $squashingData = Hash::get($squashingObject, $config['squashingData']['squashingField']);
                if (isset($this->{$config['squashingData']['massage']})) {
                    $squashingData = $this->{$config['squashingData']['massage']}($squashingData);
                }
                $squashedTarget = $potentialCanditates[$squashingJoinField];
                $squashedTarget->{"{$config['target']['squashedField']}_original_value"} = $squashedTarget->{$config['target']['squashedField']};
                $squashedTarget->{$config['target']['squashedField']} = $squashingData;
                $candidates[] = $squashedTarget;
            }
        }
        return [
            'candidates' => $candidates,
            'notExactCandidates' => [],
            'noCandidatesFound' => $noCandidatesFound,
        ];
    }

    private function findCanditatesByClosestMatch($table, $config, $source)
    {
        $squashingObjects = Hash::extract($source, $config['finder']['path']);
        if (empty($squashingObjects)) {
            $this->io->error('finder.path returned nothing');
            return [];
        }
        $query = $table->find();
        $allCanditates = $query->toArray();
        $squashingJoinField = $config['finder']['joinFields']['squashing'];
        $squashedJoinField = $config['finder']['joinFields']['squashed'];
        $closestMatchResults = [];

        $squashingObjects = $this->getBestOccurenceSet($squashingObjects, $allCanditates, $squashingJoinField, $squashedJoinField);

        // pick the best match
        foreach ($squashingObjects as $i => $squashingObject) {
            if (empty($squashingObjects[$i]['__scores'])) {
                continue;
            }
            ksort($squashingObjects[$i]['__scores'], SORT_NUMERIC);
            $squashingObjects[$i]['__scores'] = array_slice($squashingObjects[$i]['__scores'], 0, 1, true);
            $bestScore = array_key_first($squashingObjects[$i]['__scores']);
            $squashingObjects[$i]['__scores'][$bestScore] = array_values($squashingObjects[$i]['__scores'][$bestScore])[0];
        }

        $candidates = [];
        $noCandidatesFound = [];
        $notExactCandidates = [];
        $scoreThreshold = !empty($config['finder']['levenshteinScore']) ? $config['finder']['levenshteinScore'] : 10;

        foreach ($squashingObjects as $i => $squashingObject) {
            if (empty($squashingObjects[$i]['__scores'])) {
                $noCandidatesFound[] = $squashingObject;
                continue;
            }
            $bestScore = array_key_first($squashingObject['__scores']);
            $bestMatch = $squashingObject['__scores'][$bestScore];

            $squashingData = Hash::get($squashingObject, $config['squashingData']['squashingField']);
            if (isset($this->{$config['squashingData']['massage']})) {
                $squashingData = $this->{$config['squashingData']['massage']}($squashingData);
            }

            $squashedTarget = $bestMatch;
            if ($bestScore <= $scoreThreshold) {
                $squashedTarget["{$config['target']['squashedField']}_original_value"] = $squashedTarget[$config['target']['squashedField']];
                $squashedTarget['match_score'] = $bestScore;
                $squashedTarget['based_on_best_match_joinFields'] = Hash::get($squashingObject, $squashingJoinField);
                // $squashedTarget['based_on_best_match'] = json_encode($squashingObject);
                $squashedTarget[$config['target']['squashedField']] = $squashingData;
                if ($bestScore > 0) {
                    $notExactCandidates[] = $squashedTarget;
                } else {
                    $candidates[] = $squashedTarget;
                }
            } else {
                $squashingObjectBestMatchInfo = "[{$bestMatch[$squashingJoinField]}, {$bestScore}]";
                $squashingObject['__scores'] = $squashingObjectBestMatchInfo;
                $noCandidatesFound[] = $squashingObject;
            }
        }

        return [
            'candidates' => $candidates,
            'notExactCandidates' => $notExactCandidates,
            'noCandidatesFound' => $noCandidatesFound
        ];
    }

    private function removeCandidatesFromSquashingSet($squashingObjects, $bestMatch, $candidateID)
    {
        foreach ($squashingObjects as $i => $squashingObject) {
            if (Hash::remove($squashingObject, '__scores') == $bestMatch) {
                continue;
            } else {
                foreach ($squashingObject['__scores'] as $score => $candidates) {
                    foreach ($candidates as $j => $candidate) {
                        if ($candidate['id'] == $candidateID) {
                            unset($squashingObjects[$i]['__scores'][$score][$j]);
                        }
                    }
                    if (empty($squashingObjects[$i]['__scores'][$score])) {
                        unset($squashingObjects[$i]['__scores'][$score]);
                    }
                }
            }
        }
        return $squashingObjects;
    }

    private function getBestOccurenceSet($squashingObjects, $allCanditates, $squashingJoinField, $squashedJoinField)
    {
        // Compute proximity score
        foreach ($squashingObjects as $i => $squashingObject) {
            $squashingJoinValue = Hash::get($squashingObject, $squashingJoinField);
            foreach ($allCanditates as $candidate) {
                $squashedJoinValue = Hash::get($candidate, $squashedJoinField);
                $proximityScore = $this->getProximityScore($squashingJoinValue, $squashedJoinValue);
                $closestMatchResults[$candidate['id']][$proximityScore][] = $squashingObject;
                $squashingObjects[$i]['__scores'][$proximityScore][] = $candidate;
            }
        }

        // sort by score
        foreach ($squashingObjects as $i => $squashingObject) {
            ksort($squashingObjects[$i]['__scores'], SORT_NUMERIC);
        }
        foreach ($closestMatchResults as $i => $proximityScore) {
            ksort($closestMatchResults[$i], SORT_NUMERIC);
        }

        // remove best occurence in other matching sets
        foreach ($allCanditates as $candidate) {
            $bestScore = array_key_first($closestMatchResults[$candidate['id']]);
            $bestMatch = $closestMatchResults[$candidate['id']][$bestScore][0];
            $squashingObjects = $this->removeCandidatesFromSquashingSet($squashingObjects, $bestMatch, $candidate['id']);
        }
        return $squashingObjects;
    }

    private function getProximityScore($value1, $value2)
    {
        if ($value1 == $value2) {
            return -1;
        } else {
            return levenshtein(strtolower($value1), strtolower($value2));
        }
    }

    private function getDataFromSource($source)
    {
        $data = $this->getDataFromFile($source);
        if ($data === false) {
            $data = $this->getDataFromURL($source);
        }
        return $data;
    }

    private function getDataFromURL($url)
    {
        $validator = new Validator();
        $validator
            ->requirePresence('url')
            ->notEmptyString('url', 'Please provide a valid source')
            ->url('url');
        $errors = $validator->validate(['url' => $url]);
        if (!empty($errors)) {
            $this->io->error(json_encode(Hash::extract($errors, '{s}'), JSON_PRETTY_PRINT));
            die(1);
        }
        $http = new Client();
        $this->io->verbose('Downloading file');
        $response = $http->get($url);
        return $response->getJson();
    }

    private function getDataFromFile($path)
    {
        $file = new File($path);
        if ($file->exists()) {
            $this->io->verbose('Reading file');
            $data = $file->read();
            $file->close();
            if (!empty($data)) {
                $data = json_decode($data, true);
                if (is_null($data)) {
                    $this->io->error('Error while parsing the source file');
                    die(1);
                }
                return $data;
            }
        }
        return false;
    }

    private function saveDataOnDisk($filename, $data)
    {
        $file = new File($filename, true);
        $file->write(json_encode($data));
        $this->io->out("File saved at: {$file->pwd()}");
        $file->close();
    }

    private function getConfigFromFile($configPath)
    {
        $file = new File($configPath);
        if ($file->exists()) {
            $config = $file->read();
            $file->close();
            if (!empty($config)) {
                $config = json_decode($config, true);
                if (is_null($config)) {
                    $this->io->error('Error while parsing the configuration file');
                    die(1);
                }
                return $config;
            } else {
                $this->io->error('Configuration file cound not be read');
            }
        } else {
            $this->io->error('Configuration file not found');
        }
    }

    private function processConfig($config)
    {
        $allowedModels = ['Organisations', 'Individuals'];
        $allowedFinderType = ['exact', 'closest'];
        if (empty($config['source']) || empty($config['finder']) || empty($config['target']) || empty($config['squashingData'])) {
            $this->io->error('Error while parsing the configuration file, some of these fields are missing: `source`, `finder`, `target`, `squashingData`');
            die(1);
        }
        if (!empty($config['target']['model'])) {
            if (!in_array($config['target']['model'], $allowedModels)) {
                $this->io->error('Error while parsing the configuration file, target.model configuration must be one of: ' . implode(', ', $allowedModels));
                die(1);
            }
        } else {
            $this->io->error('Error while parsing the configuration file, target.model configuration is missing');
            die(1);
        }

        if (empty($config['finder']['path']) || empty($config['finder']['joinFields'])) {
            $this->io->error('Error while parsing the configuration file, some finder fields are missing');
            die(1);
        }
        if (!empty($config['finder']['type'])) {
            if (!in_array($config['finder']['type'], $allowedFinderType)) {
                $this->io->error('Error while parsing the configuration file, finder.type configuration must be one of: ' . implode(', ', $allowedFinderType));
                die(1);
            }
        } else {
            $this->io->error('Error while parsing the configuration file, finder.type configuration is missing');
            die(1);
        }
    }

    private function transformResultSetsIntoTable($result, $header=[])
    {
        $table = [[]];
        if (!empty($result)) {
            $tableHeader = empty($header) ? array_keys($result[0]) : $header;
            $tableContent = [];
            foreach ($result as $item) {
                if (empty($header)) {
                    $tableContent[] = array_map('strval', array_values($item));
                } else {
                    $row = [];
                    foreach ($tableHeader as $key) {
                        $row[] = (string) $item[$key];
                    }
                    $tableContent[] = $row;
                }
            }
            $table = array_merge([$tableHeader], $tableContent);
        }
        return $table;
    }

    private function transformEntitiesIntoTable($entities, $header=[])
    {
        $table = [[]];
        if (!empty($entities)) {
            if (empty($header)) {
                if (!is_array($entities[0])) {
                    $tableHeader = array_keys(Hash::flatten($entities[0]->toArray()));
                } else {
                    $tableHeader = array_keys($entities[0]);
                }
            } else {
                $tableHeader = $header;
            }
            $tableContent = [];
            foreach ($entities as $entity) {
                $row = [];
                foreach ($tableHeader as $key) {
                    $subKeys = explode('.', $key);
                    if (is_array($entity[$key])) {
                        $row[] = json_encode($entity[$key]);
                    } else {
                        $row[] = (string) $entity[$key];
                    }
                }
                $tableContent[] = $row;
            }
            $table = array_merge([$tableHeader], $tableContent);
        }
        return $table;
    }

    private function invertArray($data)
    {
        $inverted = [];
        foreach ($data as $key => $values) {
            foreach ($values as $i => $value) {
                $inverted[$i][$key] = $value;
            }
        }
        return $inverted;
    }

    private function genUUID($value)
    {
        return Text::uuid();
    }

    private function nullToEmptyString($value)
    {
        return is_null($value) ? '' : $value;
    }
}
