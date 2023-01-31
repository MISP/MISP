<?php
namespace App\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use Cake\Core\Configure;
use \DirectoryIterator;

class Dev2xModelReferencingCommand extends Command
{
    protected $defaultTable = 'Users';

    private $functionMaps = [];

    protected function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        $parser->setDescription("Run dev tools to sanity check what you\'re working on.\n\nFor a tl;dr, simply run\n\n./cake Dev2xOverlap -o '/path/to/MISP2' -n '/path/to/MISP3'");
        $parser->addOption('path', [
            'help' => "The full path to the MISP 2.x installation",
            'short' => 'p',
            'required' => false
        ]);
        return $parser;
    }

    public function execute(Arguments $args, ConsoleIo $io)
    {
        $type = $args->getOption('type');
        $data = $this->analyzeModels($args);
        $mermaid_data = $this->createMermaid($data);
        $io->out("## Model connectivity graph");
        foreach ($mermaid_data as $line) {
            $io->out($line);
        }
        $io->out("\n\n\n");
        $io->out("## Complexity waves");
        $waveData = $this->createWaveData($data);
        foreach ([1, 2, 3] as $wave) {
            $io->out('### Wave ' . $wave);
            sort($waveData['wave_' . $wave]);
            foreach ($waveData['wave_' . $wave] as $model) {
                $io->out('- [ ] ' . $model);
            }
        }
    }

    private function createWaveData(array $data): array
    {
        $temp = [];
        foreach ($data as $key => $values) {
            $temp[$key] = count($values);
            foreach ($values as $value) {
                if (empty($temp[$value])) {
                    $temp[$value] = 0;
                }
            }
        }
        foreach ($temp as $k => $v) {
            if ($v == 0) {
                $result['wave_1'][] = $k;
            } else if ($v < 3) {
                $result['wave_2'][] = $k;
            } else {
                $result['wave_3'][] = $k;
            }
        }
        return $result;
    }

    private function extractModelFiles(string $path, string $root_node): array
    {
        $files = new DirectoryIterator($path) or die("Failed opening directory $path.");
        $results = [];
        foreach ($files as $file) {
            if ($file->isFile()) {
                $file_name = $file->getFilename();
                if (strlen($file_name) < 5 || substr($file_name, -4) !== '.php') {
                    continue;
                }
                $results[$file->getFilename()] = [];
            }
        }
        return $results;
    }

    private function extractRelationships(Arguments $args, string $root_node, array $valid_models)
    {
        $path = $args->getOption('path') . '/app/Model';
        $model_files = $this->extractModelFiles($path, $root_node);
        $results = [];
        foreach ($model_files as $model_file => $contents) {
            if (!in_array(substr($model_file, 0, -4), $valid_models)) {
                continue;
            }
            $file_contents = file_get_contents($path . '/' . $model_file);
            $models = [];
            preg_match_all(
                '/\$this\-\>([A-Z][a-zA-Z]+)/',
                $file_contents,
                $models
            );
            if (!empty($models[1])) {
                $models = $models[1];
                foreach ($models as $k => $v) {
                    if (!in_array($v, $valid_models)) {
                        unset($models[$k]);
                    }
                }
                $results[explode('.', $model_file)[0]] = array_values(array_unique($models));
            }
        }
        return $results;
    }

    private function analyzeModels(Arguments $args): array
    {
        $root_node = '';
        if (!empty($args->getOption('root_node'))) {
            $root_node = mb_strtolower($args->getOption('root_node'));
        }
        $path = $args->getOption('path') . '/app/Model';
        $valid_model_files = $this->extractModelFiles($path, '');
        $valid_models = [];
        foreach ($valid_model_files as $valid_model => $contents) {
            if ($valid_model === 'AppModel.php') {
                continue;
            }
            $valid_models[] = substr($valid_model, 0, -4);
        }
        $results = $this->extractRelationships($args, $root_node, $valid_models);
        return $results;
    }

    private function createMermaid(array $data): array
    {
        $text = ["\n```mermaid\ngraph LR"];
        $weights = [];
        $leaves = [];
        foreach ($data as $parent => $children) {
            $weights[$parent] = count($children);
            foreach ($children as $child) {
                if (empty($weights[$child])) {
                    $weights[$child] = 0;
                }
                $text[] = "   $parent-->$child";
            }
        }
        foreach ($weights as $model => $weight) {
            $weight_colour = '#ff2200';
            $colour = '#fff';
            if ($weight == 0) {
                $weight_colour = '#0b7300';
            } else if ($weight < 3) {
                $weight_colour = '#ffbb00';
                $colour = '#000';
            }
            $text[] = "    style $model fill:$weight_colour,color:$colour";
        }
        $text[] = ["```"];
        return $text;
    }
}
