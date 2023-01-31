<?php
namespace App\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use Cake\Core\Configure;
use \DirectoryIterator;

class Dev2xOverlapCommand extends Command
{
    protected $defaultTable = 'Users';

    private $functionMaps = [];

    protected function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        $parser->setDescription("Run dev tools to sanity check what you\'re working on.\n\nFor a tl;dr, simply run\n\n./cake Dev2xOverlap -o '/path/to/MISP2' -n '/path/to/MISP3'");
        $parser->addOption('old_path', [
            'help' => "The full path to the old MISP installation",
            'short' => 'o',
            'required' => true
        ]);
        $parser->addOption('new_path', [
            'help' => "The full path to the new MISP installation",
            'short' => 'n',
            'required' => true
        ]);
        $parser->addOption('type', [
            'short' => 't',
            'help' => 'Limit the checks to the selected type',
            'default' => 'All',
            'choices' => ['All', 'Controller', 'Model', 'View']
        ]);
        $parser->addOption('search', [
            'short' => 's',
            'help' => 'Limit the searched files to ones that contain a string in their filepath.',
            'default' => 'All'
        ]);
        return $parser;
    }

    public function execute(Arguments $args, ConsoleIo $io)
    {
        $search = $args->getOption('search');
        $type = $args->getOption('type');
        $data = [];
        $missing = [];
        if ($type === 'All' || $type === 'Controller') {
            $data = $this->analyzeControllers($data, $args);
        }
        if ($type === 'All' || $type === 'Model') {
            $data = $this->analyzeModels($data, $args);
        }
        if ($type === 'All' || $type === 'View') {
            $data = $this->analyzeViews($data, $args);
        }
        $this->displayResults($io, $data['missing']);
    }

    private function displayMCBranch(ConsoleIo $io, string $scope, array $scope_data, string $last_scope): void
    {
        $dir_char = $last_scope === $scope && !empty($scoped_data) ? '└' : '├';
        $io->info('  ' . $dir_char . ' ' . $scope);
        ksort($scope_data);
        $scope_filename = array_keys($scope_data);
        $last_filename = end($scope_filename);
        foreach ($scope_data as $filename => $functions) {
            if (is_array($functions)) {
                $dir_char = $last_filename === $filename && !empty($functions) ? '└' : '├';
                $io->warning('  │  ' . $dir_char . ' ' . $filename);
                ksort($functions);
                $scope_function = array_keys($functions);
                $last_function = end($scope_function);
                foreach ($functions as $k => $function) {
                    $dir_char = $last_function === $k ? '└' : '├';
                    $io->error('  │  │  ' . $dir_char . ' ' . $function . '()');
                }
            } else {
                $dir_char = $last_filename === $filename ? '└' : '├';
                $io->error('  │  ' . $dir_char . ' ' . $filename);
            }
        }
    }

    private function displayVBranch(ConsoleIo $io, string $scope, mixed $scope_data, string $last_scope, int $depth = 2, bool $first = false): void
    {
        if ($first) {
            $dir_char = $last_scope === $scope ? '└' : '├';
            $io->info('  ' . $dir_char . ' ' . $scope);
            ksort($scope_data);
            if (!empty($scope_data)) {
                $keys = array_keys($scope_data);
                $last = end($keys);
                foreach ($scope_data as $k => $v) {
                    $this->displayVBranch($io, $k, $v, $last, 1);
                }
            }
        } else {

            $dir_char = $last_scope === $scope ? '└' : '├';
            if ($scope_data === '*') {
                $depth_string = str_repeat('  │', $depth);
                $io->error($depth_string . '  ' . $dir_char . ' ' . $scope);
            } else {
                $depth_string = str_repeat('  │', $depth);
                $io->warning($depth_string . '  ' . $dir_char . ' ' . $scope);
                ksort($scope_data);
                $keys = array_keys($scope_data);
                $last = end($keys);
                foreach ($scope_data as $k => $v) {
                    $this->displayVBranch($io, $k, $v, $last, $depth + 1);
                }
            }
        }
    }

    private function displayResults(ConsoleIo $io, array $missing): void
    {
        $io->info('Missing content');
        foreach ($missing as $k => $v) {
            if (empty($missing[$k])) {
                unset($missing[$k]);
            }
        }
        ksort($missing);
        $scope_keys = array_keys($missing);
        $last_scope = end($scope_keys);
        foreach ($missing as $scope => $scope_data) {
            if ($scope === 'View') {
                $this->displayVBranch($io, $scope, $scope_data, $last_scope, 2, true);
            } else {
                $this->displayMCBranch($io, $scope, $scope_data, $last_scope);
            }
        }
    }

    private function extractFileNames(string $path, string $search): array
    {
        if ($path === '/var/www/MISP2/app/View/GalaxyClusterRelations/../GalaxyClusterRelations') die();
        $files = new DirectoryIterator($path) or die("Failed opening directory $path.");
        $results = [];
        foreach ($files as $file) {
            if (!$file->isFile()) {
                if ($file->getFilename()[0] === '.') {
                    continue;
                }
                if (!empty($search) && $search !== 'all') {
                    if (mb_strpos(mb_strtolower($file->getPathname()), $search) === false) {
                        continue;
                    }
                }
                $results[$file->getFilename()] = $this->extractFileNames($file->getPathname(), $search);
            } else {
                if ($file->getFilename()[0] === '.') {
                    continue;
                }
                if (!empty($search) && $search !== 'all') {
                    if (mb_strpos(mb_strtolower($file->getPathname()), $search) === false) {
                        continue;
                    }
                }
                $results[] = $file->getFilename();
            }
        }
        return $results;
    }

    private function extractFunctionNames(string $path, string $search): array
    {
        $files = new DirectoryIterator($path) or die("Failed opening directory $path.");
        $results = [];
        foreach ($files as $file) {
            if (!$file->isFile()) {
                continue;
            }
            if ($file->getFilename()[0] === '.') {
                continue;
            }
            if (!empty($search) && $search !== 'all') {
                if (mb_strpos(mb_strtolower($file->getPathname()), $search) === false) {
                    continue;
                }
            }
            $file_contents = file_get_contents($file->getPathname());
            $functions = [];
            preg_match_all(
                '/public.function[\s\n]+(\S+)[\s\n]*\(/',
                $file_contents,
                $functions
            );
            if (!empty($functions[1])) {
                foreach ($functions[1] as $f) {
                    if ($f[0] === '_') {
                        continue;
                    }
                    $results[$file->getFilename()][] = $f;
                }
            }
        }
        return $results;
    }

    private function compareToOld(array $old, array $new): array
    {
        $missing = [];
        foreach ($old as $old_file_name => $functions) {
            if (!isset($new[$old_file_name])) {
                $missing[$old_file_name] = '*';
            } else {
                foreach ($functions as $function) {
                    if (!in_array($function, $new[$old_file_name])) {
                        $missing[$old_file_name][] = $function;
                    }
                }
            }
        }
        return $missing;
    }

    private function analyzeControllers(array $results, Arguments $args): array
    {
        $old_path = $args->getOption('old_path') . '/app/Controller';
        $old_component_path = $old_path . '/Component';
        $new_path = $args->getOption('new_path') . '/src/Controller';
        $new_admin_path = $args->getOption('new_path') . '/src/Controller/Admin';
        $new_component_path = $new_path . '/Component';
        $search = mb_strtolower($args->getOption('search'));
        $results['old']['Controller'] = $this->extractFunctionNames($old_path, $search);
        $results['old']['Component'] = $this->extractFunctionNames($old_component_path, $search);
        $results['new']['Controller'] = $this->extractFunctionNames($new_path, $search);
        $results['new']['Controller']['Admin'] = $this->extractFunctionNames($new_admin_path, $search);
        foreach ($results['new']['Controller']['Admin'] as $file => $admin_functions) {
            foreach ($admin_functions as $admin_function) {
                if (empty($results['new']['Controller'][$file])) {
                    $results['new']['Controller'][$file] = [];
                }
                $results['new']['Controller'][$file][] = 'admin_' . $admin_function;
            }
        }
        unset($results['new']['Controller']['Admin']);
        $results['new']['Component'] = $this->extractFunctionNames($new_component_path, $search);
        $results['missing']['Controller'] = $this->compareToOld($results['old']['Controller'], $results['new']['Controller']);
        $results['missing']['Component'] = $this->compareToOld($results['old']['Component'], $results['new']['Component']);
        return $results;
    }

    private function analyzeModels(array $results, Arguments $args): array
    {
        $old_path = $args->getOption('old_path') . '/app/Model';
        $old_behavior_path = $old_path . '/Behavior';
        $new_path_table = $args->getOption('new_path') . '/src/Model/Table';
        $new_path_entity = $args->getOption('new_path') . '/src/Model/Entity';
        $new_behavior_path = $args->getOption('new_path') . '/src/Model/Behavior';
        $search = mb_strtolower($args->getOption('search'));
        $results['old']['Model'] = $this->extractFunctionNames($old_path, $search);
        $results['old']['Behavior'] = $this->extractFunctionNames($old_behavior_path, $search);
        $results['new']['Table'] = $this->extractFunctionNames($new_path_table, $search);
        $results['new']['Entity'] = $this->extractFunctionNames($new_path_entity, $search);
        $results['new']['Component'] = $this->extractFunctionNames($new_behavior_path, $search);
        foreach ($results['old']['Model'] as $old_model => $old_model_functions) {
            $old_model_name = substr($old_model, 0, -4);
            $expected_table_name = $old_model_name . (in_array($old_model_name, ['App']) ? '': 's') . 'Table.php';
            $combined_new_function_list = [];
            if (empty($results['new']['Table'][$expected_table_name])) {
                $results['missing']['Table'][$expected_table_name] = '*';
            } else {
                $combined_new_function_list = $results['new']['Table'][$expected_table_name];
            }
            if (empty($results['new']['Entity'][$old_model])) {
                $results['missing']['Entity'][$old_model] = '*';
            } else {
                $combined_new_function_list = array_merge($combined_new_function_list, $results['new']['Entity'][$old_model]);
            }
            if (!empty($combined_new_function_list) && empty($results['missing']['Table'][$expected_table_name])) {
                $results['missing']['Table'][$expected_table_name] = array_diff($old_model_functions, $combined_new_function_list);
            }
        }

        foreach ($results['old']['Behavior'] as $old_behavior => $old_behavior_functions) {
            if (empty($results['new']['Behavior'][$old_behavior])) {
                $results['missing']['Behavior'][$old_behavior] = '*';
            } else {
                $results['missing']['Behavior'][$old_behavior] = array_diff($old_behavior_functions, $results['new']['Behavior'][$old_behavior]);
            }
        }
        return $results;
    }

    private function analyzeViews(array $results, Arguments $args): array
    {
        $old_path = $args->getOption('old_path') . '/app/View';
        $new_path = $args->getOption('new_path') . '/templates';
        $search = mb_strtolower($args->getOption('search'));
        $results['old']['View'] = $this->extractFileNames($old_path, $search);
        $results['new']['View'] = $this->extractFileNames($new_path, $search);
        foreach ($results['new']['View'] as $k => $v) {
            if ($k === 'element') {
                $results['new']['View']['Elements'] = $v;
                unset($results['new']['View']['element']);
            }
        }
        $results['missing']['View'] = $this->array_diff_recursive($results['old']['View'], $results['new']['View']);
        return $results;
    }

    private function array_diff_recursive(array $array1, array $array2)
    {
        $missing = [];
        foreach ($array1 as $array1_key => $array1_element) {
            if (is_numeric($array1_key)) {
                if (!in_array($array1_element, $array2)) {
                    $missing[$array1_element] = '*';
                }
            } else {
                if (empty($array2[$array1_key])) {
                    $missing[$array1_key] = '*';
                } else {
                    if (is_array($array1_element)) {
                        $missing[$array1_key] = $this->array_diff_recursive($array1_element, $array2[$array1_key]);
                    }
                }
            }
        }
        return $missing;
    }
}
