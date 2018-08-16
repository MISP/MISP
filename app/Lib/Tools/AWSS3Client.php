<?php

use Aws\S3\S3Client;

class AWSS3Client
{
    private $__settings = false;
    private $__client = false;

    private function __getSetSettings()
    {
        $settings = array(
                'enabled' => false,
                'bucket_name' => 'my-malware-bucket',
                'region' => 'eu-west-1',
                'aws_access_key' => '',
                'aws_secret_key' => ''
        );

        // We have 2 situations
        // Either we're running on EC2 and we can assume an IAM role
        // Or we're not and need explicitly set AWS key
        if (strlen($settings['aws_access_key']) > 0) {
            putenv('AWS_ACCESS_KEY_ID='.$settings['aws_access_key']);
        }
        if (strlen($settings['aws_secret_key']) > 0) {
            putenv('AWS_SECRET_ACCESS_KEY='.$settings['aws_secret_key']);
        }

        foreach ($settings as $key => $setting) {
            $temp = Configure::read('Plugin.S3_' . $key);
            if ($temp) {
                $settings[$key] = $temp;
            }
        }
        return $settings;
    }

    public function initTool()
    {
        $settings = $this->__getSetSettings();
        $s3 = new Aws\S3\S3Client([
            'version' => 'latest',
            'region' => $settings['region']
        ]);

        $this->__client = $s3;
        $this->__settings = $settings;
        return $s3;
    }

    public function upload($key, $data)
    {
        $this->__client->putObject([
            'Bucket' => $this->__settings['bucket_name'],
            'Key' => $key,
            'Body' => $data
       ]);
    }

    public function download($key)
    {
        $result = $this->__client->getObject([
            'Bucket' => $this->__settings['bucket_name'],
            'Key' => $key
        ]);

        return $result['Body'];
    }

    public function delete($key)
    {
        $this->__client->deleteObject([
            'Bucket' => $this->__settings['bucket_name'],
            'Key' => $key
        ]);
    }

    public function deleteDirectory($prefix) {
        $keys = $s3->listObjects([
            'Bucket' => $this->__settings['bucket_name'],
            'Prefix' => $prefix
        ]) ->getPath('Contents/*/Key');

        $s3->deleteObjects([
            'Bucket'  => $bucket,
            'Delete' => [
                'Objects' => array_map(function ($key) {
                    return ['Key' => $key];
                }, $keys)
            ],
        ]);
    }
}
