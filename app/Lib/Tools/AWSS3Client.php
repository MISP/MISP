<?php

use Aws\S3\S3Client;
use Aws\Exception\AwsException;

class AWSS3Client
{
    private $__settings = false;
    private $__client = false;

    private function __getSetSettings()
    {
        $settings = array(
                'enable' => false,
                'bucket_name' => 'my-malware-bucket',
                'region' => 'eu-west-1',
                'aws_access_key' => '',
                'aws_secret_key' => '',
                'aws_endpoint' => '',
                'aws_compatible' => false,
                'aws_ca' => '',
                'aws_validate_ca' => true
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
        $s3Config = array(
            'version' => 'latest',
            'region' => $settings['region'],
        );
        if ($settings['aws_compatible']) {
            $s3Config = array(
                 'version' => 'latest',
                 'region' => $settings['region'],
                 // MinIO compatibility
                 // Reference: https://docs.min.io/docs/how-to-use-aws-sdk-for-php-with-minio-server.html
                 'endpoint' => $settings['aws_endpoint'],
                 'use_path_style_endpoint' => true,
                 'credentials' => [
                    'key'    => $settings['aws_access_key'],
                    'secret' => $settings['aws_secret_key'],
                 ],
            );
        }
        // This line should points to server certificate
        // Generically, this verify is set to false so that any certificate is valid
        // Reference:
        //   - https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_configuration.html
        //   - https://docs.guzzlephp.org/en/5.3/clients.html#verify
        // Example:
        // -- Verify certificate
        //    'http'    => ['verify' => '/usr/lib/ssl/certs/minio.pem'],
        // -- Do not verify certificate, securitywise, this option is not recommended, however due to 
        //    internal deployment scheme it is acceptable risk to set this to false
        //    'http'    => ['verify' => false],
        // -- Verify againts  built in CA certificates
        //    'http'    => ['verify' => true],
        if ($settings['aws_validate_ca']) {
            $s3Config['http']['verify'] = true;
            if (!empty($settings['aws_ca'])) {
                $s3Config['http']['verify'] = $settings['aws_ca'];
            }
        } else {
            $s3Config['http']['verify'] = false;
        }
        $s3Client = new Aws\S3\S3Client($s3Config);
        $this->__client = $s3Client;
        $this->__settings = $settings;
        return $s3Client;
    }

    public function exist($key)
    {
        return $this->__client->doesObjectExist([
            'Bucket' => $this->__settings['bucket_name'],
            'Key' => $key,
        ]);
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
        try {
            $result = $this->__client->getObject([
                'Bucket' => $this->__settings['bucket_name'],
                'Key' => $key
            ]);

            return $result['Body'];
        } catch (AwsException $e) {
            throw new NotFoundException('Could not download object ' . $e->getMessage());
        }
    }

    public function delete($key)
    {
        $this->__client->deleteObject([
            'Bucket' => $this->__settings['bucket_name'],
            'Key' => $key
        ]);
    }

    public function deleteDirectory($prefix) {
        $keys = $this->__client->listObjectsV2([
            'Bucket' => $this->__settings['bucket_name'],
            'Prefix' => $prefix
        ]);

        $toDelete = array_map(
            function ($key) {
                return ['Key' => $key['Key']];
            },
            is_array($keys['Contents'])?$keys['Contents']:[]
        );

        if (sizeof($toDelete) != 0) {
            $this->__client->deleteObjects([
                'Bucket'  => $this->__settings['bucket_name'],
                'Delete' => [
                    'Objects' => $toDelete
                ]
            ]);
        }
    }
}
