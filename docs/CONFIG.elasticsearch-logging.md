# It's possible to send all logs from MISP to an elasticsearch
# endpoint

# First, we'll need an ES PHP library

# Replace according to your requirements
export MISP_DIR=/var/www/MISP
cd $MISP_DIR/app
sudo -u www-data php composer.phar require elasticsearch/elasticsearch

# Ok now we need to configure where we log to
# 
# In Administration -> Server Settings & Maintenance -> Plugin Settings
# Under the elasticsearch tab, enable elasticsearch logging, and input
# your connection string
# Note that explicitly specifying the port may be needed, e.g. for AWS instances
# running on 443.
# Also input a log index - all logs will be thrown at this index.

# Now give ES a template to work from
cat << EOF > misp_es_template.json 
{
  "template": "misp_logging",
  "mappings": {
    "log": {
      "_source": {
        "enabled": true
      },
      "properties": {
        "Log.email": {
          "type": "keyword"
        },
        "Log.title": {
          "type": "text"
        },
        "Log.ip": {
          "type": "ip"
        },
        "Log.created": {
          "format": "YYYY-MM-dd HH:mm:ss",
          "type": "date"
        },
        "Log.description": {
          "type": "text"
        },
        "Log.org": {
          "type": "text"
        },
        "Log.action": {
          "type": "text"
        },
        "Log.model": {
          "type": "text"
        },
        "Log.change": {
          "type": "text"
        }
      }
    }
  }
}
EOF

# And put it to ES
curl -XPUT https://my_es/_template/misp_logging --data-binary @misp_es_template.json

# Now MISP will start sending logs to ES! Hooray!
