#!/bin/sh
# Replace the name of the node
sed -i 's/REPLACE_WITH_REAL_KEY/'$NEWRELIC_KEY'/g' /etc/newrelic/newrelic-python-agent.cfg
cd /opt/source
python setup.py install
newrelic-python-agent -c /etc/newrelic/newrelic-python-agent.cfg -f
