#!/bin/bash
# Drops the standard EICAR test string on the monitored endpoint to
# trigger the Wazuh -> Shuffle -> TheHive pipeline end to end.
cd /home/mintuser/eicar_test && wget https://secure.eicar.org/eicar.com.txt -O eicar_critical.txt
