#!/bin/bash

# Usage: ./generate.sh [TEMPLATE] [OUTPUT]
# TEMPLATE: Input template file (default: cluster.template.yaml)
# OUTPUT: Output file (default: cluster.yaml)

TEMPLATE=${1:-cluster.template.yaml}
OUTPUT=${2:-cluster.yaml}

awk '
/\{\{CONTENT\}\}/ {
    while ((getline line < "worker-cis-hardening.py") > 0) print "            " line
    next
}
{ print }
' $TEMPLATE > $OUTPUT