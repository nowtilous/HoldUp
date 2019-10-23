#!/bin/bash
while IFS='' read -r line || [[ -n "$line" ]]; do
        lines=`find ./ | xargs grep -sw $line | wc -l`
        echo $line " " $lines
done < "$1"
