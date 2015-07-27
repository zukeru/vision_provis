#!/bin/bash

$playbook = 'vision_provis'
$rollname = 'storm.yml'
$repo = 'https://github.com/zukeru/' + $playbook + '.git'

git clone $repo >> ~/ansible.log
ansible-playbook -i "localhost," -c local /$playbook/$rollname >> ansible.log
