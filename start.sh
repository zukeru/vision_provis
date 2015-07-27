#!/bin/bash

$playbookname = 'storm.yml'
$playbookurl = './storm.yml'

#git clone $playbookurl >> ~/ansible.log
ansible-playbook -i "localhost," -c local $playbookname >> ansible.log