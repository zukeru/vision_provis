import os
import subprocess
import time
import uuid


def shell_command_execute(command):
    p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    print output
    return output

repo = os.environ.get('REPO_URL')
playbook = os.environ.get('PLAYBOOK')

command = 'git clone %s' % repo
shell_command_execute(command)

folder = repo.split('/')[4].replace('.git','')
#https://github.com/zukeru/vision_provis.git
execute_playbook = ('ansible-playbook -i "localhost," -c local %s/%s/%s >> ansible.log' % (os.path.dirname(os.path.realpath(__file__)),folder, playbook))
print execute_playbook
shell_command_execute(execute_playbook)
