Please use this read me file for the information required to be submitted per the assignment on MyCourses.

## Deployment using Ansible
### Things to note -
- Please edit the inventory file under the `Ansible` directory and specify your server. The ansible playbook is designed to install the web server and the service file as root user.
- Please run the playbook file as the root user. If Ansible uses a normal user with `sudo` privileges, add a `-K` flag to the `ansible-playbook` command to prompt you for the `sudo` password.
Example Ansible playbook command -
```bash
ansible-playbook Ansible/playbook.yml -i Ansible/inventory -v -K # -K is for sudo password prompt
```
- Do NOT move the location of the inventory file, the playbook depends on it. Pls.
