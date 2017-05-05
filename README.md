# check_katello_currency
![Example Icinga2 screenshot](https://raw.githubusercontent.com/stdevel/check_katello_currency/master/Icinga2_screenshot.jpg "Example Icinga2 screenshot")

`check_katello_currency` is a Nagios/Icinga plugin for checking patch currency of hosts managed by Foreman/Katello or Red Hat Satellite 6. As it also supports performance data, it can be used along with visualization tools such as Grafana:

![Example Grafana screenshot](https://raw.githubusercontent.com/stdevel/check_katello_currency/master/grafana_screenshot.jpg "Example Grafana screenshot")

The script checks the patch currency of one or multiple systems. The following information are gathered by accesing the Foreman/Katello API:
- Outstanding errata update counter per category:
  - bug fix
  - security
  - total summary

To gather these information a valid username / password combination to your management system is required. The login credentials **are prompted** when running the script. To automate this you have two options:

## Setting shell variables
The following shell variables are used:
* **SATELLITE_LOGIN** - a username
* **SATELLITE_PASSWORD** - the appropriate password

You might also want to set the HISTFILE variable (*depending on your shell*) to hide the command including the password in the history:
```
$ HISTFILE="" SATELLITE_LOGIN=mylogin SATELLITE_PASSWORD=mypass ./check_katello_currency.py -S giertz.stankowic.loc
```

## Using an authfile
A better possibility is to create a authfile with permisions **0600**. Just enter the username in the first line and the password in the second line and hand the path to the script:
```
$ ./check_katello_currency.py -a giertz.auth -S giertz.stankowic.loc
```

# Requirements
The plugin requires Python 2.6 or newer - it also requires the `requests` and `simplejson` modules.
The plugin requires API version 2 - the script checks the API version and aborts if you are using a historic version of Foreman.

# Usage
By default, the script checks a particular system or multiple systems for outstanding bugfix and security errata. It is possible to control this behaviour by specifying additional parameters (*see below*).
The script also support performance data for data visualization.

The following parameters can be specified:

| Parameter | Description |
|:----------|:------------|
| `-h` / `--help` | shows help and quits |
| `-d` / `--debug` | enable debugging outputs (*default: no*) |
| `-P` / `--show-perfdata` | enables performance data (*default: no*) |
| `-a` / `--authfile` | defines an auth file to use instead of shell variables |
| `-s` / `--server` | defines the server to use (*default: localhost*) |
| `--insecure` | Disables SSL verification (*default: no*) |
| `-y` / `--generic-statistics` | checks for inactive and outdated system statistic metrics (*default :no*) |
| `-u` / `--outdated-warning` | defines outdated systems warning percentage threshold (*default: 50*) |
| `-U` / `--outdated-critical` | defines outdated systems critical percentage threshold (*default: 80*) |
| `-n` / `--inactive-warning` | defines inactive systems warning percentage threshold (*default: 10*) |
| `-N` / `--inactive-critical` | defines inactive systems critical percentage threshold (*default: 50*) |
| `-S` / `--system` | defines one or multiple system(s) to check |
| `-A` / `--all-systems` | checks all registered systems - USE WITH CAUTION (*default: no*) |
| `-t` / `--total-warning` | defines total package update warning threshold (*default: empty*) |
| `-T` / `--total-critical` | defines total package update critical threshold (*default: empty*) |
| `-i` / `--important-warning` | defines security package (*critical, important and moderate security fixes*) update warning threshold (*default: 10*) |
| `-I` / `--important-critical` | defines security package (*critical, important and moderate security fixes*) update warning threshold (*default: 20*) |
| `-b` / `--bugs-warning` | defines bug package update warning threshold (*default: 25*) |
| `-B` / `--bugs-critical` | defines bug package update warning threshold (*default: 50*) |
| `-l` / `--location` | filters by a particular location (*default: no*) |
| `-o` / `--organization` | filters by a particular organization (*default: no*) |
| `-g` / `--hostgroup` | filters by a particular hostgroup (*default: no*) |
| `-e` / `--environment` | filters by a particular environment (*default: no*) |

## Examples
The following example checks a single system on the local Foreman/Katello server:
```
$ ./check_katello_currency.py -S giertz.stankowic.loc
Satellite Username: admin
Satellite Password:
OK: bugfix errata OK (0), security errata OK (1) for host giertz.stankowic.loc
```

Checking multiple systems on a remote Foreman/Katello server, authentication using authfile:
```
$ ./check_katello_currency.py -s st-katello01.stankowic.loc -a katello.auth -S giertz.stankowic.loc -S shittyrobots.test.loc
OK: bugfix errata OK (0), security errata OK (1) for host giertz.stankowic.loc, bugfix errata OK (0), security errata OK (1) for host shittyrobots.test.loc
```

Checking a single host on a local Foreman/Katello installation, also checking total errata, enabling performance data:
```
$ ./check_katello_currency.py -S giertz.stankowic.loc -t 1 -T 20 -P
Username: admin
Password:
WARNING: bugfix errata OK (0), security errata OK (1), total errata WARNING (1) for host giertz.stankowic.loc | 'bugfix_errata'=0;25;50;; 'security_errata'=1;10;20;; 'total_errata'=1;1;20;;
```

When specifying multiple systems along with performance data, the metric names will get prefix according to the particular host:
```
$ ./check_katello_currency.py -S giertz.stankowic.loc -S shittyrobots.test.loc -a katello.auth -P
OK: bugfix errata OK (0), security errata OK (1) for host giertz.stankowic.loc, bugfix errata OK (0), security errata OK (1) for host shittyrobots.test.loc | 'bugfix_errata_giertz'=0;25;50;; 'security_errata_giertz'=1;10;20;; 'bugfix_errata_shittyrobots'=0;25;50;; 'security_errata_shittyrobots'=1;10;20;;
```

When checking all systems (*which seriously fsckes up readability!*) it is possible to filter by location, organization, hostgroup or Puppet environment. Both human-readable names and internal IDs are accepted:
```
$ ./check_katello_currency.py -s st-katello01.stankowic.loc -a katello.auth -A -g dev-hosts
OK: bugfix errata OK (0), security errata OK (0) for host st-devel02.stankowic.loc, bugfix errata OK (0), security errata OK (0) for host st-web04.stankowic.loc
```

Checking generic statistics of a Foreman/Katello system:
```
$ ./check_katello_currency.py -a katello.auth -y -P
OK: outdated systems OK (0), inactive systems OK (0)| 'systems_outdated'=0;;;; 'systems_total'=8;;;; 'systems_inactive'=0;;;;
```

# Installation
Just deploy the Python script on your Icinga host or node. This repository also includes a [NRPE](check_katello_currency.cfg) and [Icinga2 configuration](check_katello_currency-icinga2.conf). If you're using a RPM-based Linux distro, you can use the [RPM spec file](nagios-plugins-katello-currency.spec) to create a RPM pacakge.

## Icinga2 configuration idea
I'm using the following snippet to check all the update currency of all Linux VMs:

```
apply Service "DIAG: Katello currency" {
  import "generic-service"
  check_command = "check_katello_currency"
  vars.katello_perfdata = true
  vars.katello_host = "st-katello01.stankowic.loc"
  vars.katello_authfile = "/usr/lib64/nagios/plugins/katello.auth"
  assign where host.vars.os == "Linux"
  ignore where host.vars.app == "katello"
  ignore where host.vars.nokatello
  ignore where host.vars.noagent
}
```

Systems running the Foreman/Katello application as well as systems without the Icinga2 agent (*or systems with the `noagent` flag*) are ignored.
To check the statistics on Foreman/Katello hosts, you could use the following snippet:

```
apply Service "DIAG: Katello statistics" {
  import "generic-service"
  check_command = "check_katello_currency"
  vars.katello_stats = true
  vars.katello_perfdata = true
  assign where host.vars.os == "Linux" && host.vars.app == "katello"
  ignore where host.vars.noagent
}
```

Systems running the Foreman/Katello application (*implemented by the vars.app tag*) will be checked. The **vars.katello_stats** flag automatically sets the `-y` parameter. Make sure the particular host configuration contains an authfile:

```
object Host "st-katello01.stankowic.loc" {
  import "linux-host"
...
  vars.app = "katello"
  vars.katello_authfile = "/usr/lib64/nagios/plugins/katello.auth"
```

The authfile needs to have file permissions **0600** and should be owned by the ``icinga`` user:
```
# chmod 0600 /usr/lib64/nagios/plugins/katello.auth
# chown icinga: /usr/lib64/nagios/plugins/katello.auth
```
