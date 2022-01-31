# What is SSH_Auth_Monitor?
Program running in Python 3.9 that monitors /var/log/auth.log (or a specified log file of your choice) for specific Regex Patterns indicating failed SSH Logins. This program functions by continuous monitoring of this log file in real-time, and will act by creating an IPTABLE rule blocking failed SSH logs after a pre-determined threshold of Failed Logins attempts. 

The program will also continuously monitor a list of IPs that have previous failed authentication, checking to see if it's been X minutes since last failed login. The IPTABLE rule will be deleted if this condition is specified (by default the IPTABLE rule is indefinite) and met. 

This script is highly customizable and can be applied to pretty much any specific log entry, for any log file, and using different IPTABLE rules for your needs. This can be done by inputting a custom log file location and editing the Regex Patterns the script is looking for, as well as editing the function regarding IPTABLE rule creation. 

The broad overview is simply: Monitor Log File for offenders of Something > Act upon that offender > Continuously monitor list of offenders and reverse the action if a timeout is reached

## Compatability
Runs on Python 3.9
Currently uses IPTABLES for rules, so the server running the Script must be a Unix System.

## Options
* -h  Displays Help Regarding how to run the cmd

* -l  Required: Integer indicating the number of acceptable failed logins before action is taken

* -t  Optional: Timelimit (in minutes). The program keeps track of each locked-out-IP's last failed login attempt. If it has been -t minutes since the last failed login, the           IPTABLE rule is removed and the IP's number of failed logins is reset to 0 

* -l  Optional: Specify a logfile to monitor. By default, monitors /var/log/auth.log

## Quickstart
1) Download .ZIP File and extract to a directory of your choice
2) ```sudo python3 SSH_Auth_Monitor.py -t [Timelimit] -f [logfile] -l [Threshold]```
3) i.e. ``` sudo python3 SSH_Auth_Monitor.py -t 5 -l 5 ```

### Example Output
![image](https://user-images.githubusercontent.com/77559638/151867534-33fc3318-df21-4297-8a7a-df7a83e98b74.png)

![image](https://user-images.githubusercontent.com/77559638/151867617-4409faf3-0614-4f7e-bd8c-b092345b847c.png)

![image](https://user-images.githubusercontent.com/77559638/151867645-a87869fd-7458-4da8-9532-41bb13fda312.png)

![image](https://user-images.githubusercontent.com/77559638/151871927-9a8b0749-5aab-43ca-8db6-3dad96e68fe5.png)


