(define-module (dissoc confs system-definitions workstations battlestation os))
(

 use-modules ;;(guix-hardened hardened sysctl)
 (dissoc services monitoring)
 (dissoc services cassandra)
 (dissoc services elasticsearch)
 (dissoc packages databases)
 (dissoc services wildfly)
 (dissoc services java)
 ;;(dissoc packages linux)
 (dissoc packages wm)
 (gnu packages databases)
 (gnu packages radio)
 (gnu packages terminals)
 (gnu packages suckless)
 (gnu packages java)
 (gnu packages wm)
 (dissoc private packages tablet)
 (dissoc private packages linux)
 (gnu services desktop)
 (gnu system setuid)
 ((dissoc services tor) #:prefix dissoc-tor:)
 (gnu)
 (nongnu packages linux)
 (nongnu system linux-initrd)
 (srfi srfi-1))
(use-package-modules fonts lisp-xyz cups)
(use-service-modules admin
                     audio
                     auditd
                     avahi
                     base
                     certbot
                     cups
                     databases
                     dbus
                     desktop
                     docker
                     monitoring
                     networking
                     nix
                     sound
                     ssh
                     sysctl
                     syncthing
                     virtualization
                     vpn
                     web
                     xorg)
;;(load "/home/dissoc/Workspace/guix-dissoc/dissoc/packages/linux.scm")

(define %host-ip "10.45.136.51")

(define %hosts-file (plain-file "hosts"
                                "127.0.0.1 localhost bs battlestation
::1 localhost bs battlestation
10.45.136.50 workshop-server"))

(define %undertow-config (local-file "/home/dissoc/Workspace/attic-balance/config_examples//test.edn"))

(define auditd.conf
  (plain-file "auditd.conf"
              "log_file = /var/log/audit.log
log_format = ENRICHED
freq = 1
space_left = 5%
space_left_action = syslog
admin_space_left_action = ignore
disk_full_action = ignore
disk_error_action = syslog"))

(define audit.rules
  (plain-file "audit.rules"
              "-D
-b 8192
# Failure Mode
## Possible values: 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
-f 1

# Ignore errors
## e.g. caused by users or files not found in the local environment
-i
-w /etc/group -p wa -k etcgroup
"))


(define %auditd-configuration-directory
  (computed-file "auditd"
                 #~(begin
                     (mkdir #$output)
                     (copy-file #$auditd.conf
                                (string-append #$output "/auditd.conf"))
                     (copy-file #$audit.rules
                                (string-append #$output "/audit.rules")))))

(define %nftables-allow-cloudflare
  "
# ipv4s that cloudflare uses to connect to host
define CLOUDFLARE_IPV4 = {173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22,
103.31.4.0/22, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 188.114.96.0/20, 197.234.240.0/22, 198.41.128.0/17, 162.158.0.0/15, 104.16.0.0/13, 104.24.0.0/14, 172.64.0.0/13, 131.0.72.0/22}

table inet cloudflare {

  set allowed_vpn_ipv4 {
    typeof ip saddr
    flags interval
    auto-merge
    elements CLOUDFLARE_IPV4
}

  chain input {
    type filter hook input priority -10; policy accept;

    iifname \"lo\" return

    tcp dport 55555 add @candidates_ipv4 {ip  saddr . 4444 timeout 30s}
    tcp dport 4444 ip  saddr . tcp dport @candidates_ipv4 add @candidates_ipv4 {ip  saddr . 333 timeout 30s}
    tcp dport 333 ip  saddr . tcp dport @candidates_ipv4 add @candidates_ipv4 {ip  saddr . 1776 timeout 30s}
    tcp dport 1776 ip  saddr . tcp dport @candidates_ipv4 add @clients_ipv4 {ip  saddr timeout 30s} log prefix \"Successful portknock: \"
    tcp dport $guarded_ports ip  saddr @clients_ipv4 counter accept
    tcp dport $guarded_ports ct state established,related counter accept
    tcp dport $guarded_ports counter reject with tcp reset
  }
}")

(define %ntables-portknocking
  "
# Port knocking rules
define guarded_ports = {ssh}

table inet portknock {

  set clients_ipv4 {
    type ipv4_addr
    flags timeout
  }

  set candidates_ipv4 {
    type ipv4_addr . inet_service
    flags timeout
  }

  chain input {
    type filter hook input priority -10; policy accept;

    iifname \"lo\" return

    tcp dport 55555 add @candidates_ipv4 {ip  saddr . 4444 timeout 30s}
    tcp dport 4444 ip  saddr . tcp dport @candidates_ipv4 add @candidates_ipv4 {ip  saddr . 333 timeout 30s}
    tcp dport 333 ip  saddr . tcp dport @candidates_ipv4 add @candidates_ipv4 {ip  saddr . 1776 timeout 30s}
    tcp dport 1776 ip  saddr . tcp dport @candidates_ipv4 add @clients_ipv4 {ip  saddr timeout 30s} log prefix \"Successful portknock: \"
    tcp dport $guarded_ports ip  saddr @clients_ipv4 counter accept
    tcp dport $guarded_ports ct state established,related counter accept
    tcp dport $guarded_ports counter reject with tcp reset
  }
}")

(define %nftables-rules
  "# A simple and safe firewall
define VPN_ALLOW = { 75.108.123.151 }
define VPN_PORT = 9993
table inet filter {

  # create the set for blocked
  # ipv4 addresses to be added
  # via libnftables
  set blocked_ipv4 {
    typeof ip daddr
    # would not allow to use empty set so put
    # random IP fro, TEST-NET-3
    #elements = { 203.0.113.241 }
  }

  chain input {
    type filter hook input priority 0; policy drop;

    # early drop of invalid connections
    ct state invalid drop

    # drop the connections from the blocklist
    ip saddr @blocked_ipv4 drop
    # allow established/related connections
    ct state { established, related } accept

    # allow from loopback
    iifname lo accept

    # allow icmp
    # ip protocol icmp accept
    # ip6 nexthdr icmpv6 accept

    # allow ssh
    tcp dport ssh accept

    # allow vpn connections from
    # whitelisted set
    udp dport { $VPN_PORT } ip saddr $VPN_ALLOW accept
    # reject everything else
    # reject with icmpx type port-unreachable
    # in some cases drop can be better than reject
    # this can prevent a response going to a spoofed IP
    drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}")

(define %nftables-ruleset
  (plain-file "nftables.conf"
              (string-join (list %nftables-rules %ntables-portknocking) "\n")))

(define %ucore-tracer-udev-rule
  (udev-rule
   "90-ucore-tracer.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"0483\", "
                  "ATTRS{idProduct}==\"5750\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))

(define %de-5000-udev-rule
  (udev-rule
   "90-de-5000.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"0403\", "
                  "ATTRS{idProduct}==\"6001\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))

(define %bk-393-udev-rule
  (udev-rule
   "90-bk-393.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"0403\", "
                  "ATTRS{idProduct}==\"6001\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))


(define %lilygo-ttgo-udev-rule
  (udev-rule
   "90-lilygo-ttgo.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"239a\", "
                  "ATTRS{idProduct}==\"4405\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))


(define %gaomon-m10k-udev-rule
  (udev-rule
   "90-gaomon-m10k.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"256c\", "
                  "ATTRS{idProduct}==\"006f\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))

(define %postgres-hba-file
  (string-join '("local	all	all			trust"
                 "host	all	all	127.0.0.1/32 	trust"
                 "host	all	all	::1/128 	trust")
               "\n"))

(define gaomon-m10k-xorg-file
  "Identifier \"Tablet\"
  Driver \"wacom\"
  MatchDevicePath \"/dev/input/event*\"
  MatchUSBID \"256c:0064\"
  EndSection")

;; (define %my-desktop-packages (begin
;;                                ;; import modules here because later can move to other file
;;                                (use-modules
;;                                 (gnu packages wm)
;;                                 (gnu packages emacs)
;;                                 (gnu packages web-browsers)
;;                                 (gnu packages chromium))
;;                                (list stumpwm emacs modsecurity-nginx)))

(define (customize-services services)
  ((compose (lambda (s)
              (remove
               (lambda (service)
                 (or (eq? (service-kind service) gdm-service-type)
                     (eq? (service-kind service) sysctl-service-type)
                     (eq? (service-kind service) network-manager-service-type)))
               s))
            (lambda (s)
              (modify-services
               s
               (udev-service-type
                config =>
                (udev-configuration
                 (inherit config)
                 (rules
                  (append
                   (udev-configuration-rules config)
                   (list hackrf
                         rtl-sdr
                         %gaomon-m10k-udev-rule
                         %ucore-tracer-udev-rule
                         %lilygo-ttgo-udev-rule
                         %de-5000-udev-rule)))))))
            (lambda (s)
              (modify-services
               s
               (guix-service-type
                config =>
                (guix-configuration
                 (inherit config)
                 (extra-options
                  '("--cores=10"))
                 (authorized-keys
                  (append
                   (guix-configuration-authorized-keys config)
                   (list (local-file "/etc/guix/signing-key.pub")))))))))
   services))

(operating-system
 (locale "en_US.utf8")
 (timezone "America/Chicago")
 (keyboard-layout (keyboard-layout "us"))
 (host-name "bs")
 ;;(hosts-file %hosts-file)
 (kernel linux-bpf-sched-ext)
 (kernel-loadable-modules (list digimend-module-linux))
 (firmware (list linux-firmware))
 (initrd microcode-initrd)
 (users (cons* (user-account
                (name "dissoc")
                (comment "Dissoc")
                (group "users")
                (home-directory "/home/dissoc")
                (supplementary-groups
                 '("wheel" "netdev" "audio" "video" "lp" "dialout"
                   ;;"kvm"                   "docker" "tor" "libvirt"
                   )))
               (user-account
                (name "carl")
                (comment "carl")
                (group "users")
                (home-directory "/home/carl"))
               %base-user-accounts))
 ;; (setuid-programs
 ;;  (append (list (setuid-program
 ;;                 (program (file-append openjdk19 "/bin/java")))
 ;;                (setuid-program
 ;;                 (program (file-append openjdk19 "/lib/libjli.so"))))
 ;;          %setuid-programs))
 (packages
  (append
   (list ;;alacritty
    stumpwm
    sbcl-stumpwm-ttf-fonts
    font-dejavu
    sbcl-ubiquitous
    sbcl-stumpwm-mpd
    sbcl-stumpwm-clipboard-history
    (specification->package "nss-certs"))
   %base-packages))
 (services
  (append
   (list
    ;;(service auditd-service-type)
    ;; (service auditd-service-type
    ;;          (auditd-configuration
    ;;           (configuration-directory %auditd-configuration-directory)))
    (service libvirt-service-type
             (libvirt-configuration
              (listen-tcp? #t)
              (unix-sock-group "libvirt")
              (tls-port "16555")))
    ;; (service virtlog-service-type
    ;;          (virtlog-configuration
    ;;           (max-clients 1000)))
    ;; (service mpd-service-type
    ;;          (mpd-configuration
    ;;           (user "dissoc")
    ;;           (music-directory "~/Music")
    ;;           (outputs (list (mpd-output )))))
    (static-networking-service "eno1" %host-ip
                               #:netmask "255.255.255.0"
                               #:gateway "10.45.136.1"
                               #:name-servers '("10.45.136.50"
                                                "10.45.136.1"))
    ;;(service elasticsearch-service-type)
    ;; (service nftables-service-type
    ;;          (nftables-configuration
    ;;           (ruleset %nftables-ruleset)))
    ;;(service nix-service-type)
    ;; (service jar-service-type
    ;;          (jar-configuration
    ;;           (application-name "attic-relay")
    ;;           (jdk openjdk17)
    ;;           (jar-file (local-file "/home/dissoc/Workspace/attic-relay/target/uberjar/attic-relay.jar"))))

    ;; (service jar-service-type
    ;;          (jar-configuration
    ;;           (application-name "attic-shopping")
    ;;           (jdk openjdk17)
    ;;           (jar-file (local-file "/home/dissoc/Workspace/attic-shopping/target/uberjar/attic-shopping.jar"))))

    ;; (service jar-service-type
    ;;          (jar-configuration
    ;;           (application-name "attic-balance")
    ;;           (jdk openjdk21)
    ;;           (jar-file (local-file "/home/dissoc/Workspace/attic-balance/target/attic-balance-0.1.0-SNAPSHOT-standalone.jar"))))

    ;; (service nginx-service-type
    ;;          (nginx-configuration
    ;;           (server-blocks
    ;;            (list (nginx-server-configuration

    ;;                   (listen '("443 ssl"))
    ;;                   (server-name '("dev.attic.shopping"))
    ;;                   (ssl-certificate "/etc/letsencrypt/live/dev.attic.shopping/fullchain.pem")
    ;;                   (ssl-certificate-key "/etc/letsencrypt/live/dev.attic.shopping/privkey.pem")
    ;;                   (root "/srv/http/dev.attic.shopping")
    ;;                   (locations
    ;;                    (list
    ;;                     (nginx-location-configuration
    ;;                      (uri "/")
    ;;                      (body '("proxy_pass http://127.0.0.1:30001;"))))))))))




    ;; (service nginx-service-type
    ;;          (nginx-configuration
    ;;           (server-blocks
    ;;            (list
    ;;             (nginx-server-configuration
    ;;              (listen '("10.45.136.51:80"))
    ;;              (server-name '("zabbix.hq.dissoc.me" "zabbix.dissoc.me"))
    ;;              (root "/srv/http/zabbix.hq.dissoc.me")
    ;;              (locations
    ;;               (list
    ;;                (nginx-location-configuration
    ;;                 (uri "/")
    ;;                 (body '("proxy_pass http://127.0.0.1:44441/;"))))))
    ;;             (nginx-server-configuration
    ;;              (listen '("10.45.136.51:80"))
    ;;              (server-name '("publish.hq.dissoc.me" "publish.dissoc.me"))
    ;;              (root "/srv/http/publish.hq.dissoc.me")
    ;;              (locations
    ;;               (list
    ;;                (nginx-location-configuration
    ;;                 (uri "/")
    ;;                 (body '("proxy_pass http://127.0.0.1:44442/;"))))))
    ;;             (nginx-server-configuration
    ;;              (listen '("10.45.136.51:80"))
    ;;              (server-name '("git.hq.dissoc.me" "git.dissoc.me"))
    ;;              (root "/srv/http/git.hq.dissoc.me")
    ;;              (locations
    ;;               (list
    ;;                (nginx-location-configuration
    ;;                 (uri "/")
    ;;                 (body '("proxy_pass http://127.0.0.1:44440/;"))))))))))
    ;; (service cups-service-type
    ;;          (cups-configuration
    ;;           (web-interface? #t)
    ;;           (extensions
    ;;            (list cups-filters epson-inkjet-printer-escpr hplip-minimal foomatic-filters brlaser foo2zjs))))
    (service ntp-service-type)
    ;; (pam-limits-service
    ;;  (list (pam-limits-entry "*" 'both 'nofile 100000)))
    (service openssh-service-type)
    ;; (service dissoc-tor:tor-service-type
    ;;              (dissoc-tor:tor-configuration
    ;;               (control-socket? #t)
    ;;               (config-file (plain-file "extra-tor-config"
    ;;                                        "Log debug stdout
    ;; CookieAuthentication 1
    ;; CookieAuthFile /var/lib/tor/control_auth_cookie
    ;; CookieAuthFileGroupReadable 1"))
    ;; (config-file (plain-file "extra-tor-config"
    ;;                                        "DataDirectoryGroupReadable 1
    ;; ClientOnionAuthDir /var/lib/tor/onion_auth
    ;; CookieAuthentication 1
    ;; CookieAuthFile /var/lib/tor/control_auth_cookie
    ;; CookieAuthFileGroupReadable 1
    ;; ControlSocket /var/run/tor/control-sock
    ;; Log debug stdout"))
    ;;ControlPort 9051
    ;; ClientOnionAuthDir /var/lib/tor/onion_auth
    ;; ControlPort 9051
    ;; CookieAuthentication 1
    ;; CookieAuthFile /var/lib/tor/control_auth_cookie
    ;; CookieAuthFileGroupReadable 1

    ;;Log debug stdout
    ;;(control-socket? #t)

    ;; ))
    ;; (dissoc-tor:tor-hidden-service "relay-conn-0"
    ;;                                '((44120 "127.0.0.1:5440"))
    ;;                                `(,(local-file "key.auth" #:recursive? #t)))
    (elogind-service)
    (service syncthing-service-type
             (syncthing-configuration (user "dissoc")))
    ;; (service postgresql-service-type
    ;;          (postgresql-configuration
    ;;           (config-file
    ;;            (postgresql-config-file
    ;;             (hba-file
    ;;              (plain-file "pg_hba.conf"
    ;;                          %postgres-hba-file))))
    ;;           (postgresql postgresql-13)))
    ;;(service pulseaudio-service-type)
    ;; (service qemu-binfmt-service-type
    ;;          (qemu-binfmt-configuration
    ;;           (platforms (lookup-qemu-platforms "arm" "aarch64"))))
    ;;(service docker-service-type)
    (service slim-service-type (slim-configuration
                                (auto-login? #t)
                                (auto-login-session (file-append stumpwm "/bin/stumpwm"))
                                (default-user "dissoc")
                                (display ":0")
                                (vt "vt7")
                                (xorg-configuration
                                 (xorg-configuration
                                  (extra-config '("Section \"InputClass\"
    Identifier \"Tablet\"
    Driver \"wacom\"
    MatchDevicePath \"/dev/input/event*\"
    MatchUSBID \"256c:006f\"
EndSection"))))




                                ))
    ;; (service sysctl-service-type
    ;;          (sysctl-configuration
    ;;           (settings
    ;;            '(("fs.file-max" . "kernel.kptr_restrict"))

    ;;            ;; (append (assoc-remove! %hardened-sysctls "net.core.bpf_jit_harden")
    ;;            ;;                  '(("fs.file-max" . "kernel.kptr_restrict"))
    ;;            ;;                  )


    ;;            )))
    ;; (service unattended-upgrade-service-type
    ;;          (unattended-upgrade-configuration
    ;;           ;; run at 4:30 every day, every month, every day of the week
    ;;           (schedule "30 04 * * *")))
    ;;(dbus-service)
    ;; (service certbot-service-type
    ;;          (certbot-configuration
    ;;           ;;(email "foo@example.net")
    ;;           (certificates
    ;;            (list
    ;;             (certificate-configuration
    ;;              (domains '("dev.attic.shopping"))
    ;;              ;;(deploy-hook %nginx-deploy-hook)
    ;;              )
    ;;             ;; (certificate-configuration
    ;;             ;;  (domains '("bar.example.net")))
    ;;             ))))
    ;; (service zabbix-server-service-type
    ;;          (zabbix-server-configuration
    ;;           (log-type "system")
    ;;           (db-host "127.0.0.1")
    ;;           (db-port 5432)
    ;;           (db-name "zabbix")
    ;;           (db-password "Th!sismyP@ss#W0rd")
    ;;           (extra-options
    ;;            (string-join '("JavaGateway=127.0.0.1"
    ;;                           "JavaGatewayPort=10052"
    ;;                           "StartJavaPollers=5")
    ;;                         "\n"))))
    ;;(service zabbix-jmx-agent-service-type)
    ;;(cassandra-service)
    ;; (service screen-locker-service-type
    ;;          (screen-locker-configuration
    ;;           (name "slock")
    ;;           (program (file-append slock "/bin/slock"))))
    ;; (service avahi-service-type)
    ;; (bluetooth-service)
    ;; (service wireguard-service-type
    ;;          (wireguard-configuration
    ;;           ;;(addresses '("10.66.93.21"))
    ;;           (addresses '("10.64.239.231"
    ;;                        "fc00:bbbb:bbbb:bb01::1:efe6"))
    ;;           (private-key "/home/dissoc/tmp/somethingsomething")
    ;;           (peers
    ;;            (list
    ;;             (wireguard-peer
    ;;              (name "fi-hel-wg-001")
    ;;              ;;(endpoint "176.125.235.71:51820")
    ;;              (endpoint " 185.204.1.203:51820")
    ;;              ;;(public-key "jOUZjMq2PWHDzQxu3jPXktYB7EKeFwBzGZx56cTXXQg=")
    ;;              (public-key "veLqpZazR9j/Ol2G8TfrO32yEhc1i543MCN8rpy1FBA=")
    ;;              (allowed-ips '("0.0.0.0/0" "::0/0")))))))
    ;; (service guix-publish-service-type
    ;;          (guix-publish-configuration
    ;;           (host "10.45.136.51")
    ;;           (port 8080)
    ;;           (advertise? #t)))
    ;; (service wildfly-service-type
    ;;             (wildfly-configuration
    ;;              (maximum-heap-size "6000m")
    ;;              (initial-heap-size "4000m")
    ;;              (config-files
    ;;               (list (local-file "../../../conf-files/wildfly/logging.properties")
    ;;                     (local-file "../../../conf-files/wildfly/standalone.xml")
    ;;                     (local-file "../../../conf-files/wildfly/mgmt-users.properties")
    ;;                     (local-file "../../../conf-files/wildfly/mgmt-groups.properties")
    ;;                     (local-file "../../../conf-files/wildfly/application-roles.properties")
    ;;                     (local-file "../../../conf-files/wildfly/application-users.properties")))))
    ;; (service zabbix-agent-service-type
    ;;          (zabbix-agent-configuration))

    )
   (customize-services %base-services)))
 (bootloader
  (bootloader-configuration
   (bootloader grub-bootloader)
   (target "/dev/sdb")
   (keyboard-layout keyboard-layout)))
 (mapped-devices
  (list ;; (mapped-device
   ;;  (source
   ;;   (uuid "f3e4d0ca-fd56-4317-9cb8-b88f83ecb6c5"))
   ;;  (target "datadrive")
   ;;  (type luks-device-mapping))
   (mapped-device
    (source
     (uuid "4cc40178-2b40-4d33-9e37-bc073550f0a3"))
    (target "cryptroot")
    (type luks-device-mapping))))
 (file-systems
  (cons* (file-system
          (mount-point "/")
          (device "/dev/mapper/cryptroot")
          (type "ext4")
          (dependencies mapped-devices))
         ;; (file-system
         ;;  (mount-point "/data")
         ;;  (device "/dev/mapper/datadrive")
         ;;  (type "ext4")
         ;;  (dependencies mapped-devices))
         %base-file-systems)))
