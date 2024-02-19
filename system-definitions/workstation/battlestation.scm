;;; Copyright © 2024 Justin Bishop <mail@dissoc.me>

;; NOTE: this definition will not build without access to private
;; files stored in the "vault". Otherise it will require modification for
;; use, especially where variables are used.

(define-module (dissoc-guix-confs system-definitions workstation battlestation))
(use-modules
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

;; this is where system variables are store. i.g. ip address
(load "/mnt/vault/configs/systems/battlestation.scm")

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
              (string-join (list %nftables-rules
                                 %ntables-portknocking) "\n")))

(define %gaomon-m10k-xorg-file
  "Identifier \"Tablet\"
  Driver \"wacom\"
  MatchDevicePath \"/dev/input/event*\"
  MatchUSBID \"256c:0064\"
  EndSection")

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
 (hosts-file (plain-file "hosts" %hosts-file))
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
                 '("wheel" "netdev" "audio" "video" "lp" "dialout")))
               %base-user-accounts))
 (packages
  (append
   (list stumpwm
         sbcl-stumpwm-ttf-fonts
         font-dejavu
         (specification->package "nss-certs"))
   %base-packages))
 (services
  (append
   (list
    (static-networking-service
     "eno1" %host-ip
     #:netmask %netmask
     #:gateway %gateway
     #:name-servers %name-servers)
    (service ntp-service-type)
    (service openssh-service-type)
    (elogind-service)
    (service slim-service-type
             (slim-configuration
              (auto-login? #t)
              (auto-login-session (file-append stumpwm "/bin/stumpwm"))
              (default-user "dissoc")
              (display ":0")
              (vt "vt7")
              (xorg-configuration
               (xorg-configuration
                (extra-config '(%gaomon-m10k-xorg-file)))))))
   (customize-services %base-services)))
 (bootloader
  (bootloader-configuration
   (bootloader grub-bootloader)
   (target "/dev/sdb")
   (keyboard-layout keyboard-layout)))
 (mapped-devices
  (list (mapped-device
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
         %base-file-systems)))
