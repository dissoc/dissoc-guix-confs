(define-module (dissoc confs nftables router))

;; modeled from:
;; https://github.com/gene-git/blog/blob/master/nftables/firewall/nftables.conf

(define-public %nftables-router
  "#!/usr/bin/nft -f
#
# Example of firewall - 2 interfaces.
#
#  One facing the internal network, one facing internet
#
#  Services:
#    2 kinds of services are allowed for:
#
#     - self services
#       These are on the firewall itself.
#       E.g. border mail, dns and ssh.
#
#     - forwarded services
#       These are provided by servers on the internal network.
#        E.g. web server, vpn, server,
#
#  NAT:
#    Internal network is NAT'd out.
#
#  Blocks:
#
#  We also support IP blocks from set of CIDRs. These are provided in separate file(s).
#  blocks come in 2 flavors:
#       - inet
#         These are the usual blocks for inbound (SYN) packets but do allow replies
#         to come back from these IPs if originated by us.
#
#       - netdev
#         These are blocked very early and are 'full' blocks. They are not allowed back in
#         not SYN nor Established/Related. You won't get a reply at all not even a ping.
#
#  Whitelist
#    - whitelist inet blocks
#
# After install use by:
#   systemctl enable nftables
#   systemctl start nftables
#
#   Manual
#       Use     : nft -f /etc/nftables.conf
#       Remove  : nft flush ruleset
#
#   Check   :
#       nft -c -f /etc/nftables.conf
#
#   Install:
#       - Edit nftables.conf
#           - interfaces, internal and external, match your own.
#           - change services artc as needed.
#
#       - Edit set files in etc/nftables.d/
#           - filter_sets
#
#       - check
#           Please run a 'check'.
#
#       - Save any existing rules:
#          mv /etc/nftables.conf /etc/nftables.conf.orig
#
#       - Copy rules
#           mkdir /etc/nftables.d
#           rsync -a nftables.conf /etc/
#           rsync -a etc/nftables.d /etc/nftables.d/
#
#           systemctl restart nftables
#
# Policy used is that nothing is allowed unless it is explicitly allowed by rules.
# Obviously adjust as needed :)
#
#  NB.
#  Flush, and turn off remove any legacy iptables rules before using nftbales.
#
#  systemctl stop iptables; systemctl disable iptables
#  systemctl enable nftables
#
#  - Adding new blocks:
#     Add whatever CIDR blocks to the blocks files and restart
#     systemctl restart nftables
#
#  N.B. Sets are local to each table. i.e not shareable across tables
#       See nftables documentation.
#
# Gene C 2023
#

#********************************************************************
# ===> Change <===:
#
define int_iface = enp6s0               # internal facing interface
define int_net = 10.0.0.0/24            # internal network

define ext_iface = enp0s25               # external facing interface
define ext_ip = 1.2.3.4                 # ip or range of ips : 1.2.3.4-1.2.3.14

define ssh_port = 46543                 # change and Add this port to sshd on firewall
define ssh_port_int = 46544             # this port forwarded to internal server : 22
define ssh_ip_int = 10.0.0.2            # internal server for ssh via ssh_port_int
define ssh_ip_fw_ext = 1.2.3.4          # external ip for ssh to firewall itself
define ssh_ip_inside_ext = 1.2.3.4      # external ip for ssh to some inside machine

define wg_port = 6666                   # wireguard port
define wg_ip = 10.0.0.10                # ip of internal wireguard server
define wg_ip_ext = 1.2.3.4              # external ip for wiregiard

define web_ip_ext = 1.2.3.4             # external ip for web server
define web_ip = 10.0.0.11               # ip of internal web server

#********************************************************************

# always start fresh
flush ruleset

table inet t_filter {

    chain early_packet_filter {
        # prio -150 is before pre routing in nat table and after connection tracking (-200)
        type filter hook prerouting priority -150; policy accept;

        # drop badly formed packets
        ct state invalid drop
        tcp flags & (fin|syn|rst|ack) != syn ct state new drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        tcp flags syn tcp option maxseg size 1-536 drop
    }

    chain blocks {
        # after early filter and before nat
        type filter hook prerouting priority -125; policy accept;

        ct state vmap { established : accept, related : accept }

        # inet allow (whitelist) and block
        iifname $ext_iface ip saddr @inet_whitelist accept
        iifname $ext_iface ip saddr @inet_blocks drop
    }

    chain input {
        # default policy is everything is dropped
        type filter hook input priority -50; policy drop ;

        # allow established/related traffic
        ct state vmap { established : accept, related : accept }

        # Allow icmp
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept

        # local traffic is ok
        iif lo accept

        # allow internal
        iifname $int_iface ip saddr $int_net accept

        # 5m ban for excessive SYN and log (adjust rate as needed)
        iifname $ext_iface tcp dport @xsrate_ports ct state new, untracked limit rate over 30/second counter update @xsrate_block { ip saddr }
        iifname $ext_iface ip saddr @xsrate_block log prefix \"nft: xs_rate \" drop

        # Services on firewall
        # DNS, mail and ssh
        # DNS and mail for entire ip range, ssh to fw on one specific ip
        iifname . ip daddr . meta l4proto . th dport {
            $ext_iface . $ext_ip . tcp .    53,
            $ext_iface . $ext_ip . udp .    53,
            $ext_iface . $ext_ip . tcp .    25,
            $ext_iface . $ssh_ip_fw_ext . tcp .    $ssh_port,
        } ct state new accept
    }

    chain output {
        type filter hook output priority 0; policy drop;

        # traffic to local / internal is ok
        oif lo accept
        oifname $int_iface ip daddr $int_net accept

        # our external facing IPs
        oifname $ext_iface ip saddr $ext_ip accept
    }

    chain forward {
        type filter hook forward priority -50; policy drop ;

        # from internal is ok
        iifname $int_iface accept

        # replies (related/established) are ok
        iifname $ext_iface ct state related,established accept

        # nat allowed to be forwarded
        ct status dnat accept
    }

    chain late_packet_filter {
        type filter hook postrouting priority 90; policy accept;

        # dont allow filtered ports out to internet (either local or forwarded)
        oifname $ext_iface ip protocol tcp tcp dport @filtered_tcp drop
        oifname $ext_iface ip protocol udp udp dport @filtered_udp drop
    }

    #
    # sets - can move these sets to the filter_sets file as well
    #
    set xsrate_block {
        type ipv4_addr ; flags dynamic,timeout ; timeout 5m;
    }
    set xsrate_ports {
        type inet_service ; flags interval;
        elements = {443}
    }
    set filtered_tcp {
        type inet_service; flags interval;
        elements = {2049, 6000-6015, 137-139, 445, 67-68, 135, 6660-6669,}
    }
    set filtered_udp {
        type inet_service; flags interval;
        elements = {2049, 6000-6015, 137-139, 67-68, 135, 161-162, 69, 514, }
    }

    # note the \"./etc\" so can be run either from system or from test area
    include \"./etc/nftables.d/filter_sets\"

} # end filter table

table inet t_nat {
    chain preroute {
        type nat hook prerouting  priority -100; policy accept;

        #
        # services map - edit/add :
        # This is a map which maps (something inbound) to (something outbound)
        # Specifically:
        #        (inbound)               :  (forward to internal)
        #   iface . ip . proto . port    :       ip . port
        #
        # Note http3 / Quic uses UDP on port 443
        #
        dnat ip to iifname . ip daddr . meta l4proto . th dport map {
            $ext_iface . $web_ip_ext        . tcp .  443            : $web_ip     .  443,
            $ext_iface . $web_ip_ext        . udp .  443            : $web_ip     .  443,
            $ext_iface . $web_ip_ext        . tcp .   80            : $web_ip     .   80,
            $ext_iface . $ssh_ip_inside_ext . tcp .  $ssh_port_int  : $ssh_ip_int .   22,
            $ext_iface . $wg_ip_ext         . udp .  $wg_port       : $wg_ip      .   $wg_port,
        }
    }

    chain postroute {
        type nat hook postrouting  priority 100; policy accept;

        # source NAT internal ips to external ip(s) (can be range of ips here as well)
        oifname $ext_iface ip saddr $int_net snat to $ext_ip
    }
} # end nat table

table netdev t_netdev {

    chain ingress {
        type filter hook ingress device $ext_iface priority -500; policy accept;

        # blocks - nothing allowed in. No SYN and no replies established/related
        ip saddr @netdev_blocks drop
    }

    chain egress {
        type filter hook egress device $ext_iface priority -500; policy accept;

        # block same outbound as inbound as can't get reply anyway
        ip daddr @netdev_blocks drop
    }

    include \"./etc/nftables.d/netdev_sets\"

} # end netdev table

")
