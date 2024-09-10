(define-module (dissoc confs nftables core))

(define-public (generate-nftable-rules ip-allow port-allow)
  (string-append
   "# A simple and safe firewall
define VPN_ALLOW = { " ip-allow " }
define VPN_PORT = " port-allow "
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
}"))

(define-public (port-redirect dport redirect-port)
  (string-append
   "table ip nat {
  chain prerouting {
    type nat hook prerouting priority 100; policy accept;
    iif eth0 tcp dport { " dport " } counter redirect to " redirect-port "
  }
}"))
