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
