(define-module (dissoc confs nftables ttl))

(define-public (generate-ttl-table interface-name)
  (string-append "table inet tether_ttl {
	chain postrouting {
		type filter hook postrouting priority srcnat; policy accept;
		oifname " interface-name " ip ttl set 66
		oifname " interface-name " ip6 hoplimit set 66
	}

	chain prerouting {
		type filter hook prerouting priority 100; policy accept;
		iifname " interface-name " ip ttl set 66
		iifname " interface-name " ip6 hoplimit set 66
	}
}"))
