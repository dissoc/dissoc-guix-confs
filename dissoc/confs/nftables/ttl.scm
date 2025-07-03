(define-module (dissoc confs nftables ttl))

;; If you're here then you probably want to set ttl to 66 (65+1)
;; or 65 + n, where n is the number of routes
(define-public (generate-ttl-table interface-name ttl)
  (string-append "table inet tether_ttl {
	chain postrouting {
		type filter hook postrouting priority srcnat; policy accept;
		oifname " interface-name " ip ttl set " ttl "
		oifname " interface-name " ip6 hoplimit set " ttl "
	}

	chain prerouting {
		type filter hook prerouting priority 100; policy accept;
		iifname " interface-name " ip ttl set " ttl "
		iifname " interface-name " ip6 hoplimit set " ttl "
	}
}"))
