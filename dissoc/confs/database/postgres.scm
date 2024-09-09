(define-module (dissoc confs database postgres))

(define %postgres-hba-file
  (string-join '("local	all	all			trust"
                 "host	all	all	127.0.0.1/32 	trust"
                 "host	all	all	::1/128 	trust")
               "\n"))
