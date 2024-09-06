(define-module (dissoc confs auditd workstation))

(define %auditd.conf
  "log_file = /var/log/audit.log
log_format = ENRICHED
freq = 1
space_left = 5%
space_left_action = syslog
admin_space_left_action = ignore
disk_full_action = ignore
disk_error_action = syslog")

(define %audit.rules
  "-D
-b 8192
# Failure Mode
## Possible values: 0 (silent), 1 (printk, print a failure message), 2 (panic, halt the system)
-f 1g

# Ignore errors
## e.g. caused by users or files not found in the local environment
-i
-w /etc/group -p wa -k etcgroup
")
