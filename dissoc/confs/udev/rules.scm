(define-module (dissoc confs udev rules)
  #:use-module (gnu services base))

(define-public %ucore-tracer-udev-rule
  (udev-rule
   "90-ucore-tracer.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"0483\", "
                  "ATTRS{idProduct}==\"5750\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))

(define-public %de-5000-udev-rule
  (udev-rule
   "90-de-5000.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"0403\", "
                  "ATTRS{idProduct}==\"6001\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))

(define-public %bk-393-udev-rule
  (udev-rule
   "90-bk-393.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"0403\", "
                  "ATTRS{idProduct}==\"6001\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))

(define-public %lilygo-ttgo-udev-rule
  (udev-rule
   "90-lilygo-ttgo.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"239a\", "
                  "ATTRS{idProduct}==\"4405\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))

(define-public %gaomon-m10k-udev-rule
  (udev-rule
   "90-gaomon-m10k.rules"
   (string-append "SUBSYSTEM==\"usb\", "
                  "ATTRS{idVendor}==\"256c\", "
                  "ATTRS{idProduct}==\"006f\", "
                  "GROUP=\"users\", "
                  "MODE=\"0666\"")))
