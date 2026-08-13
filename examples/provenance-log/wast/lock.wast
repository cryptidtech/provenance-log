;; SPDX-License-Identifier: FSL-1.1
;;
;; Standard lock script for provenance log entries.
;; Checks recovery key first (higher precedence), then primary key.
;;
(module
  (import "wacc" "_check_signature" (func $check_sig (param i32 i32 i32 i32) (result i32)))

  (func $main (export "move_every_zig") (param) (result i32)
    ;; Check 1: recovery key (check_count=0 if succeeds)
    i32.const 0   i32.const 14   ;; "/keys/recovery"
    i32.const 14  i32.const 7    ;; "/entry/"
    call $check_sig
    (if (then i32.const 1 return))

    ;; Check 2: primary key (check_count=1 if succeeds)
    i32.const 21  i32.const 13   ;; "/keys/primary"
    i32.const 14  i32.const 7    ;; "/entry/"
    call $check_sig
    return
  )

  (memory (export "memory") 1)

  ;;                     [NAME]              [IDX] [LEN]
  (data (i32.const  0)  "/keys/recovery")  ;;  0    14
  (data (i32.const 14)  "/entry/"       )  ;; 14     7
  (data (i32.const 21)  "/keys/primary" )  ;; 21    13
)
