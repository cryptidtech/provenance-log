;; SPDX-License-Identifier: FSL-1.1
;;
;; First entry lock script for provenance log examples.
;; Verifies that the entry was signed with the ephemeral VLAD key.
;;
(module
  (import "wacc" "_check_signature" (func $check_sig (param i32 i32 i32 i32) (result i32)))

  (func $main (export "move_every_zig") (param) (result i32)
    ;; check_signature("/vlad/key", "/entry/")
    i32.const 7   i32.const 9    ;; "/vlad/key"
    i32.const 0   i32.const 7    ;; "/entry/"
    call $check_sig
    return
  )

  (memory (export "memory") 1)

  ;;                     [NAME]             [IDX] [LEN]
  (data (i32.const  0)  "/entry/"     )  ;;   0     7
  (data (i32.const  7)  "/vlad/key"   )  ;;   7     9
)
