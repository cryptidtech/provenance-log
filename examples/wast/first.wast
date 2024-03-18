;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc functions
  (import "wacc" "_check_signature" (func $check_signature (param i32 i32) (result i32)))

  ;; function to execute the signature check for the first entry in a plog
  (func $main (export "move_every_zig") (param) (result i32)

    ;;   Stack
    ;; ┌────────────────┐
    ;; │ "/entry/proof" │
    ;; ├────────────────┤
    ;; │ "/entry/"      │
    ;; ├────────────────┤
    ;; │       ┄        │ 
    ;; ┆                ┆

    ;; check_signature("/ephemeral")
    i32.const 0
    i32.const 10
    call $check_signature
    (if
      (then
        return
      )
      (else
        i32.const 0
        return
      )
    )
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                    [NAME]              [IDX] [LEN]
  (data (i32.const  0)  "/ephemeral" )  ;;    0     10
)
