;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc push functions
  (import "wacc" "_push" (func $push (param i32 i32) (result i32)))

  ;; unlock script function
  (func $main (export "for_great_justice") (param) (result i32)
    ;; Push(<"/entry/">), this clones the current entry, sets the
    ;; "/entry/proof" value to an empty Vec<u8> then serializes the entry to a
    ;; Vec<u8> and pushes that onto the stack. This is necessary for a lock
    ;; script that calls check_signature since this is the signed message
    i32.const 0
    i32.const 7
    call $push

    ;; "/entry/proof", this data is either a digital signature over <"/entry/">
    i32.const 7
    i32.const 12
    call $push

    ;; Created Stack
    ;; ┌──────────────────┐
    ;; │ <"/entry/proof"> │
    ;; ├──────────────────┤
    ;; │ <"/entry/">      │
    ;; ├──────────────────┤
    ;; │        ┆         │
    ;; ┆                  ┆

    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                   [NAME]                  [IDX] [LEN]
  (data (i32.const  0) "/entry/"  )       ;;     0     7
  (data (i32.const  7) "/entry/proof"  )  ;;     7     12
)
