;; SPDX-License-Identifier: FSL-1.1
;;
;; Standard unlock script for provenance log entries.
;; Pushes the primary proof signature onto the parameter stack.
;;
(module
  (import "wacc" "_push" (func $push (param i32 i32) (result i32)))

  (func $main (export "for_great_justice") (param) (result i32)
    ;; Push primary proof signature onto pstack
    i32.const 0  i32.const 15  call $push  ;; "/proofs/primary"
    return
  )

  (memory (export "memory") 1)

  ;;                    [NAME]              [IDX] [LEN]
  (data (i32.const  0) "/proofs/primary")  ;;  0    15
)
