[![Functional Source License 1.1](https://img.shields.io/badge/License-Functional_Source_1.1-red)][FSL]

# Cryptographic Provenance Log (plog)

This crate implements a hash-linked data structure that is a cryptographically
verifiable provenance log. Cryptographic provenance logs are constructed as a
singly-linked list of entries that contain an arbitrarily long, ordered list of
mutations to a virtual key-value store as well as a set of cryptographic
puzzles that must be solved by the next entry in the list for it to be valid.
This design is to ensure delagatable, recoverable and revocable write control
over the log.

## Features
* Sequence numbering for detecting forks and erasures.
* Lipmaa links for O(log N) path lengths between any two entries in a plog.
* Forking capability to create child plogs with back links to the parent plog
  forming a DAG of plogs.
* Stable, non-key-material identifier to scope/namespace each branch in the
  DAG of plogs.
* WACC verification script for the next entry is stored inline or externally in 
  a content-addressable storage.
* Serialization to/from DAG-CBOR for automated retrieval of the entire plog.

## Plog entry 

Each plog entry contains the entry version, the VLAD identifier for the plog,
the CID of the previous entry in the log, the CID of the lipmaa predecessor,
the sequence number of the entry, the list of mutation operations, the lock
script for validating the next entry, the unlock script used for validating
this entry and the proof data also used for validating this entry.

## Virtual Name Space

The provenance log is a sequence of entries that each contain an ordered list
of mutation operations applied to a virtual key-value pair store. There are
three different possible operations: update, delete, and noop. The update
operation creates/updates the value associated with a key. The delete operation
deletes a key-value pair. The noop operation does nothing. As each entry in the
plog is verified and processed, the mutations contained within are applied to 
the virtual key-value pair storage. These pairs have no intrinsic meaning. It
is expected that they will have meaning in the context of the WACC lock and
unlock scripts as well as in the context of applications consuming the plogs.

### Hierarchical Keys 

The keys in the virtual key-value pair system are UTF-8 strings and are 
hierarchical in nature. They work similarly to file paths in Linux in that they
use the forward slash '/' character as the separator. All keys must begin with 
the '/' character but must not end with a '/' in the key-value ops.

### Values

The values in the key-value pair store are self describing and can take one of 
three values: nil, str, or data. The 'nil' value is an empty value. A 'str' 
value is a UTF-8 text string. The 'data' value is a binary blob.

### Example of virtual namespace

Let us assume the first entry in a provenance log includes the following ops.

```json
"ops": [
    "noop",
    { "update": [ "/name", { "str": [ "foo" ] } ] },
    { "update": [ "/move", { "str": [ "zig" ] } ] },
    { "delete": [ "/zig" ] },
]
```

After processing the first entry, the virtual key-value store contains the 
following.

```json
{
    "/move": "zig",
}
```

Then, let us assume the second entry contains the following ops.

```json
"ops": [
    { "update": [ "/name", { "str": [ "bar" ] } ] },
    { "delete": [ "/answer" ] },
    { "update": [ "/move", { "str": [ "zig" ] } ] },
]
```

After processing the second entry, the virtual key-value store contains the 
following.

```json
{
    "/name": "bar",
    "/move": "zig"
}
```

## Lock and Unlock Scripts

Each entry contains a list of lock scripts and a single unlock script. The set
of lock scripts define the conditions which must be met by the next entry in
the plog for it to be valid. The unlock script is the solution to one of the
lock scripts in the previous plog entry. All scripts are wasm code that
executes inside of a [WACC VM][WACC]. When a script is executed, it is expected
to reference data in a key-value store when executing. Along with the virtual 
key-value store from the ops in each event, the scripts may also reference the
fields in the event they are a part of (e.g. vlad, seqno, etc).

### Validating a Proposed Entry

It is critical to the security of the plog that the validation of each entry be
done following a very specific order of operations:

0. Create two empty key-value stores.
1. Apply the mutations for each entry in the plog, from the foot (first) to the
   head (last), to one key-value store so as to establish the current state of
   the plog.
2. Load the proposed entry fields (e.g. seqno, vlad, proof, etc) into the
   second key-value store to established the proposed state. DO NOT apply the
   `ops` mutations from the proposed entry.
3. Load the unlock script from the proposed entry and execute it to initialize 
   the stack for the lock script to execute.
4. Execute each lock script from the current entry in order. For each lock 
   script, clone stack from step 3 and clone the key-value pair store from step 
   1 and execute it.
5. Check the top value on the stack for a SUCCESS value, all other values
   indicate a failure.

### Example lock and unlock scripts

Assume the current entry (e.g. seqno: N) of the plog has the following
mutations.

```json
"ops": [
    { "update": [ "/pubkey", { "data": [ "<base encoded pubkey data>" ] } ] },
]
```

A lock script may reference the value of the public key like so:

```rust
#[no_mangle]
pub fn lock() -> bool {
    // check the signature using the data on the stack and the pubkey
    check_signature("pubkey")
}
```

or in web assembly text:

```wast
(module
  ;; the imported _check_signature function
  (import "wacc" "_check_signature" (func $check_signature (param i32 i32) (result i32)))

  ;; the exported "lock" function to call
  (func $main (export "lock") (param) (result i32)
    i32.const 0 
    i32.const 7 
    call $check_signature 
    return
  )

  ;; define the memory to store the string constants in
  (memory (export "memory") 1)

  ;; string constant to pass to check_signature
  (data (i32.const 0) "/pubkey")
)
```

The unlock script in the proposed new entry (e.g. seqno: N+1) references the
proof and the other entry values to provide a solution to the lock script in
the current entry (e.g. seqno: N) like so:

```rust
#[no_mangle]
pub fn unlock() {
    // push the serialized Entry as the message
    push("/entry");

    // push the proof data
    push("/proof");
}
```

or in web assembly text:

```wast
(module
  ;; the imported _check_signature function
  (import "wacc" "_push" (func $push (param i32 i32) (result i32)))

  ;; the exported "lock" function to call
  (func $main (export "unlock") (param) (result i32)
    ;; push("/entry/")
    i32.const 0 
    i32.const 6
    call $push

    ;; push("/entry/proof")
    i32.const 5 
    i32.const 12
    call $push 

    return
  )

  ;; define the memory to store the string constants in
  (memory (export "memory") 1)

  ;; string constant to pass to check_signature
  (data (i32.const 0) "/entry")
  (data (i32.const 6) "/entry/proof")
)
```

Then to check if the next entry is valid, the next entry's unlock script is
first executed followed by the lock scripts in the current entry. The scripts 
operate on a virtual stack not directly accessible to the lock scripts and
unlock script. If after both scripts execute there is a `SUCCESS` value on the
top of the stack then the validation was successful and the next entry is
valid. If any other value is on top of the stack, or there is no value at all,
then the next entry is invalid and discarded.

In the example given above, the unlock script pushes the value associated with 
the key "/entry" which is the compact serialized form of the proposed entry
with a NULL "/proof" value. In essence, the value associated with "/entry" is
the serialized entry object that was digitally signed; it is the message
associated with the digital signature. The value associated with "/proof" is
the digital signature itself. This assumes a detached signature but it is also
possible to use a combined signature that contains the signed data, eliminating
the need to push the "/entry" value but also unnecissarily duplicating the
entry data.

The lock script above executes the `check_signature` function passing it the
key referencing the public key to use. The function first peeks at the value on
top of the stack to see if there is a [Multisig][MULTISIG] encoded digital
signature on the top of the stack that it is the same kind of signature as the
public key it was passed. If those match, then the function expects the stack
to have the digital signature on top with the message just below that. It pops
the digital signature and message off of the stack, checks the signature, and
if it is valid, it pushes the `SUCCESS` marker onto the stack.

The `check_signature` function understands the [Multikey][MULTIKEY] and
[Multisig][MULTISIG] formats. It executes the correct signature validation
function depending on the kind of signature found on the stack (e.g. ed25519,
etc) and the public key passed to the function.

### Lock Scripts

To create a system that supports recovery, delegation, and  revocation in a
decentralized, p2p setting, a novel namespacing and precedence design is used
for evaluating lock scripts. 

```
 └── "entry/"
     ├─ "version"
     ├─ "vlad"
     ├─ "prev"
     ├─ "lipmaa"
     ├─ "seqno"
     ├─ "ops"
     ├─ "locks"
     ├─ "unlock"
     └─ "proof"
```

#### Namespacing

The [WACC VM][WACC] execution environment exposes a number of cryptographic
functions to lock and unlock scripts. To ensure maximum safety, no lock script
has direct access to any of the data in log events or the key-value pair store.
Instead the functions take keys as references to data as the parameters to
functions. You've already seen in the examples above how the `push` function
takes a key as its argument and the associated value is pushed onto the
execution stack. 

The keys themselves are actual a path-like string with forward slash `/`
characters as separators. This is because lock scripts are associated with
namespaces and leaves. A namespace is any key that ends with a `/` and a leaf
is any key that does not. It is correct to mentally think of namespaces like
filesystem folders and leaves like files. A namespace can contain other
namespaces and leaves.

Each lock script has a key-path that it governs and there may be multiple
lock scripts for each key-path that get executed in the order in which they
are listed in the log event's lock scripts list. If a namespace contains
children namespaces/leaves that do not have a lock script associated with them
then the parent namespace lock script also governs them. I think an example
would help understand this more clearer. Assume you have a key-path structure
like the following:

```
"/"
 ├─ "tpubkey"
 ├─ "pubkey"
 ├─ "hash"
 └─ "delegated/"
     ├─ "mike/"
     │   └─ "endpoint"
     ├─ "walker/"
     │   └─ "peerid"
     └─ "dave/"
         └─ "endpoint"
```

And also assume the entry has the following list of lock scripts in the most
current entry:

```json
[
  [ "/", "<root lock script>" ],
  [ "/delegated/mike/", "<mike lock script>"],
  [ "/delegated/walker/", "<walker lock script>"],
  [ "/delegated/dave/", "<dave lock script>"],
]
```

If a proposed entry only contains an op to `update("/foo")` then the only lock
script that gets executed is the one associated with the `/` namespace because
`/foo` is in the `/` namespace. If the proposed entry only contains an op to
`update("/delegated/mike/endpoint")` then the lock script for `/` runs, and if 
it fails, followed the lock script for `/delegated/mike/` runs because
`/delegated/mike/endpoint` is in the `/delegated/mike/` namespace. In this way
lock scripts associated with namespaces closer to the root override the lock
scripts closer to the leaves as it should be. If the provenance log owner
wishes to override an update made to a delegated namespace/leaf, their proof
takes precedence as long as it is causes a lock script closer to the root to
succeed. So in this example, the proposed next entry with proof that satisfies
the `/` lock script will take precedence over a proposed next entry with proof
that only satisfies the `/delegated/mike` lock script.

Lock scripts may themselves have multiple checks that are combined with logical
"and" and logical "or" operations. In those cases, precedence is stablished by
the "check counter". The check counter starts at zero and is incremented every
time a `check_*` function is called and fails. When two competing proposed 
entries satisfy the same lock script, the one with the _lowest_ check counter
value takes precedence.

Below is an example of the use of and and or predicates to construct a lock 
script that enforces that the proposed entry proof is either a valid threshold
signature or pubkey signature or preimage proof.

```rust
#[no_mangle]
pub fn lock() -> bool {
    // then check a possible threshold sig...
    check_signature("/tkey") ||   // check_count++
    // then check a possible pubkey sig...
    check_signature("/pubkey") || // check_count++
    // then the pre-image proof...
    check_preimage("/hash")
}
```

You can see the four `check_*` function calls. To enforce precedence in the
checks, every time a `check_*` function is executed and it fails the check
counter is incremented in the WACC VM. If the lock script succeeds, the check
counter value is pushed onto the stack as the payload of the
`SUCCESS(check_counter)` marker.

Because logical operations in Rust short circuit, in the example lock script
above, the only time the `check_preimage` function will execute is if the
`check_signature("/pubkey")` fails. The only time the
`check_signature("/pubkey")` function will execute is if the
`check_signature("/tkey")` function fails. If either `check_signature` functions
fail, their only side-effect is to increment the check counter. Then if the
`check_preimage` succeeds, the marker left on the stack will be `SUCCESS(2)`.
If the `check_signature("/pubkey")` succeeds, the marker left on the stack will
be `SUCCESS(1)`. If the `check_signature("/tkey")` succeeds, the marker left on
the stack will be `SUCCESS(0)`. If there are two competing entries and one
provides a valid signature and the other provides a valid preimage, the one
with the valid signature takes precedence over the one with the valid preimage
because the check counter is lower for the entry with the valid signature.

In the case where competing entries satisfy the same lock script with the same
check count, the entry with a mutation closest to the `/` namespace takes 
precedence. The solution for resolving a tie is for entry creators to generate 
proof with a lower check count or proof that satisfies a lock script with 
higher precedence. Single clause lock scripts are a bad idea for this reason; 
they leave the door open for unresolvable ties in precedence.

#### Delegation 

The lock script mechanism is designed to support delegation. By adding lock 
scripts associated with namespaces/leaves that can be satisfied by proofs 
generated by 3rd party people/services, the owner of a plog is delegating the 
management of those namespaces/leaves to those people/services. The precedence 
and check counter mechanism is designed to resolve any conflicts between 
competing entries, giving a hierarchy of who can override whom when updating a 
plog.

#### Forced recovery using precedence

The purpose of the precedence is to create lock scripts with the hardest to 
hack and most secure checks as the top precedences with less secure checks
having lower precedence. Today the most secure kind of check is a threshold
signature generated through the coopration of multiple independent
people/services. If the lock scripts are like the example given above where the
threshold check takes precedence over a public key signature that in turn takes
precedence over a preimage check, then if a password (i.e. preimage) is
compromised and the attacker creates a new entry using a preimage proof, the
rightful owner of the plog can then create a competing entry with the same
sequence number using a signature proof. The plog "protocol" demands that the
higher precedence entry to be chosen as the next valid entry and not the one
created by the attacker who guessed your password.

Most importantly, if a public key pair is compromised and an attacker attempts
a takeover by creating an entry using a signature proof, the rightful owner can
then contact their friends—or a threshold recovery service—and have them
create a threshold signature over a new entry that takes precedence over the
attacker's entry. The new entry with the threshold signature can then contain a
key rotation and key revocation mutation for the virtual key-value store
marking the compromised key as revoked as well as establishing a new valid
public keypair all without breaking the chain of trust in the plog.

You can think of this recovery scenario as a digital "social recovery" where
your friends collaborate to generate the threshold signature to recover your
control over your plog. This can be applied in a number of real-world
scenarios such as board control over a corporation's identity plog, heirs
collaborating with the deceased's counsel to take over the deceased's plogs, or
even parents co-signing with their minor children to update the children's plog
for some reason.

One especially useful application is empowering maintainers of a Git repository
with full identity and access management (IAM) capabilities. By requiring that 
the `/` namespace lock script have a `check_signature("/maintainers")`
threshold signature check as the highest precedence, then the threshold group
associated with the "maintainers" threshold public key have full control over
every key-value pair in the provenance log. Maintainers can force rotate to a
new signing key for a contributor if they should lose theirs or believe it to
be compromised. They can force rotate a contribor's signing key to NULL and
remove their ability to contribute to the repository. They can delegate
namespaces and leaves in contributors' provenance logs to enable a
repository-wide service to update the contributors' plogs as needed. In short,
a design like this gives the maintainers of the repository full control over
the IAM for contributors to the repository all without a centralized
server/service such as Github or Gitlab.

### The special case for the first entry

The first entry in a provenance log necessarily is self-signed since there
isn't a previous entry to establish the lock script to validate it with. In the
case where the entry's sequence number is `0` and the CID of the previous entry
is `None`, then the lock script is assumed to be the following:

```rust
#[no_mangle]
pub fn lock() -> bool {
    check_signature("/ephemeral")
}
```

Since there is no previous entry specifying the value of "ephemeral" then the
value is taken from the current proposed entry. This is the only case where a
check function reads its argument value from the key-value store after the
proposed entry mutations have been applied. In all other cases, the argument
value comes from the key-value store before the proposed entry mutations are
applied. This allows for the first entry of every plog to be self-signed. The
list of mutations in the first entry should at least contain the following:

```json
"ops": [
    { "update": [ "/ephemeral", { "data": [ "<base encoded ephemeral pubkey data>" ] } ] },
    { "update": [ "/pubkey", { "data": [ "<base encoded pubkey data>" ] } ] },
]
```

The "ephemeral" public key is the public key used to verify the signature over 
the first entry. This ephemeral key pair must be destroyed immediately after 
generating the signature over the first entry. This prevents any future 
compromise of the key pair that would allow an attacker to create a competing 
first entry. The signature is created over the VLAD value, the sequence number
0, and the set of mutation operations with both the ephemeral and pubkey
updates as well as the lock and unlock scripts.

## Forking provenance logs

It is possible to fork provenance logs by creating any number of child plogs.
Child plogs always start with an entry that has a sequence number of `0` but
the CID of the previous entry points at the entry in the parent plog from which
the child plog is forked. The entry in the parent plog must set up a lock
script that validates the first entry in the child plogs. An example lock
script in the parent plog for creating two child plogs is given below.

### Example parent forking entry

The parent entry must have `update` mutations to record the VLAD and public key
of the first entry in each of the child provenance logs like so:

```json
"ops": [
    { "update": [ "/forks/001/vlad", { "data": [ "<base encoded vlad of child 1>" ] } ] },
    { "update": [ "/forks/001/pubkey", { "data": [ "<base encoded pubkey of child 1>" ] } ] },
    { "update": [ "/forks/002/vlad", { "data": [ "<base encoded vlad of child 2>" ] } ] },
    { "update": [ "/forks/002/pubkey", { "data": [ "<base encoded pubkey of child 2>" ] } ] },
]
```

Then the lock script in the parent entry must have clauses for enforcing not
only the next entry in the parent plog but also the first entries in the child
plogs.

```rust
#[no_mangle]
pub fn lock() -> bool {
    // normal signature check for the next entry in the parent plog
    check_signature("/pubkey") ||

        // do both a check of the vlad and a signature check for first child
        (check_eq("/forks/001/vlad") && check_signature("/ephemeral")) ||

        // do both a check of the vlad and a signature check for second child
        (check_eq("/forks/002/vlad") && check_signature("/ephemeral"))
}
```

Then in the first entry of both child plogs, the unlock script looks like:

```rust
#[no_mangle]
pub fn unlock() {
    // push the entry values
    push("/entry/");

    // push the signature created using the ephemeral1 key pair
    push("/entry/proof");

    // push the vlad
    push("/entry/vlad");
}
```

When validating the first entry in the first child plog, the unlock script
pushes the serialized entry, the ephemeral signature over the entry as well as
the plog's VLAD value. Then the parent plog entry's lock script executes. The
first `check_signature` fails because it sees a VLAD on top of the stack and
not a signature. The script continues with the `check_eq` which will succeed
because the "/forks/001/vlad" value in the parent matches the "vlad" value in
the child. The `check_eq` function pops the top value from the stack and checks
if it equals the value associated with the key passed in. The `check_eq` pushes
the `SUCCESS(1)` marker and execution continues. The check count is 1 because
of previous call to `check_signature` that failed; the successful `check_eq`
does not increment the check counter. The `check_signature` function pops all
`SUCCESS` markers from the stack until it reaches a signature or the stack is
empty. If it finds a valid signature, it pops the signature and the message
from the stack and uses the ephemeral public key to verify the signature. In
this case, when the signature validates, the function pushes `SUCCESS(1)` onto
the stack and the script returns. The check count is `1` because there was a
prior `check_signature` that failed and incremented the check count. Neither
call to `check_eq("/forks/001/vlad")` and `check_signature("/ephemeral")`
incremented the check count because they both succeeded.

For the second child, the same process is followed as the first child. However,
the `check_eq("/forks/001/vlad")` check fails—incrementing the check count—and
the subsequence `check_eq("/forks/002/vlad")` check succeeds as well as the 
`check_signature("/ephemeral")` to verify the digital signature using the 
ephemeral public key both found in the first entry of the second child. The
resuting value left on the stack is `SUCCESS(2)` because both the first
`check_signature("/pubkey")` and `check_eq("/forks/001/vlad")` functions
failed; incrementing the check count two times in total.

As with the first entry in a non-forked plog, the first entry in a child plog
shall be digitally signed with an ephemeral key pair that is destroyed
immediately after signing the first entry. The mutation operations in the first
entry shall also contain and `update("/pubkey")` to establish the public key 
for the child plog as well as set the lock scripts to delegate control over the
child plog appropriately.

## Requirements for check function execution

0. The current key-value pair store is copied before the check function is
   executed.
1. The current stack is copied before the check function is executed.
2. All `SUCCESS(n)` markers must be popped off of the stack before the check 
   function executes.
3. The check function executes using the copied stack and key-value store. If
   it succeeds, the resulting stack becomes the new stack used for subsequent
   operations and the original is disgarded. If it fails, the stack copy is
   disgarded.
4. If a check function fails, the only side effect is incrementing the check
   count by 1.
5. If a check function succeeds, it must pop its arguments off of the stack and
   push on the stack a `SUCCESS(n)` marker where `n` is the check count.

[FSL]: https://github.com/cryptidtech/provenance-log/blob/main/LICENSE.md
[WACC]: https://github.com/cryptidtech/wacc.git
[MULTIKEY]: https://github.com/cryptidtech/multikey.git
[MULTISIG]: https://github.com/cryptidtech/multisig.git
