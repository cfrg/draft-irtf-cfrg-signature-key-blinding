---
title: "EdDSA Key Blinding"
category: info

docname: draft-wood-cfrg-eddsa-blinding-latest
ipr: trust200902
area: AREA
workgroup: WG Working Group
keyword: Internet-Draft
venue:
  group: CFRG
  type: Working Group
  mail: cfrg@irtf.org
  github: USER/REPO
  latest: https://example.com/LATEST

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare, Inc.
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net
 -
    ins: F. Denis
    name: Frank Denis
    org: Fastly Inc.
    street: 475 Brannan St
    city: San Francisco
    country: United States of America
    email: fde@00f.net

normative:

informative:
  TORBLINDING:
    title: Proving Security of Tor’s Hidden Service Identity Blinding Protocol
    target: https://www-users.cse.umn.edu/~hoppernj/basic-proof.pdf
    date: 2013
    author:
      -
        ins: N. Hopper
        name: Nicholas Hopper


--- abstract

This document describes a variant of EdDSA as specified in {{!RFC8032}} for
blinding private and public keys such that the blinded public key and all
signatures produced using the blinded key pair are unlinkable to the unblinded
key pair. Signatures produced using blinded key pairs are indistinguishable
from standard EdDSA signatures.

--- middle

# Introduction

EdDSA {{?EDDSA=DOI.10.1007/s13389-012-0027-1}} is a type of Schnorr signature algorithm 
based on Edwards curves. The specification {{!RFC8032}} describes several variants of 
EdDSA with parameter sets for the edwards25519 and edwards448 curves as described in
{{?RFC7748}}. According to the specification, private keys are randomly generated
seeds, which are then used to derive scalar elements and their corresponding public
group element for signing and verifying messages, respectively. 

Given an EdDSA private and public key pair (sk, pk), any message signed by sk is
linkable to pk. One simply checks whether the message signature is valid under pk.
In some settings, in is useful to produce signatures with a given key pair (sk, pk)
such that the resulting signature is not linkable to pk without knowledge of a
particular witness r. That is, given pk corresponding to sk, witness r, and a 
message signature, one can determine if the signature was indeed produced using sk.
In effect, the witness "blinds" the key pair associated with a message signature.

This document describes a modification to the EdDSA key generation and signing
procedures in {{RFC8032}} to support this blinding operation, referred to as key
blinding.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used throughout this document to describe the blinding modification.

- `sk`: An EdDSA private key, which is a randomly generated private 
  seed of length 32 bytes or 57 bytes according to {{RFC8032, Section 5.1.5}}
  or {{RFC8032, Section 5.2.5}}, respectively.
- `pk(sk)`: The public key corresponding to the private key `sk`.
- `concat(x0, ..., xN)`: Concatenation of byte strings.
  `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.
- ScalarMult(pk, k): Multiply the EdDSA public key pk by scalar k, producing a new
  public key as a result.

In pseudocode descriptions below, integer multiplication of two EdDSA scalar values
is denoted by the \* operator. For example, the product of two scalars `x` and `y`
is denoted as `x * y`.

# Key Blinding

At a high level, key blinding allows signers to use private keys to blind their signing
key such that any signature produced under the blinded key pair is unlinkable to the
original signing key pair. Similar to the EdDSA private key used for signing, the blind 
is also an EdDSA private key. That is, the blind is a 32-byte or 57-byte random seed for
Ed25519 or Ed448 variants, respectively.

Key blinding extends the base EdDSA specification with three routines:

- BlindPublicKey(pkS, skB): Blind the public key pkS using the private key skB.
- UnblindPublicKey(pkM, skB): Unblind the public key pkM using the private key skB.
- BlindSign(skS, skB, msg): Sign a message msg using the private key skS with the private 
  blind skB. 

Correctness requires the following equivalence to hold:

~~~
UnblindPublicKey(BlindPublicKey(pkS, skB), skB) = pkS
~~~

Security requires that signatures produced using BlindSign are unlinkable from
signatures produced using the standard EdDSA Sign function with the same private key.

# Ed25519ph, Ed25519ctx, and Ed25519

This section describes implementations of BlindPublicKey, UnblindPublicKey, and BlindSign as
modifications of routines in {{RFC8032, Section 5.1}}.

## BlindPublicKey and UnblindPublicKey

BlindPublicKey transform a private blind skB into a scalar for the edwards25519 group
and then multiplies the target key by this scalar. UnblindPublicKey performs essentially
the same steps except that it multiplies the target public key by the multiplicative
inverse of the scalar, where the inverse is computed using the order of the group L,
described in {{RFC8032, Section 5.1}}.

More specifically, BlindPublicKey(pk, skB) works as follows.

1. Hash the 32-byte private key skB using SHA-512, storing the digest in a 64-octet 
   large buffer, denoted h. Only the lower 32 bytes are used for generating the public key.
1. Prune the buffer: The lowest three bits of the first octet are cleared, the highest 
   bit of the last octet is cleared, and the second highest bit of the last octet is set.
1. Interpret the buffer as the little-endian integer, forming a secret scalar s. Perform a 
   scalar multiplication ScalarMult(pk, s), and output the encoding of the 
   resulting point as the public key.

UnblindPublicKey(pkM, skB) works as follows.

1. Compute the secret scalar s from skB as in BlindPublicKey.
1. Compute the multiplicative inverse of s, denoted sInv, modulo L as defined in {{RFC8032, Section 5.1}}.
1. Perform a scalar multiplication ScalarMult(pk, sInv), and output the encoding 
   of the resulting point as the public key.

## BlindSign

BlindSign transforms a private key skB into a scalar for the edwards25519 group and a
message prefix to blind both the signing scalar and the prefix of the message used 
in the signature generation routine. 

More specifically, BlindSign(skS, skB, msg) works as follows:

1. Hash the private key skS, 32 octets, using SHA-512.  Let h denote the
   resulting digest.  Construct the secret scalar s1 from the first
   half of the digest, and the corresponding public key A1, as
   described in {{RFC8032, Section 5.1.5}}.  Let prefix1 denote the second
   half of the hash digest, h[32],...,h[63]. 
1. Perform the same routine to transform the secret blind skB into a secret
   scalar s2, public key A2, and prefix2. 
1. Compute the signing scalar s = s1 \* s2 (mod L) and the signing public key A = ScalarMult(A1, s2). 
1. Compute the signing prefix as concat(prefix1, prefix2).
1. Run the rest of the Sign procedure in {{RFC8032, Section 5.1.6}} from step (2) onwards
   using the modified scalar s, public key A, and string prefix.

# Ed448ph and Ed448

This section describes implementations of BlindPublciKey, UnblindPublicKey, and BlindSign as 
modifications of routines in {{RFC8032, Section 5.2}}.

## BlindPublicKey and UnblindPublicKey

BlindPublicKey and UnblindPublicKey for Ed448ph and Ed448 are implemented just as these
routines are for Ed25519ph, Ed25519ctx, and Ed25519, except that (1) SHAKE256 is used instead
of SHA-512 for hashing the secret blind to a 114-byte buffer, (2) the buffer is pruned
as described in {{RFC8032, Section 5.2.5}}, and the order of the edwards448 group L is
as defined in {{RFC8032, Section 5.2.1}}.

## BlindSign

BlindSign for Ed448ph and Ed448 is implemented just as this routine for Ed25519ph,
Ed25519ctx, and Ed25519, except in how the scalars (s1, s2), public keys (A1, A2),
and message strings (prefix1, prefix2) are computed. More specifically, 
BlindSign(skS, skB, msg) works as follows:

1. Hash the private key skS, 57 octets, using SHAKE256(skS, 117).  Let h denote the
   resulting digest.  Construct the secret scalar s1 from the first
   half of the digest, and the corresponding public key A1, as
   described in {{RFC8032, Section 5.2.5}}.  Let prefix1 denote the second
   half of the hash digest, h[57],...,h[113]. 
1. Perform the same routine to transform the secret blind skB into a secret
   scalar s2, public key A2, and prefix2. 
1. Compute the signing scalar s = s1 \* s2 (mod L) and the signing public key A = ScalarMult(A1, s2). 
1. Compute the signing prefix as concat(prefix1, prefix2).
1. Run the rest of the Sign procedure in {{RFC8032, Section 5.2.6}} from step (2) onwards
   using the modified scalar s, public key A, and string prefix.

# Security Considerations

This document describes a variant of the identity key blinding routine used in
Tor's Hidden Service feature. Security analysis for that feature is contained
{{TORBLINDING}}. Further analysis is needed to ensure this is compliant with
the signature algorithm described in {{RFC8032}}.

# IANA Considerations

This document has no IANA actions.

# Test Vectors

This section contains test vectors for Ed25519 as described in {{RFC8032}}.
Each test vector lists the private key and blind seeds, denoted skS and skB
and encoded as hexadecimal strings, the unblinded and blinded public keys,
denoted pkS and pkB and encoded according to {{RFC8032, Section 5.1.2}},
and the message and signature values, each encoded as hexadecimal strings.

~~~
skS: 8c21b65abb8413cf12e5e723bde5337b07a257b5cc8893128a9b6837d3c92168
pkS: 93f512c1fdc4bd2c35b42c5173822f1dc792dfda4df04518dbe8f6b4391ab612
skB: e3e75045e670bbcd958401a9f892d963f0413a3594ee2b918be5d671701dc635
pkB: 0f74d46e69d418d95ae190ddf0526643feac97f53a84cd7efc4c3f89a5a426eb
pkM: becee23eba2f4eb01fd743f2ee5983cc0098f33ba54ea72bf40dcc218e8e3d96
message: 68656c6c6f20776f726c64
signature: 895a390a5de23f821b1379aacee8fc8fb5ced73c7482fac61d0b2859cc957
a0f68a887e7539aa9d1d463f10ca119cab70a8c1763fd93fa425fe4da6976a8ae02

skS: aea7dd1f6342f591ae9ac0dfcbbc8cedf82ee16c76cea1d1d1d2a5362a94618d
pkS: b5b0e225b0ada4a00a56cac1c4c61a038e866163128f3260cbba96411bc70d30
skB: 0000000000000000000000000000000000000000000000000000000000000000
pkB: 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
pkM: b0f1cde5afa4022b7a2ca93839ed66375e1d6c318b44d644d7e78a66ac2ad771
message: 68656c6c6f20776f726c64
signature: 2f89287ba7e5df0efab4d736befc635368c026c6419f53955ed12e0a0d3ab
35dc5a6c51aad14792be1dfa1356574d089c36a9eff80887f611a2f8a2161cee000
~~~

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank Dennis Jackson for helpful discussions 
that informed the development of this draft.


