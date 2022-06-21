# Key Blinding for Signature Schemes

This is the working area for the Internet-Draft, "Key Blinding for Signature Schemes".

* [Editor's Copy](https://cfrg.github.io/draft-irtf-cfrg-signature-key-blinding/#go.draft-irtf-cfrg-signature-key-blinding.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-irtf-cfrg-signature-key-blinding)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-signature-key-blinding)
* [Compare Editor's Copy to Individual Draft](https://cfrg.github.io/draft-irtf-cfrg-signature-key-blinding/#go.draft-irtf-cfrg-signature-key-blinding.diff)

# Existing implementations

| Implementation                                                           | Language | Algorithms                     | Version |
| ------------------------------------------------------------------------ | :------- | :------------------------------| :------ |
| [ed25519](https://github.com/cloudflare/pat-go/tree/main/ed25519)        | Go       | Ed25519                        | main    |
| [ecdsa](https://github.com/cloudflare/pat-go/tree/main/ecdsa)            | Go       | ECDSA(P-384, SHA-384)          | main    |
| [ed25519-compact](https://crates.io/crates/ed25519-compact)              | Rust     | Ed25519                        | main    |
| [eddsa-key-blinding](https://github.com/jedisct1/zig-eddsa-key-blinding) | Zig      | Ed25519                        | main    |

Submit a PR if you would like your implementation to be added!

## Contributing

See the
[guidelines for contributions](https://github.com/cfrg/draft-irtf-cfrg-signature-key-blinding/blob/main/CONTRIBUTING.md).

Contributions can be made by editing markdown through the GitHub interface.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

This requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

