# pbotp

`pbotp` is a public-key based OTP mechanism. Its goal is to allow a central server to control and audit access to a number of devices without having to register the devices on the server beforehand, share secrets, synchronize time, etc. This is achieved through a public-key based challenge-response scheme where the device only needs to be configured with the server's public key.

Furthermore, it is meant to be usable on devices that are not online, so the challenge-response mechanism must be structured in such a way that it can be conveniently mediated by a human operator.

See `doc/proto.md` for more technical details.

This repository provides some components based on this mechanism, their operation is detailed in the following sections.

**Warning: While this project was built with the intention of being secure, the code has not undergone any kind of structured security review yet. Use at your own risk.**

## pam_pbotp

`pam_pbotp` uses the pbotp mechanism for implementing a PAM module that provides an authentication mechanism. It is configured via key-value pairs similar to other PAM modules. The following parameters are mandatory:

  * **pubkey**: The b64url encoded public key of the authentication server.
  * **baseurl**: The base url of the authentication server (without trailing slash).
  * **group**: The group of the device. Since the whole point of pbotp is that the server does not have to know each individial device, it still generally needs a way to know the *equivalence class* of the device. This could for example be a product code name.

See `doc/proto.md` for an example how these parameters get used.

Furthermore, there are some optional parameters:

  * **response_mode**: Determines how the response is to be encoded. Can be either `code` (default) or `phrase`.
  * **length**: Length of the response in digits (`code` mode, default: 9, max: 19) or words (`phrase` mode, default: 5, max: 23).
  * **qr**: How to render the QR code, only supported if built with libqrencode support. Valid values:
    * **utf8** (default): Represents the QR code using Unicode Block Elements and ANSI color codes. This gives the best and most compact results, but requires an Unicode-clean transport/terminal.
    * **ansi**: Only use ANSI color codes to render QR code modules. Requires support for ANSI color codes.
    * **ascii**: Only use ASCII art. Works everywhere, but can be difficult to scan.
    * **none**: Disable QR code generation.

The `code` mode gives about 3 bits of entropy per digit, the `phrase` mode uses a 2048-word dictionary and gives 11 bits of entropy per word.

Note that `pam_pbotp` does not set `pam_faildelay` on its own and leaves it to the administrator to use `pam_faildelay.so` as appropriate for the given application.

## genkey

`genkey` generates a public/private keypair.

Usage:

```
umask 077
./genkey privkey | tee key.priv | ./genkey pubkey > key.pub
```

## responder

A small Python web application that responds to challenges. It's only meant to serve as a demo counterpart to the challenger implementation and as an alternate representation of the challenge-response algorithm using another programming language and libraries.

There is no authentication/authorization support and it only supports the `code` response mode.
