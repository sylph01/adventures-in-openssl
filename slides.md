---
title: Adventures in the Dungeons of OpenSSL
paginate: true
marp: true
theme: argent
---

<!-- _class: titlepage -->

# Adventures in the Dungeons of OpenSSL
## Ryo Kajiwara (sylph01), 2023/07/12
### @ somewhere?

---

<!-- _class: titlepage -->

# Hi!

---

<!-- _class: titlepage -->

# I do stuff

<!-- DDR, bassoon, Magic: the Gathering, trains(rails) -->

---

<!-- _class: titlepage -->

# And I do stuff

<!-- ISOC-JP, W3C, IETF, current work -->

---

<!-- _class: titlepage -->

# I'm from the **Forgotten Realm** of Japan called **Shikoku**

---

<!-- _class: titlepage -->

# Caution before I start...

----

<!-- _class: titlepage -->

# I'm going to talk about **Dungeons**

----

<!-- _class: titlepage -->

# ... so there be **Dragons**

<!-- 
https://en.wikipedia.org/wiki/Here_be_dragons

Dungeons & Dragons, am I right
-->

----

<!-- _class: titlepage -->

# Maybe try this at home,

# but **definitely not in production** unless you're super sure

----

# Caution

- Cryptographic API can be very easy to misuse
  - What's different from dungeons like `parse.y`-vania is that **you can actually hurt yourself.** Do you like security breaches?
- I've done my research, but I don't consider myself a cryptography expert
  - I don't have a PhD/Master in this field, so yeah...
  - If you're not sure, please have your system audited by a security expert before going to production

----

# Past Related Work

- [Do Pure Ruby Dream of Encrypted Binary Protocol? / Yusuke Nakamura @ RubyKaigi 2021](https://youtu.be/hCos6p_S-qc)
  - Talks about the pain of handling hex-encoded and raw strings in Ruby
  - Also talks about implementing protocols

<!-- By the way, the answer to this question is: "Yes it does. I'm going to talk about one." -->

----

----

<!-- _class: titlepage -->

# HPKE
## Hybrid Public Key Encryption, RFC 9180

----

# What is HPKE

- In the past:
  - Encrypt a session key using Public Key Cryptography
    - like RSA
  - Then send your messages using symmetric ciphers
    - like AES
  - You don't do everything with PKC because it's costly

----

# What is HPKE

- The problem
  - 「公開鍵警察」
  - dies from misuse
    - PKCS padding...

----

# What is HPKE

- HPKE solves this by:
  - Agreement of symmetric keys using a **Key Encapsulation Mechanism (KEM)**
    - that internally uses a **Key Derivation Function (KDF)**
  - Then use the symmetric keys to perform **Authenticated Encryption with Associated Data (AEAD)**

----

# What is HPKE

- The high-level API of HPKE is designed to prevent misuses
  - misuse of RSA was very prevalent
  - nonce reuse of AES-CBC was also very prevalent

----

# So I wanted HPKE in Ruby...

----

# What is needed for HPKE?

- Key Encapsulation Function
  - Diffie-Hellman Key Exchange
    - use of Elliptic Curves: P-256, P-384, P-521, X25519, X448
- Key Derivation Function
  - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    - HMAC-SHA256, HMAC-SHA512
- Authenticated Encryption with Associated Data
  - AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305

----

# All of this is supported by **OpenSSL**, right?

----

# Well, **kinda**

----

# What we had readily available

- AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
  - `test/openssl/test_cipher.rb`
  - ChaCha20-Poly1305 isn't in this test code, but uses the same API as AES-GCM
- HMAC-SHA256, HMAC-SHA512
  - Even with SHA256 and SHA512 only, I can implement HMAC
  - Actually we have HKDF itself but we need to use some parts of HKDF and customize it

----

# What we 'kinda' had

- Elliptic curves P-256, P-384, P-521
  - `test/openssl/test_pkey_ec.rb`
- X25519, X448
  - `test/openssl/test_pkey.rb`

----

# Q: Really? These seem to be undocumented

# A: **Yes.**

----

# Really? These seem to be undocumented

(as I heard from an undisclosed Ruby committer)

Some APIs in OpenSSL are intentionally left undocumented to avoid misuses by people who are not well-versed in cryptography.

Yes, misuse in cryptography **can hurt yourself.**

----

# `OpenSSL::PKey`

an explanation

----

# Raw public/private key support for X25519/X448

----

# Raw public/private key support for X25519/X448

- There was a pull request that worked on this
- But it was 3 years old and not working on some platforms
- So I started working on this by
  - Fixing errors on the CI matrix
  - Addressing unfixed review comments

----

# https://github.com/ruby/openssl/pull/646

## my first Ruby C extension experience!

----

# While I was at it...

----

# `OpenSSL::PKey` is immutable in OpenSSL 3.0

----

# So you can't do this

```ruby
pkey = OpenSSL::PKey::EC.new('prime256v1')
pkey.private_key = SecureRandom.random_bytes(32)
```

Note: A private key of `P-256` elliptic curve consists of a 32 byte number (=scalar). 

<!-- To be more accurate, it is a positive number under the "order" of the generator, which in `P-256`'s case is `0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`. -->

----

# In OpenSSL 3.0, we were not just missing APIs to make **X25519/X448 key pairs**,

# we didn't even have APIs to make **EC key pairs**!

----

# How can we create a key pair with a **specified** private key?

----

# This was available

```ruby
der = # write something in ASN.1 DER format

OpenSSL::PKey.read(der)
```

----

# ASN.1 Sequence -> DER -> `PKey::EC`

it's even in Ruby 3.3 preview1!

----

# Enter **ASN.1**

----

# ASN.1?

an explanation

----

# I did this in my initial HPKE gem for X25519/X448 too

----

# But does this look good?

# **No, it's ugly!**

----

# API to generate PKeys with a private key

(after I actually work on this)

----

----

# Well actually, we **had** HPKE itself in OpenSSL 3.0

----

# Why not write a Ruby wrapper for this?

----

(about actually writing a wrapper for HPKE)

----


----

# Conclusion

----

# So here was my **"Adventures in the Forgotten Realm"** called OpenSSL

----

# **Why** HPKE in Ruby?

It's the building block for modern security/privacy protocols

- TLS Encrypted ClientHello
- Oblivious HTTP
- Messaging Layer Security

----

# **Why** HPKE in Ruby?

If we don't have the building block for modern networking protocols, people would not implement them

... and just **go to Python / Go / Rust / whatever** because they have the building blocks readily available.

----

# We need modern cryptography in Ruby **for Ruby to stay relevant**

----

# It's not for everyone
# ... but it **surely is** for someone

----

# The adventure continues...

- HPKE is just a building block for other protocols
- I am working on implementing protocols that rely on HPKE
- Also now that I came back from the OpenSSL dungeon alive, I might continue digging into this "Forgotten Realm"

----

# Shoutouts

(@ mentions are in GitHub ID)

- Ruby OpenSSL maintainers, esp. @rhenium
- Past RubyKaigi speakers, esp. @unasuke and @shioimm
- HPKE implementers, esp. @dajiaji

<!-- and whatever conference team I'm submitting to -->

----

# Questions? / Comments?

## Twitter: @s01 or Fediverse: @s01@ruby.social