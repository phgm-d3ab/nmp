#### Addresses and keys
A "full address" in these examples is implemented as `pubkey@ip:port`,  where:
* `pubkey` is a string representing peer's public key in hex
* `ip:port` is IP4 or IP6 address+port in formats `0.0.0.0:00000` or `[0:0:0:0:0:0:0:0]:00000` respectively
* bind accepts `ip:port`, defaults to `0.0.0.0:0` if `-b` not set

Keys are generated using `getrandom()` if `-k` not set, or loaded from binary files which can be generated using:
```shell
dd if=/dev/urandom of=key bs=56 count=1
```

#### Message
Alice generates a key and binds to some port on localhost:
```shell
$ ./message -b 127.0.0.1:0
[conf] using addr: 127.0.0.1:56594
[conf] local public key:
ee29384278117e1ca7d6ebf7acb0651cd6cf8b5284a2b762c4e3f634
1172c9e11336cba17fd36871c0ba641b82f26a16761cb524e60c75fa
...
```

Bob tries to connect:
```shell
$ ./message -c ee29384278117e1ca7d6ebf7acb0651cd6cf8b5284a2b762c4e3f6341172c9e11336cba17fd36871c0ba641b82f26a16761cb524e60c75fa@127.0.0.1:56594
[conf] using addr: 0.0.0.0:49273
[conf] local public key:
32879bd83374ec0c7444f709702f6a7b18be6d76742ca450cebee0c5
ab6bc7080bb3311ecee179beeab0bd085781d94512c2cf3f0b3bc161
[peer] e93fbae connecting..
```

Alice accepts connection:
```shell
...
[peer] session e93fbae connecting from 127.0.0.1:49273
32879bd83374ec0c7444f709702f6a7b18be6d76742ca450cebee0c5
ab6bc7080bb3311ecee179beeab0bd085781d94512c2cf3f0b3bc161
[peer] connected (e93fbaeu)
```

Alice and Bob can start exchanging messages.

#### File transfer
Alice listens for incoming files:
```shell
$ ./file_transfer -f alice.file
[conf] using addr: 0.0.0.0:34721
[conf] local public key:
9722132946e73199c219625c2cbdea0d319a1a03c437be3879a70227
5116cdf8a2e6b5996ea814ebf0f7f557f9da82017e525510843d60d3
...
```

Bob generates some file and sends it to Alice:
```shell
$ dd if=/dev/urandom of=bob.file bs=1M count=1
$ ./file_transfer -a 9722132946e73199c219625c2cbdea0d319a1a03c437be3879a702275116cdf8a2e6b5996ea814ebf0f7f557f9da82017e525510843d60d3@127.0.0.1:34721 -f bob.file
[ft] sending 'bob.file'
[conf] using addr: 0.0.0.0:58230
[conf] local public key:
31a7b021343bebe192c8cafcb40b82f9f2a6c294a1c3273e0418a491
b4b742ec5b79e6b3f05818c8df7a36a84e6bc4a3ee733f869176631a
[ft] starting
[ft] sent 'bob.file' (1.0 MB)
```

Alice receives file:
```shell
...
[peer] session f753fc38; receiving 1.0 MB from 127.0.0.1:58230
31a7b021343bebe192c8cafcb40b82f9f2a6c294a1c3273e0418a491
b4b742ec5b79e6b3f05818c8df7a36a84e6bc4a3ee733f869176631a
[ft] starting
[ft] received 'alice.file' (1.0 MB)
```

Both Alice and Bob can verify hash:
```shell
$ sha256sum alice.file bob.file
3788a309ed6f065cec03392fa3a39ff8b709a1b29a5407a38ecbbe82738d1106  alice.file
3788a309ed6f065cec03392fa3a39ff8b709a1b29a5407a38ecbbe82738d1106  bob.file
```
