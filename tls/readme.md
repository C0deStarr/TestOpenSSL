Directory:

```shell
$ tree
.
├── cacert.pem
├── csr.csr
├── makefile
├── prikey.key
├── server.crt
├── test.cpp
└── tls
    ├── tls_ctx.cpp
    ├── tls_ctx.h
    ├── tls_demo.cpp
    └── tls_demo.h
```

Server listening on port 23333 :

```shell
TestOpenSSL 23333
```

Client:

```shell
TestOpenSSL 23333 127.0.0.1
```

