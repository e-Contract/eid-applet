README for FedICT eID Applet - PHP 5 back end
=============================================

(c) 2009, Bart Hanssens, Fedict


=== 0. Warning

THIS IS AN ALPHA VERSION, DO NOT USE THIS IN A PRODUCTION ENVIRONMENT


=== 1. Introduction

This project contains the source code tree of the FedICT eID Applet
PHP 5 back-end, a port of the Java back-end
The source code is hosted at: http://code.google.com/p/eid-applet-php


=== 2. Caveats

- PHP 5.2.9 does not serialize DateTime
(that's a problem when going from one .PHP page to another...)
- by default, session data is stored server side as (more or less) plain text files
(msession should be used)
- PHP 5.x does not support strong typing ("type hinting") for primitives types like int, string
(so we need to add some ugly is_string() code to check parameters)
- openssl_random_pseudo_bytes() requires PHP 5.3
- DateTime::createFromFormat requires PHP 5.3


=== 3. Requirements

For the moment, this PHP5 back end requires at least

- PHP 5.2.9
- pecl_http
- OpenSSL

In the near future PHP 5.3.0 will be required


=== 4. Build
...

=== 6. License

The license conditions can be found in the file: LICENSE.txt

