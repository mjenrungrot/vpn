# Simplified VPN

This repository contains the working implementation of a simple SSL VPN system that is a part of the final project for 
CS181N - Computer Security (Fall 2017) at Harvey Mudd College. The design of the implemented VPN 
is based on the VPN Lab written by Wenliang Du, Syracus University. More details on the VPN lab can be accessed 
online at: [http://www.cis.syr.edu/~wedu/seed/Labs/VPN/](http://www.cis.syr.edu/~wedu/seed/Labs/VPN/)

# Technical Descriptions

Our VPN's implementation is using TLS/SSL based on UDP TUN/TAP tunnels implemented in OpenSSL. Data  
transmitted under the tunnels are encrypted using the AES encryption algorithm, and the integrity is ensured
by using Message Authentication Code (MAC) method with the HMAC-SHA256 algorithm. The encryption's key is based
on an initial vector randomly generated once the client and server are connected. The client-server authentication
is based on a generated public-key certificate with x509 standard.

# License

Copyright 2017 Teerapat Jenrungrot and Fabio Amendola

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
