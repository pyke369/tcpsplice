## tcpsplice        [![Build Status](https://travis-ci.org/pyke369/tcpsplice.svg?branch=master)](https://travis-ci.org/pyke369/tcpsplice)

![Chain Of Gophers](/images/chain.jpg?raw=true "Chain Of Gophers")

`tcpsplice` is a simple TCP proxy/connection splicer written in Go.

## Requirements

`tcpsplice` only requires a recent Golang compiler (1.6+).

## Build

Just type the following commands at the shell prompt:

    $ git clone https://github.com/pyke369/tcpsplice
    $ cd tcpsplice
    $ make

From there, you may use the binary immediately or build a Debian package for later deployment (see below).

## Configuration

TODO

## Monitoring

![Monitoring Interface](/images/monitor.png?raw=true "Monitoring Interface")

## Packaging

(requires devscripts package)

You may optionally build a Debian package by typing the following command at the shell prompt:

    $ make deb

The `tcpsplice` binary will be installed by the package in the `/usr/sbin` directory, with additional
startup scripts and a default configuration file in `/etc/tcpsplice.conf`.

    $ sudo dpkg -i tcpsplice_1.0.2_amd64.deb
    Selecting previously unselected package tcpsplice.
    Unpacking tcpsplice (from tcpsplice_1.0.2_amd64.deb) ...
    Setting up tcpsplice (1.0.2) ...
