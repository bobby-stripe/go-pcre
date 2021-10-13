# go-pcre

[![GoDoc](https://godoc.org/github.com/bobby-stripe/go-pcre?status.svg)](https://godoc.org/github.com/bobby-stripe/go-pcre)

This is a **pure** Go language package providing support for Perl Compatible Regular Expressions (PCRE), enabling the use of this package with `CGO_ENABLED=0`.

## Installation

Install the package for Debian as follows:

    go get github.com/bobby-stripe/go-pcre

## Usage

Go programs that depend on this package should import
this package as follows to allow automatic downloading:

    import "github.com/bobby-stripe/go-pcre"

## History

This is a clone of gijsbers's [go-pcre](https://github.com/gijsbers/go-pcre), but instead of using pcre via CGO, we compile pcre2 to WebAssembly and interpret it.
I've tried to keep the API the same, except by necessity the JIT-related functions were removed.
[bobby-stripe/pcre2-wasm](https://github.com/bobby-stripe/pcre2-wasm) contains the build script to compile pcre2 into wasm bytecode using docker.

This is a clone of
[golang-pkg-pcre](http://git.enyo.de/fw/debian/golang-pkg-pcre.git)
by Florian Weimer, which has been placed on Github by Glenn Brown,
so it can be fetched automatically by Go's package installer.

Glenn Brown added `FindIndex()` and `ReplaceAll()`
to mimic functions in Go's default regexp package.

Mathieu Payeur Levallois added `Matcher.ExtractString()`.

Malte Nuhn added `GroupIndices()` to retrieve positions of a matching group.

Chandra Sekar S added `Index()` and stopped invoking `Match()` twice in `FindIndex()`.

Misakwa added support for `pkg-config` to locate `libpcre`.

Yann Ramin added `ReplaceAllString()` and changed `Compile()` return type to `error`.

Nikolay Sivko modified `name2index()` to return error instead of panic.

Harry Waye exposed raw `pcre_exec`.

Hazzadous added partial match support.

Pavel Gryaznov added support for JIT compilation.
