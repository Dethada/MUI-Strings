# MUI Parser

Get strings from the resource section of MUI files.

## Building 🔨

```bash
cargo build --release
```

## Install

### Linux 🐧
```bash
make install
```

### Windows
Add `target/release/mui-strings` to somewhere in path.

## Usage 📖

```bash
➜ mui-strings --help
MUI Strings 0.1.0
David Z. <david@dzhy.dev>
Get strings from the resource section of MUI files.

USAGE:
    mui-strings --file <file>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f, --file <file>    The target file
```