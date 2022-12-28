# sign-file
Rust version of sign tool for kernel module, see: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/scripts/sign-file.c

# Command help
```shell
Command to sign kernel module file with x509 certificate

Usage: sign-file [OPTIONS] [COMMAND]

Commands:
  produce  Sign ko file as well as generate detached signature file (*.p7s)
  detach   Sign ko file with only generate detached signature file (*.p7s)
  raw      Append raw signature to ko file
  help     Print this message or the help of the given subcommand(s)

Options:
      --debug    
  -h, --help     Print help information
  -V, --version  Print version information

```