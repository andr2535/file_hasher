# File_hasher

This program was written for making reliable integrity checks for files from some root directory.

File_hasher creates a list of file checksums, which is itself protected by a checksum.

It also creates a banlist, which contains paths that will not be indexed by the program.  
As this file affects which files that will be indexed, it is also protected by a checksum.

File_hasher always creates a backup of the file_hashes file,  
when it has successfully parsed it.

All files created by file_hasher are stored in the folder "./file_hasher_files/".

### Installing

#### Install using deb file

There is a .deb file included in the releases tab of Github.  
It can be installed using this command:
```
dpkg -i debfilename.deb
```

#### Install using Cargo

```
cargo install --path ./file_hasher_term/
```

#### Other OS than Linux

File_hasher has only been tested on Linux.  
However I don't see any reason why it wouldn't work on Windows or Mac OS.

## License

File_hasher is licensed under the GPLv3 [license](LICENSE) or later.