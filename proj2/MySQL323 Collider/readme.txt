MySQL323 Collider 1.1

Run this in command prompt!!!

*** New in MySQL323 Collider 1.1 ***

* Multi hash with -l|--list
* Fixed on Ctrl+C the last n-1 threads' work get check instead of thrown away
* Fixed issue with odd and even hashes
* -m|--memory is required


Please note with -m|--memory this is only the memory used for the main lookup table.
In the 64 bit versions there is 384 MiB of other data and 320 MiB in the 32 bit versions.
Using -n saves 256 MiB in all versions.


*** Required parameters ***
 -h|--hash=<string>
    A MySQL323 hash (such as 7fffffff7fffffff)

 -l|--list=<file>
    A file with a list MySQL323 hashes

 -m|--memory=<int>
    MiB of memory to allocate for main lookup table

 -t|--threads=<int>
    Number of threads


*** Optional parameters ***
 --help
    Display this message and exit

 -c|--collisions=<int>
    Number of collisions found before exiting (default 1)

 -e|--even
    Run only even hashes (Only applies to -l|--list)

 -n|--no-bitmap
    Don't create the 31 bits of the hash bitmap

 -o|--output=<file>
    A file to output cracked hashes

 -O|--odd
    Run only odd hashes (Only applies to -l|--list)

 -p|--prefix
    Use t, M, B, T, and Q for thousand, million, billion, trillion, and
    quadrillion. Instead of the SI prefixes k, M, G, T, P, E, Z, and Y.

 -r|--resume=<int>
    Resume code

 -s|--silent
    Silent mode (suppresses output of current speed)

 -S|--super-silent
    Super silent mode (outputs cracked hashes or nothing with -o)

 -v|--verbose
    Verbose mode
