#ifndef HPP_HELP
#define HPP_HELP

#include <string>

const std::string g_strHelp = R"(
usage: ./address-miner [OPTIONS]

  Basic modes:
    --benchmark             Run without any scoring, a benchmark.
    --zeros                 Score on zeros anywhere in hash.
    --letters               Score on letters anywhere in hash.
    --numbers               Score on numbers anywhere in hash.
    --mirror                Score on mirroring from center.
    --leading-doubles       Score on hashes leading with hexadecimal pairs
    --leading-any           Score on hashes leading with any symbol

  Modes with arguments:
    --leading <single hex>  Score on hashes leading with given hex character.
    --matching <hex string> Score on hashes matching given hex string.
    -T, --leading-threshold <number>
                            With --leading, print every address scoring at
                            least <number> instead of only new best ones.

  Advanced modes:
    --leading-range         Scores on hashes leading with characters within
                            given range.
    --range                 Scores on hashes having characters within given
                            range anywhere.

  Range:
    -m, --min <0-15>        Set range minimum (inclusive), 0 is '0' 15 is 'f'.
    -M, --max <0-15>        Set range maximum (inclusive), 0 is '0' 15 is 'f'.

  Device control:
    -s, --skip <index>      Skip device given by index.

  Tweaking:
    -w, --work <size>       Set OpenCL local work size. [default = 256]
    -W, --work-max <size>   Set OpenCL maximum work size. [default = -S]
    -S, --size <size>       Set number of salts tried per loop.
                            [default = 16777216]
    -r, --rounds <count>    Set number of rounds per kernel dispatch.
                            [default = auto-tune]

  Profiling:
    -p, --profile           Print average kernel and read times.

  Examples:
    ./address-miner --leading 0
    ./address-miner --leading-any

  About:
    Address Miner is a vanity address generator for Address Market NFT addresses that
	utilizes computing power from GPUs using OpenCL.

    https://address-market.com

    Based on ERADICATE2 repo by Johan Gustafsson <johan@johgu.se>
    Beer donations for him: 0x000dead000ae1c8e8ac27103e4ff65f42a4e9203
)";

#endif /* HPP_HELP */
