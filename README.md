# Address Miner

## About
Address Miner is a vanity address generator for [Address Market](https://address-market.com) addresses that utilizes computing power from GPUs using OpenCL.

Based on [ERADICATE2](https://github.com/johguse/ERADICATE2) by Johan Gustafsson  
Beer donations for him: 0x000dead000ae1c8e8ac27103e4ff65f42a4e9203


## Usage
usage: `./address-miner [OPTIONS]`

Basic modes:
```
--benchmark             Run without any scoring, a benchmark.
--zeros                 Score on zeros anywhere in hash.
--letters               Score on letters anywhere in hash.
--numbers               Score on numbers anywhere in hash.
--mirror                Score on mirroring from center.
--leading-doubles       Score on hashes leading with hexadecimal pairs
--leading-any           Score on hashes leading with any symbol
```

Modes with arguments:
```
--leading <single hex>  Score on hashes leading with given hex character.
--leading-threshold <number>  Minimum leading score to display results (use with --leading).
--matching <hex string> Score on hashes matching given hex string.
```

Advanced modes:
```
--leading-range         Scores on hashes leading with characters within
		    given range.
--range                 Scores on hashes having characters within given
		    range anywhere.
```

Range:
```
-m, --min <0-15>        Set range minimum (inclusive), 0 is '0' 15 is 'f'.
-M, --max <0-15>        Set range maximum (inclusive), 0 is '0' 15 is 'f'.
```

Device control:
```
-s, --skip <index>      Skip device given by index.
-n, --no-cache          Don't load cached pre-compiled version of kernel.
```

Tweaking:
```
-w, --work <size>       Set OpenCL local work size. [default = 64]
-W, --work-max <size>   Set OpenCL maximum work size. [default = -i * -I]
-S, --size <size>       Set number of salts tried per loop.
		    [default = 16777216]
--rounds <count>        Set number of rounds per kernel dispatch. [default = 1]
```

Examples:
```
./address-miner --leading 0
./address-miner --leading-any
```

Profiling:
```
--profile               Enable kernel/read profiling output (shows average time once the first sample is collected).
```

