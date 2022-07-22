# XilinxUnprotect

Tool for removing content protection from vhdl and verilog files.

Xilinx, and other fpga tool suppliers use several kinds of content protection in their products.

## Xilinx method

In older versions of ISE Xilinx used their own scheme. The contents of the file was either only
compressed, or compressed and encrypted with a fixed key.

These files start with a magic string: `XlxV`.

## Verilog Protected Envelope

A method used by several manufacturers: Verilog Protected Envelope. This is standardized in IEEE P1735.

These files can be recognized by presence of the string: `pragma protect begin_protected`.

The private keys needed to decrypt are found by reverse engineering fpga toolchains.
If you find a file which can not yet be decoded by `xlxunprotect.py`, please open an issue here on github.

Currently keys for Xilinx, mentor and altera have been found.


## Usage

    python xlxunprotect.py  filelist

files will be output to stdout with content protection removed.

## Some statistics

Here is an overview of how many of various kinds of protected files i found in my ISE directory.

| occurence | protection type
| -----:| ------
|   824 | XILINX-XDB 0.1 STUB 0.1 ASCII.XILINX-XDM V1.6e
|    30 | XlxV32DM ( in XILINX-XDB 0.1 STUB 0.1 ASCII.XILINX-XDM V1.6 )
|    17 | XlxV35EB
|     4 | XlxV36EB
|  3816 | XlxV37EB
|    64 | XlxV38EB
|  5351 | XlxV50EB
|    15 | XlxV60EB
|    74 | XlxV61EB
| 34132 | XlxV64EB
|  6664 | XlxV65EB
|   189 | XlxVHYEB
|     0 | XlxVc1EB
|     0 | XlxVHLEB
|  3517 | `pragma protect

These have many different file extensions, but the most interesting:

| occurence | file
| -----:| ------
| 17747 | protected .v or .vhd
| 22517 | unprotected .v or .vhd

The Xilinx RSA keys
===================

The private keys for the vhdl content protection are stored in `.pem` files in the `/opt/Xilinx/14.7/ISE_DS/ISE/data` directory.

These private keys can be decrypted, for instance using openssl:

    openssl rsa -passin pass:<longhexkey> -in xilinx.pem -out decrypted.pem
    
The filenames of the keys are: `xilinx_2048_pvt.pem`,  `xilinx_3072_pvt.pem`, `xilinx_2013_09.pem`, `xilinx_2014_03.pem`.

The key for the first three is:

6e0380d8f8b58ae296366baab0a421fec94f87c6b6f6dc10id48625a6428f1b3464b27c0379304d09d157b3869bdcb2dc1a19c4d299027a9fc04bf09abc13f2

The key for the 2014 key is:

f8b58ae26ea380d82a1421fei6366ba1c94fh7c69d4h625ab6564c1a642hf1b33g9304d0464227c0i4157b38c1a19c4d6ibdcb242i9027aiabc13fb

The key for the 2015 key is:

6ea380d8f8b58ae22a1421feabc13fb

in 2016 Xilinx switched to using binary keys, you can no longer use the openssl commandline to decrypt these.

the 2017.1 key is: hex:`08 0f 07 05 6b 09 0a c1 08 0e f5 05 0c 01 0e 0a 07 ae 05 ba`

The encrypted certificates have become a bit more difficult to extract from the `libisl_iostreams` library,
I now found them by piecing together the chunks of base64 like text until they matched up to be a valid certificate.

The Xilinx download files
=========================

When installing a xilinx product, the installer will download many .xz archives. These are password protected, with the password:

    www.Trebuchet.com

Since 2016.1, the password is: `www.theonion_saidnasser.com`

The password is now stored in the file `data/idata.dat`, in `idata.xml`, in the property named `archivePasswd`.
The `.dat` file is encrypted with this password:

    Error, There was an unexpected error, code 00345~. See AR:342674 @ http://www.xilinx.com

You can find this by decompiling xinstaller, and look in IDataManager.java.


Links
=====

Previously this tool was published 
 * [as a gist](https://gist.github.com/anonymous/8de2917b7b305718e920)
 * [on github](https://github.com/reversing-research/XilinxUnprotect)
 * [on okis.ru](http://revres.okis.ru/)
 * [now defunct onion](haklab4ulibiyeix.onion/revres/XilinxUnprotect)
 
Another tool decrypting `begin_protect` sections: [hdl_decrypt](https://github.com/hdl-writer/hdl_decrypt)

Encryption tools
================

 * Aldec protectip
 * Synplify encryptP1735.pl - on [pastebin](https://github.com/reversing-research/XilinxUnprotect/blob/master/pastebin.com/cdHTHBB1)
 * Xilinx Encryption Tool
 * Cadence ncprotect

TODO
+===

Find keys for the following:

 * fixed AES-256 key named: `CDS_DATA_KEY` for Cadence Design Systems, tool: `ncprotect`
 * fixed AES-128 key named: Model Technology tool: `DEV`
 * rsa key named: `VCS001`
 * rsa key named: `ALDEC08_001` for Aldec, tool: `protectip`, Riviera PRO
 * rsa key named: `SYNP05_001` for Synplicity
 * rsa key named: `SNPS-VCS-RSA-1` for Synopsys
 * rsa key named: `cds_rsa_key` for Cadence Design Systems
 * rsa key named: `MGC-PREC-RSA` for Mentor Graphics Corporation
 * rsa key named: `ALDEC15_001` for Aldec


