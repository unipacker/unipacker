     _   _         __  _  __                    _
    | | | |       / / (_) \ \                  | |
    | | | |_ __  | |   _   | | _ __   __ _  ___| | _____ _ __
    | | | | '_ \/ /   | |   \ \ '_ \ / _` |/ __| |/ / _ \ '__|
    | |_| | | | \ \   | |   / / |_) | (_| | (__|   <  __/ |
     \___/|_| |_|| |  |_|  | || .__/ \__,_|\___|_|\_\___|_|
                  \_\     /_/ | |
                              |_|

# Un{i}packer
## Unpacking PE files using Unicorn Engine

The usage of runtime packers by malware authors is very common, as it is a technique that helps to hinder analysis.
Furthermore, packers are a challenge for antivirus products, as they make it impossible to identify malware by signatures
or hashes alone.

In order to be able to analyze a packed malware sample, it is often required to unpack the binary. Usually this means,
that the analyst will have to manually unpack the binary by using dynamic analysis techniques (Tools: OllyDbg, x64Dbg).
There are also some approaches for automatic unpacking, but they are all only available for Windows. Therefore when
targeting a packed Windows malware the analyst will require a Windows machine. The goal of our project is to enable
platform independent automatic unpacking by using emulation.

## Supported packers

- **[UPX](https://github.com/upx/upx)**: Cross-platform, open source packer
- **[ASPack](http://www.aspack.com/)**: Advanced commercial packer with a high compression ratio
- **[PEtite](https://www.un4seen.com/petite/)**: Freeware packer, similar to ASPack
- **[FSG](https://www.aldeid.com/wiki/Category:Digital-Forensics/Computer-Forensics/Anti-Reverse-Engineering/Packers/FSG)**: Freeware, fast to unpack

## Usage
Install [r2](https://github.com/radare/radare2) and [YARA](https://github.com/VirusTotal/yara)
```
pip3 install -r requirements.txt
python3 unipacker.py
```
For detailed instructions on how to use Un{i}packer please refer to the [Wiki](https://github.com/unipacker/unipacker/wiki).
Additionally, all of the shell commands are documented. To access this information, use the ```help``` command
