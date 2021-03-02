     _   _         __  _  __                    _
    | | | |       / / (_) \ \                  | |
    | | | |_ __  | |   _   | | _ __   __ _  ___| | _____ _ __
    | | | | '_ \/ /   | |   \ \ '_ \ / _` |/ __| |/ / _ \ '__|
    | |_| | | | \ \   | |   / / |_) | (_| | (__|   <  __/ |
     \___/|_| |_|| |  |_|  | || .__/ \__,_|\___|_|\_\___|_|
                  \_\     /_/ | |
                              |_|

# Un{i}packer   [![PyPI: unipacker](https://badge.fury.io/py/unipacker.svg)](https://pypi.org/project/unipacker/) [![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/vfsrfs/unipacker.svg)](https://hub.docker.com/r/vfsrfs/unipacker)

| | |
|---|---|
| Master  | [![Build Status](https://travis-ci.org/unipacker/unipacker.svg?branch=master)](https://travis-ci.org/unipacker/unipacker) |
| Dev  | [![Build Status](https://travis-ci.org/unipacker/unipacker.svg?branch=dev)](https://travis-ci.org/unipacker/unipacker) |

## Unpacking PE files using Unicorn Engine

The usage of runtime packers by malware authors is very common, as it is a technique that helps to hinder analysis.
Furthermore, packers are a challenge for antivirus products, as they make it impossible to identify malware by signatures
or hashes alone.

In order to be able to analyze a packed malware sample, it is often required to unpack the binary. Usually this means,
that the analyst will have to manually unpack the binary by using dynamic analysis techniques (Tools: OllyDbg, x64Dbg).
There are also some approaches for automatic unpacking, but they are all only available for Windows. Therefore when
targeting a packed Windows malware the analyst will require a Windows machine. The goal of our project is to enable
platform independent automatic unpacking by using emulation that yields runnable Windows binaries.

## Fully supported packers

- **[ASPack](http://www.aspack.com/)**: Advanced commercial packer with a high compression ratio
- **[FSG](https://www.aldeid.com/wiki/Category:Digital-Forensics/Computer-Forensics/Anti-Reverse-Engineering/Packers/FSG)**: Freeware, fast to unpack
- **[MEW](https://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/MEW-SE.shtml)**: Specifically designed for small binaries
- **[MPRESS](http://www.matcode.com/mpress.htm)**: Free, more complex packer
- **[PEtite](https://www.un4seen.com/petite/)**: Freeware packer, similar to ASPack
- **[UPX](https://github.com/upx/upx)**: Cross-platform, open source packer
- **YZPack**

## Other packers
Any other packers should work as well, as long as the needed API functions are implemented in Un{i}packer. For packers that
aren't specifically known you will be asked whether you would like to manually specify the start and end addresses for emulation.
If you would like to start at the entry point declared in the PE header and just emulate until section hopping is detected,
press ```Enter```

## Usage
### Normal installation
Install the [YARA](https://github.com/VirusTotal/yara) package for your OS, get Un{i}packer from PyPi and start it using the automatically created command line wrapper:
```
pip3 install unipacker
unipacker
```
For detailed instructions on how to use Un{i}packer please refer to the [Wiki](https://github.com/unipacker/unipacker/wiki).
Additionally, all of the shell commands are documented. To access this information, use the ```help``` command

You can take a quick look at Un{i}packer in action in a (german) [video](https://youtu.be/ee5_JUIEf8Q) by Prof. Chris Dietrich

### Development mode installation
Clone the repository, and inside the project root folder activate development mode using ```pip3 install -e .```

### Using Docker
You can also use the provided Dockerfile to run a containerized version of Un{i}packer:
```
docker run -it -v ~/local_samples:/root/unipacker/local_samples vfsrfs/unipacker
```
Assuming you have a folder called ```local_samples``` in your home directory, this will be mounted inside the container.
Un{i}packer will thus be able to access those binaries via ```/root/unipacker/local_samples```

### RESTful API
A 3rd party wrapper created by @rpgeeganage allows to unpack samples by sending a request to a RESTful server: [https://github.com/rpgeeganage/restful4up](https://github.com/rpgeeganage/restful4up)
